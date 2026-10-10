## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""External-tool check adapters -- rules whose verdict comes from RUNNING another
tool (bash -n, shellcheck) rather than from the shfmt AST. Check-only: an
external tool reports, it does not get a fix().

They run only in the human/check front (Engine's include_external pass), never
the US-delimited '--detect' channel, so a tool's multi-line output is carried in
the finding message without corrupting a machine record. bash -n runs even when
shfmt could not parse the file -- catching the syntax error is the whole point --
so these do not gate on ctx.tree the way the AST rules do."""

import contextlib
import json
import math
import os
import resource
import signal
import subprocess
import tempfile

from dist_ai import model
from dist_ai.model import ExternalRule


def _find_shellcheckrc(start_dir):
    """The nearest '.shellcheckrc' at or above START_DIR, else None. shellcheck
    discovers its rc by walking up from the CHECKED FILE's own directory -- but a
    staged blob is materialized under a temp dir with no '.shellcheckrc' above it,
    so the project rc (its SC disables) is silently dropped and the gate fails a
    file that is clean IN PLACE. Locating the real rc lets the caller pass it via
    '--rcfile' so the blob is judged by the same config as the on-disk file."""
    directory = os.path.abspath(start_dir) if start_dir else os.getcwd()
    while True:
        candidate = os.path.join(directory, ".shellcheckrc")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(directory)
        if parent == directory:
            return None
        directory = parent


def _repo_root(abspath):
    """The git work-tree root containing ABSPATH, or None. Runs from the file's
    own directory so the answer is that file's repo, not the process CWD."""
    if not abspath:
        return None
    directory = os.path.dirname(os.path.abspath(abspath))
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=directory, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip() or None


def _tree_blob_shas(root, rev):
    """{relpath: (mode, sha)} for every blob in REV ('' -> the stage-0 INDEX, a
    commit-ish -> that tree), taken in ONE listing keyed by EXACT path so no
    per-file path is ever spliced into a git object argument. A name that is
    pathspec MAGIC or collides with git's ':<stage>:<path>' / '<rev>:<path>' grammar
    (a crafted directory like '0:pwn') therefore cannot misparse into a DIFFERENT
    object. quotePath=false + '-z' keep an odd-byte path one intact record. {} on a
    git failure."""
    if rev == "":
        cmd = ["git", "-c", "core.quotePath=false", "ls-files", "--stage", "-z"]
        sha_field = 1                       # 'mode sha stage \t path'
    else:
        cmd = ["git", "-c", "core.quotePath=false", "ls-tree", "-r", "-z", rev]
        sha_field = 2                       # 'mode type sha \t path'
    entries: dict[str, tuple[str, str]] = {}
    try:
        out = subprocess.run(
            cmd, cwd=root, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return entries
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _tab, path = record.partition(b"\t")
        fields = meta.split()
        if len(fields) <= sha_field:
            continue
        ## An UNMERGED index path emits one record per conflict stage (1=base,
        ## 2=ours, 3=theirs) and NO stage-0 entry. Keying by path would keep
        ## whichever stage git lists LAST (stage 3, "theirs") and silently govern
        ## the shellcheck run with the incoming side's rc -- e.g. a conflicted
        ## '.shellcheckrc' carrying 'disable=all'. Skip nonzero stages so a
        ## conflicted path resolves to NO staged blob (the caller's walk then
        ## falls back to a higher rc or none), never an arbitrary conflict side.
        if rev == "" and len(fields) > 2 and fields[2] != b"0":
            continue
        entries[os.fsdecode(path)] = (
            os.fsdecode(fields[0]), os.fsdecode(fields[sha_field]))
    return entries


def _blob_shellcheckrc_bytes(ctx):
    """The nearest '.shellcheckrc' governing CTX's file, read from CTX's OWN git
    tree (source_rev; '' is the index) rather than the working tree -- so a dirty
    or unstaged rc cannot govern a committed/staged blob (a 'disable=all' left in
    the worktree must not suppress a real finding in the object that ships). Walks
    up the file's tree path like shellcheck's own discovery. The path PREFIX comes
    from ctx.path, which IS attacker-controlled, so the rc is fetched BY SHA from a
    whole-tree listing keyed by exact path -- NEVER a 'git show <rev>:<path>' object
    spec: a crafted directory ('0:pwn') would else misparse the ':path' form as a
    ':<stage>:<path>' index spec and read a DIFFERENT '.shellcheckrc' (disable=all)
    to SUPPRESS shellcheck on the malicious PR's own scripts. None if no rc found."""
    root = _repo_root(ctx.abspath)
    if root is None:
        return None
    rev = getattr(ctx, "source_rev", None) or ""      # '' -> the index
    entries = _tree_blob_shas(root, rev)
    reldir = os.path.dirname(ctx.path or "")
    while True:
        rel = (reldir + "/.shellcheckrc") if reldir else ".shellcheckrc"
        entry = entries.get(rel)
        if entry is not None:
            mode, sha = entry
            if mode not in ("120000", "160000"):      # skip a symlink/gitlink rc
                try:
                    out = subprocess.run(
                        ["git", "cat-file", "blob", sha],
                        cwd=root, capture_output=True, check=True)
                    return out.stdout
                except (OSError, subprocess.CalledProcessError):
                    pass
        if not reldir:
            return None
        reldir = os.path.dirname(reldir)


def _rewrite_scriptdir_source_paths(data, src_dir):
    """Rewrite a materialized '.shellcheckrc' so its SCRIPTDIR-relative 'source-path='
    entries point at SRC_DIR (the checked file's REAL directory), returned as bytes.

    shellcheck's SCRIPTDIR resolves to the directory of the CHECKED FILE. A staged /
    committed blob is checked as a temp file under /tmp (see context.materialized), so
    SCRIPTDIR is /tmp there and a 'source-path=SCRIPTDIR/../libexec/...' entry silently
    misses the real siblings -- dropping '# shellcheck source=' resolution that works
    in place (SC1091), and with it the cross-file SC2034 tracking. Anchoring those
    entries to the real SRC_DIR makes the staged check resolve intra-repo sources
    exactly like the on-disk check. Only leading-SCRIPTDIR entries are touched;
    absolute paths and every other directive pass through byte-for-byte. On any
    decode error the input is returned unchanged (fail-safe: never corrupt the rc)."""
    if not src_dir:
        return data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    out_lines = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        newline = line[len(body):]
        stripped = body.lstrip()
        indent = body[:len(body) - len(stripped)]
        if stripped.startswith("source-path="):
            value = stripped[len("source-path="):]
            if value == "SCRIPTDIR" or value.startswith("SCRIPTDIR/"):
                rest = value[len("SCRIPTDIR"):]           # '' or '/...'
                resolved = os.path.normpath(src_dir + rest)
                out_lines.append(indent + "source-path=" + resolved + newline)
                continue
        out_lines.append(line)
    return "".join(out_lines).encode("utf-8")


@contextlib.contextmanager
def _shellcheckrc_for(ctx, src_dir):
    """Yield a filesystem path to the '.shellcheckrc' governing CTX, or None. A
    DISK context (source_rev is None) reads it from SRC_DIR on disk. A BLOB context
    (staged/committed, source_rev set) reads it from its own git tree and
    materializes it to a temp file for the with-block, so the blob is judged by the
    config that ships with it, not a diverged working copy. Its SCRIPTDIR-relative
    'source-path=' entries are re-anchored to SRC_DIR so a '# shellcheck source='
    resolves against the real siblings, not the /tmp staged temp dir."""
    if getattr(ctx, "source_rev", None) is None:
        yield _find_shellcheckrc(src_dir)
        return
    data = _blob_shellcheckrc_bytes(ctx)
    if data is not None:
        data = _rewrite_scriptdir_source_paths(data, src_dir)
    if data is None:
        ## No rc in the blob's OWN tree. Do NOT yield None: shellcheck would then
        ## fall back to its own discovery and find the WORKING-TREE '.shellcheckrc'
        ## (or the CWD's) -- letting a dirty/unstaged rc govern the object that
        ## ships, the exact hole this closes. Pin an EMPTY rc so nothing is
        ## suppressed and no rc is discovered.
        yield os.devnull
        return
    handle = tempfile.NamedTemporaryFile(
        prefix="dist-ai-shellcheckrc-", suffix=".shellcheckrc", delete=False)
    try:
        handle.write(data)
        handle.close()
        yield handle.name
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            ## best-effort cleanup of our own temp file; already-gone or
            ## unremovable is not actionable here
            pass


class BashParse(ExternalRule):
    """'bash -n': the shell must parse. A syntax error fails the gate. bash is
    always present (the strict-mode preamble needs 4.4+), so no skip path."""

    id = "bash-n"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.is_shell

    def detect(self, ctx):
        try:
            with ctx.materialized() as (path, _src_dir):
                proc = subprocess.run(
                    ["bash", "-n", "--", path],
                    capture_output=True, text=True)
        except OSError:
            return
        if proc.returncode != 0:
            message = "bash -n: '%s' failed to parse" % ctx.path
            if proc.stderr.strip():
                message += "\n" + proc.stderr.rstrip("\n")
            yield model.fail("bash-n", message, ctx.path)


## Kept IDENTICAL to the set ai-review's static reviewer enables, so a file
## cannot be gate-green yet carry findings the reviewer reports.
SHELLCHECK_OPTIONAL = (
    "avoid-nullary-conditions,check-unassigned-uppercase,deprecate-which,"
    "quote-safe-variables,require-variable-braces")

## Per-subprocess CPU-time cap (see _run_shellcheck) on a single shellcheck run.
## '--external-sources' follows '# shellcheck source=' directives transitively, and that following is
## EXPONENTIAL on the deep helper-scripts graph (see the comment above
## _absent_helper_scripts_sibling): a resolvable sibling tree makes shellcheck hang
## for minutes. Without a cap the hang reaches the OUTER hook timeout, which fails
## OPEN -- the gate silently stops gating. On expiry the run is retried once with
## following FORCED off (_forced_no_follow_rcfile), so it cannot explode and returns
## fast, and the file degrades loudly instead of vanishing.
##
## BUDGET: the primary (follow) and the fallback (full body analysis, no follow) each
## get SHELLCHECK_TIMEOUT. The common case spends ONE: a normal file passes the
## primary; an exploding-follow file is cut at the primary cap, then the fallback
## analyzes its body well under the cap. Both caps stack only on ONE pathological file
## (exploding follow AND a body too big to analyze in the budget). That rare file
## approaches the 20s PostToolUse outer cap (its fail-OPEN) or exhausts the fallback
## (fail-CLOSED, loud) -- never a silent pass; the 120s pre-commit cap is unaffected.
## The fallback needs the full budget because its body analysis scales with file size
## (a ~5000-line script like usr/bin/ai-review takes ~6s); a smaller cap fail-closes
## clean large files. Overridable for tests via DIST_AI_SHELLCHECK_TIMEOUT (clamped,
## LOWER only).


## Ceiling on the per-run cap, and the default when unset. DIST_AI_SHELLCHECK_TIMEOUT
## may only LOWER it (tests, fail-fast), never raise it: primary + fallback + the
## other rules + process startup must stay under the smallest OUTER hook cap
## (shell-style-check.py's 20s) or the outer fail-open re-opens the silent-pass hole.
## A larger finite value -- including one big enough to overflow subprocess.run's C
## timeout (OverflowError) -- is clamped DOWN to this, never crashes.
_SHELLCHECK_TIMEOUT_MAX = 10.0


def _read_shellcheck_timeout():
    """Validated DIST_AI_SHELLCHECK_TIMEOUT. A non-numeric, non-finite (nan/inf) or
    non-positive value falls back to the ceiling; a larger finite value is clamped
    DOWN to it -- never passed on to crash subprocess.run (OverflowError on inf/huge,
    ValueError on nan) nor to expire every file at 0/negative nor to breach the outer
    hook budget."""
    try:
        value = float(os.environ.get(
            "DIST_AI_SHELLCHECK_TIMEOUT", str(_SHELLCHECK_TIMEOUT_MAX)))
    except ValueError:
        return _SHELLCHECK_TIMEOUT_MAX
    if not math.isfinite(value) or value <= 0:
        return _SHELLCHECK_TIMEOUT_MAX
    return min(value, _SHELLCHECK_TIMEOUT_MAX)


SHELLCHECK_TIMEOUT = _read_shellcheck_timeout()
## The fallback still runs shellcheck's FULL body analysis (just no following), and
## that scales with FILE SIZE -- a ~5000-line script takes ~6s. A smaller cap here
## fail-CLOSES a clean large file (e.g. usr/bin/ai-review), so the fallback gets the
## SAME budget as the primary. The two caps stack only on ONE pathological file (big
## body AND an exploding follow graph); that rare file approaches the 20s PostToolUse
## cap (its fail-open) or exhausts the fallback (fail-closed, loud) -- never a silent
## pass, and the 120s pre-commit cap is unaffected.
SHELLCHECK_FALLBACK_TIMEOUT = SHELLCHECK_TIMEOUT


## The cap is CPU seconds (RLIMIT_CPU), not wall-clock: a following explosion is
## CPU-bound, so CPU time catches it exactly, while a wall cap also expires a clean
## file whenever the host is loaded (a ~2600-line script needs ~8s CPU, which is
## 20s+ wall at load 20) -- the gate then fail-closes on load, not on the code. The
## wall backstop only bounds a run that hangs WITHOUT burning CPU; primary plus
## fallback at the backstop (2 x 5 x 10s) stays under the 120s pre-commit cap.
_SHELLCHECK_WALL_BACKSTOP_FACTOR = 5


## Only the SOFT limit is lowered; the inherited hard limit is kept, since an
## unprivileged process cannot raise it. SIGXCPU at the soft limit is the one cap
## signal -- a SIGKILL (OOM killer, operator) is not a cap expiry.
def _limit_cpu_seconds(seconds):
    def apply():
        _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
        if hard != resource.RLIM_INFINITY:
            seconds_capped = min(seconds, hard)
        else:
            seconds_capped = seconds
        resource.setrlimit(resource.RLIMIT_CPU, (seconds_capped, hard))
    return apply


def _run_shellcheck(command, timeout, env=None):
    cpu_seconds = max(1, math.ceil(timeout))
    proc = subprocess.run(
        command, capture_output=True, text=True, env=env,
        timeout=timeout * _SHELLCHECK_WALL_BACKSTOP_FACTOR,
        preexec_fn=_limit_cpu_seconds(cpu_seconds))
    if proc.returncode == -signal.SIGXCPU:
        raise subprocess.TimeoutExpired(
            command, timeout, output=proc.stdout, stderr=proc.stderr)
    return proc


@contextlib.contextmanager
def _forced_no_follow_rcfile(rc_file):
    """A temp rcfile whose FIRST 'external-sources' directive is false, yielded as a
    path. shellcheck honors the FIRST such directive, and an rcfile 'external-sources
    =false' overrides SHELLCHECK_OPTS=-x, so this forces following OFF no matter what
    the project rcfile (which here CAN carry 'external-sources=true') or the
    environment asks -- the fallback therefore cannot re-enter the exponential follow.
    The project rcfile's OTHER directives (disable/enable lists) are preserved after
    it, so the file body is judged by the same config."""
    body = "external-sources=false\n"
    if rc_file is not None:
        try:
            with open(rc_file, "r", encoding="utf-8", errors="replace") as src:
                body += src.read()
        except OSError:
            ## best-effort: an unreadable project rcfile just means the forced
            ## 'external-sources=false' body stands alone; following stays OFF.
            pass
    handle = tempfile.NamedTemporaryFile(
        mode="w", prefix="dist-ai-nofollow-", suffix=".shellcheckrc",
        delete=False, encoding="utf-8")
    try:
        handle.write(body)
        handle.close()
        yield handle.name
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            ## best-effort cleanup: the temp rcfile may already be gone; ignore.
            pass

## A '# shellcheck source=' directive into the helper-scripts sibling repo
## (repo-tree shape '<repo-parent>/helper-scripts/usr/libexec/helper-scripts/...')
## cannot be FOLLOWED on a dev host: a local helper-scripts checkout is disallowed,
## and the installed /usr/libexec/helper-scripts is a flat runtime layout, not that
## tree. CI checks the sibling out and follows the source. Reproducing the sibling
## locally is not viable: shellcheck's '--external-sources' following of the deep
## helper-scripts graph is exponential (measured ~1s for one such source, >60s past
## four -- it hangs the gate). So the gate accepts the verdict CI reaches and drops
## the info-level SC1091 for that ABSENT sibling.
##
## Tolerance is decided from the FILESYSTEM, never the message text, so it is
## EXACT: (1) the unresolved path must resolve to the well-known sibling location
## (not merely CONTAIN that substring -- a broken '../lib/...helper-scripts/...'
## stays fatal); (2) that sibling dir must be genuinely ABSENT -- when it is present
## (CI), a missing file under it is a REAL broken path and its SC1091 stays fatal,
## so a typo is caught in CI exactly as before.
_HELPER_SCRIPTS_SIBLING_SUFFIX = os.path.join(
    "helper-scripts", "usr", "libexec", "helper-scripts")


def _absent_helper_scripts_sibling(abspath):
    """The absolute helper-scripts sibling dir a repo-tree 'source=' resolves to
    (<repo-parent>/helper-scripts/usr/libexec/helper-scripts) IF the file is in a
    git repo AND that sibling is NOT checked out; else None. None when the sibling
    is present -- a missing file under it (a typo) then stays a hard failure, as it
    does in CI."""
    root = _repo_root(abspath)
    if root is None:
        return None
    sibling = os.path.join(os.path.dirname(root), _HELPER_SCRIPTS_SIBLING_SUFFIX)
    if os.path.isdir(sibling):
        return None
    ## realpath, so the comparison in _is_absent_helper_scripts_source is in the
    ## SAME namespace as the resolved source path -- else a checkout reached via a
    ## symlink (git 'rev-parse --show-toplevel' is physical, the source path is
    ## not) would never match and a tolerable source would false-fail.
    return os.path.realpath(sibling)


## shellcheck's SC1091 'does not exist' message is 'Not following: <path>:
## openBinaryFile: does not exist (...)'. The path is everything between the
## prefix and the LAST occurrence of this fixed error suffix. Using the LAST
## occurrence (not the first ': ' or the first ': openBinaryFile') is what keeps a
## quoted source= value -- which shellcheck echoes verbatim, so it can itself
## contain ': ' or even ': openBinaryFile/...' -- from being truncated and
## misread as the sibling. A path ending in this EXACT marker would still fool it,
## but the real helper-scripts directives are plain unquoted paths; a value
## crafted to embed it needs a '## style-ok: R-080' waiver to exist at all and is
## an adversarial local-content case outside this gate's threat model (CI, sibling
## present, and the runtime source both reject a genuinely broken path anyway).
_SC1091_ERROR_MARKER = ": openBinaryFile: does not exist"


def _sc1091_unfollowed_path(comment):
    """The unresolved path from an SC1091 'does not exist' comment, or None if this
    is not that comment."""
    if comment.get("code") != 1091:
        return None
    message = comment.get("message", "")
    marker = "Not following: "
    if not message.startswith(marker):
        return None
    body = message[len(marker):]
    index = body.rfind(_SC1091_ERROR_MARKER)
    if index == -1:
        return None
    return body[:index]


def _is_absent_helper_scripts_source(comment, src_dir, sibling_dir):
    """True only for the SC1091 of a source= whose path resolves INTO the
    genuinely absent helper-scripts sibling (sibling_dir, from
    _absent_helper_scripts_sibling). sibling_dir None -> nothing is tolerated (no
    repo, or the sibling is present, where a missing file is a real error)."""
    if sibling_dir is None:
        return False
    path = _sc1091_unfollowed_path(comment)
    if path is None:
        return False
    ## realpath (not normpath): resolve any symlink in src_dir so the result is in
    ## the same namespace as sibling_dir (also realpath'd). Applied to an absolute
    ## path too -- shellcheck rarely emits one, but it costs nothing.
    base = path if os.path.isabs(path) else os.path.join(src_dir, path)
    resolved = os.path.realpath(base)
    return resolved == sibling_dir or resolved.startswith(sibling_dir + os.sep)


def _render_shellcheck(path, comments):
    """A readable rendering of shellcheck JSON COMMENTS, keyed on the caller-facing
    PATH (not the temp blob path a staged check runs against)."""
    lines = ["shellcheck: '%s'" % path]
    for comment in comments:
        lines.append("%s:%s:%s: %s: %s [SC%s]" % (
            path, comment.get("line", "?"), comment.get("column", "?"),
            comment.get("level", "?"), comment.get("message", ""),
            comment.get("code", "?")))
    return "\n".join(lines)


## SC2034 (assigned, never used) and SC2154 (used, never assigned) are reliable ONLY
## when shellcheck can follow 'source'. In the degraded no-follow fallback a global
## SHARED across a source boundary (set here, read in a sourced file, or vice versa) is
## FALSE-flagged (e.g. systemcheck's ICON/IDENTIFIER). We cannot tell such a false
## positive from a genuine in-file typo without following the (transitively) sourced
## files -- exactly the work that exploded. Heuristically re-deriving it from the
## sourced files' text is a bash parser that lies in BOTH directions (a name in a
## comment/string excuses a real bug; a quoted/transitive/space path misses a real use),
## so per the "never reinvent a bash parser -> NOTIFY-only" rule the fallback does NOT
## gate on SC2034/SC2154: it surfaces them as a VISIBLE ADVISORY note (not silently
## dropped, so no silent green; not a hard fail, so a load-induced degrade of a valid
## large file is not blocked). SC1091 is still dropped unconditionally (never a real bug,
## just "could not follow").
_FOLLOW_DEPENDENT_VAR_CODES = frozenset({2034, 2154})


def _emit_shellcheck(ctx, proc, src_dir, no_follow):
    """Turn a finished shellcheck PROC into model events. no_follow is the degraded
    (no-following) path: SC1091 'not following' is dropped (the forced consequence of
    disabling the follow, identical to the absent-sibling drop); SC2034/SC2154 cannot be
    verified across 'source' boundaries without the follow that exploded, so they are
    emitted as a NON-GATING advisory NOTE (visible, never silently dropped) rather than
    a fail; every other finding stays a real fail. The normal path drops only the SC1091
    of a genuinely absent helper-scripts sibling (see _is_absent_helper_scripts_source)."""
    try:
        comments = json.loads(proc.stdout)["comments"]
    except (ValueError, KeyError, TypeError):
        ## No parseable JSON (a shellcheck internal error, or a build without
        ## --format=json1). Fall back to the raw exit status so a real failure
        ## is never silently swallowed.
        if proc.returncode != 0:
            message = "shellcheck: '%s'" % ctx.path
            raw = proc.stdout.strip() or proc.stderr.strip()
            if raw:
                message += "\n" + raw.rstrip("\n")
            yield model.fail("shellcheck", message, ctx.path)
        return
    if no_follow:
        advisory = [c for c in comments
                    if c.get("code") in _FOLLOW_DEPENDENT_VAR_CODES]
        if advisory:
            yield model.note(
                "shellcheck",
                "following timed out on '%s'; these unused/unassigned-variable findings "
                "could not be verified across 'source' boundaries and are ADVISORY, not "
                "gating (inspect by hand, or re-run with following):\n%s"
                % (ctx.path, _render_shellcheck(ctx.path, advisory)))
        remaining = [c for c in comments
                     if c.get("code") != 1091
                     and c.get("code") not in _FOLLOW_DEPENDENT_VAR_CODES]
    else:
        ## The git probe for the sibling runs only when there is an unfollowable
        ## source to judge (rc>=1 with an SC1091 'does not exist').
        needs_sibling = any(
            comment.get("code") == 1091
            and "does not exist" in comment.get("message", "")
            for comment in comments)
        sibling_dir = (_absent_helper_scripts_sibling(ctx.abspath)
                       if needs_sibling else None)
        remaining = [
            comment for comment in comments
            if not _is_absent_helper_scripts_source(comment, src_dir, sibling_dir)]
    if remaining:
        yield model.fail(
            "shellcheck", _render_shellcheck(ctx.path, remaining), ctx.path)
    elif proc.returncode >= 2:
        ## rc 0 clean, rc 1 findings (all tolerated if we reach here); rc>=2 is a
        ## shellcheck PROCESSING error (unreadable path, a directory) that emits
        ## '{"comments":[]}' -- fail-closed, never a silent green.
        message = "shellcheck: '%s' could not be processed (exit %d)" % (
            ctx.path, proc.returncode)
        err = proc.stderr.strip()
        if err:
            message += "\n" + err.rstrip("\n")
        yield model.fail("shellcheck", message, ctx.path)


class Shellcheck(ExternalRule):
    """'shellcheck --external-sources' with the ai-review-aligned optional
    checks. '--source-path=<script dir>' resolves a '# shellcheck source=' path
    relative to the SCRIPT's own directory (every such directive here is written
    script-relative). The dir is passed explicitly, not as SCRIPTDIR, so a
    virtual context (a staged blob checked from a temp file) still resolves
    'source=' against the real siblings. The project '.shellcheckrc' is likewise
    passed via '--rcfile' so a temp-file blob is judged by the same config, not
    dropped: for a DISK file it is located on disk; for a staged/committed BLOB it
    is read from the blob's OWN git tree (see _shellcheckrc_for), never the working
    tree -- a dirty rc must not govern the object that ships. Findings are read
    as JSON ('--format=json1') so the info-level SC1091 for a helper-scripts
    sibling that cannot be followed locally is dropped -- see
    _is_absent_helper_scripts_source -- while every other finding stays fatal.
    Fail-open when shellcheck is absent (a bare git-hook run without it installed
    must still commit). Each run is bounded by SHELLCHECK_TIMEOUT: if
    '--external-sources' following explodes it is retried once with following FORCED
    off and a NOTE marks the degrade, so a hanging file never reaches the outer
    fail-open."""

    id = "shellcheck"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.is_shell

    def detect(self, ctx):
        if not model.have_on_path("shellcheck"):
            yield model.note(
                "shellcheck",
                "shellcheck not on PATH; skipping (apt-get install shellcheck)")
            return
        try:
            with ctx.materialized() as (path, src_dir), \
                    _shellcheckrc_for(ctx, src_dir) as rc_file:
                command = ["shellcheck", "--external-sources",
                           "--source-path=" + src_dir, "--format=json1"]
                if rc_file is not None:
                    command.append("--rcfile=" + rc_file)
                command += ["--enable=" + SHELLCHECK_OPTIONAL, "--", path]
                try:
                    proc = _run_shellcheck(command, SHELLCHECK_TIMEOUT)
                    degraded = False
                except subprocess.TimeoutExpired:
                    ## '--external-sources' following exploded (exponential on the
                    ## deep helper-scripts graph). Re-run ONCE with following FORCED
                    ## off via the rcfile (dropping '--external-sources' from argv is
                    ## NOT enough -- the project rcfile may set external-sources=true,
                    ## or SHELLCHECK_OPTS=-x, either of which re-enables the follow and
                    ## re-explodes). shellcheck still fully analyzes the file BODY.
                    ## SHELLCHECK_OPTS is cleared belt-and-suspenders. The fallback
                    ## cannot follow, so it returns fast under its smaller cap.
                    with _forced_no_follow_rcfile(rc_file) as nofollow_rc:
                        fallback = ["shellcheck",
                                    "--source-path=" + src_dir, "--format=json1",
                                    "--rcfile=" + nofollow_rc,
                                    "--enable=" + SHELLCHECK_OPTIONAL, "--", path]
                        env = dict(os.environ)
                        env.pop("SHELLCHECK_OPTS", None)
                        proc = _run_shellcheck(
                            fallback, SHELLCHECK_FALLBACK_TIMEOUT, env=env)
                    degraded = True
        except subprocess.TimeoutExpired:
            ## The forced-no-follow fallback itself hung (pathological: a huge file
            ## body, NOT a following explosion). Fail CLOSED and loud -- never a
            ## silent green.
            yield model.fail(
                "shellcheck",
                "shellcheck: '%s' timed out after %gs with following forced off"
                % (ctx.path, SHELLCHECK_FALLBACK_TIMEOUT),
                ctx.path)
            return
        except OSError as exc:
            ## shellcheck resolved on PATH but could not be executed. Fail OPEN so
            ## a bare git-hook run still commits, but leave a NOTE so the skip is
            ## VISIBLE rather than a silent no-output pass.
            yield model.note(
                "shellcheck",
                "shellcheck present but could not run (%s); skipping" % exc)
            return
        if degraded:
            ## Always VISIBLE -- the degrade is never a silent pass. Honest about the
            ## COVERAGE lost: without following, shellcheck cannot resolve cross-file
            ## sources NOR distinguish a missing/typo'd 'source=' from a real one (it
            ## emits the same SC1091 for both), so those are dropped; and SC2034/SC2154
            ## cannot be verified across a source boundary, so _emit_shellcheck surfaces
            ## them as a non-gating advisory NOTE. The same cap applies in CI, so this
            ## file's cross-file checks are not recovered there either; the BODY is still
            ## fully checked.
            yield model.note(
                "shellcheck",
                "shellcheck '--external-sources' following exceeded %gs on '%s'; "
                "re-checked with following forced off -- cross-file source resolution and "
                "missing-source detection skipped, and unused/unassigned-variable checks "
                "(SC2034/SC2154) downgraded to advisory, for this file (body still checked)"
                % (SHELLCHECK_TIMEOUT, ctx.path))
        yield from _emit_shellcheck(ctx, proc, src_dir, degraded)


RULES = (BashParse(), Shellcheck())
