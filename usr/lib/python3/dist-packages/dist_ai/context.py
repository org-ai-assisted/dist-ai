## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Per-file context for the style engine: the ONE place that classifies a file
and answers its waivers.

Every rule receives a FileContext and asks it what it needs -- the parsed tree,
the file kind, whether a '## style-ok: <tag>' waiver is present. The
classification predicates (is_shell / is_text / is_binary / the config-file
shapes) and the waiver grammar live here ONCE, so a rule's detect and its fix
read one definition instead of separate copies that drift.

The tree is parsed lazily: a text rule never forces a shell parse, and a shell
file that shfmt cannot parse yields tree=None (the rule declines; the gate's
'bash -n' reports the syntax error)."""

import contextlib
import fnmatch
import io
import os
import re
import subprocess
import tempfile
import tokenize

from dist_ai import bash_ast
from dist_ai import model

SHELL_EXTS = (".sh", ".bsh", ".bash")
SHELL_SHEBANG_RE = re.compile(r'#!.*(/|\s)(bash|sh|dash)(\s|$)')
PYTHON_SHEBANG_RE = re.compile(r'#!.*(/|\s)python[0-9.]*(\s|$)')

## is_text scope for the trailing-whitespace rule: the extension set, with a
## file(1) --mime fallback for extensionless files.
TEXT_EXTS = (
    ".md", ".sh", ".bsh", ".bash", ".py", ".yml", ".yaml", ".json", ".toml",
    ".xml", ".txt", ".csv", ".cfg", ".conf", ".ini", ".rst", ".html", ".css",
    ".js", ".ts", ".c", ".h", ".cpp", ".hpp", ".go", ".rs", ".tex",
    ".dockerfile",
)
TEXT_BASENAMES = ("Dockerfile", "Makefile", "COPYING", "README", "LICENSE")
TEXT_MIME_NEEDLES = ("text/", "x-shellscript", "x-python", "json", "xml",
                     "yaml", "toml", "charset=us-ascii", "charset=utf-8")

## The .gitattributes classification attributes, queried in ONE check-attr call:
##   binary                -- data, not text: the whole text tier skips it.
##   linguist-vendored / -generated -- third-party / generated code kept VERBATIM
##     (a byte-pinned vendored lib with its own drift guard): our STYLE + format
##     rules skip it, as `binary` does, but the secret / large-file / structural
##     checks still run (precommit keeps it in the scan list). Reuses GitHub's own
##     vendored/generated vocabulary, so one glob line exempts a whole tree and
##     any future file under it, with nothing to recall. An explicit `=false`
##     re-includes (Linguist's own override).
CLASSIFY_ATTRS = ("binary", "linguist-vendored", "linguist-generated")
_VENDORED_ATTRS = ("linguist-vendored", "linguist-generated")


def check_attrs(cwd, path, source_rev, names):
    """{name: value} from `git check-attr` for NAMES on PATH, run in CWD. The
    attribute source matches the tree the scanned CONTENT came from (source_rev),
    so a stale / uncommitted .gitattributes cannot govern a blob it does not:
    '' -> the INDEX (--cached); a commit-ish -> that commit (--attr-source); None
    -> the working tree (plain check-attr). '-z' makes the output machine-parsable
    (NUL-delimited path, attr, value triples) so an odd-byte path or value stays
    one record. Empty dict on any git error -- fail toward NOT exempting.

    The machine-wide attribute sources are SUPPRESSED (GIT_ATTR_NOSYSTEM for
    /etc/gitattributes; core.attributesFile=/dev/null for the user-global file),
    so a developer's global Linguist setting cannot silently exempt an unrelated
    repo from the gate. The repo-local $GIT_DIR/info/attributes still applies --
    git offers no flag to disable it -- but it is uncommitted and non-propagating,
    and CI runs the gate in a clean checkout, so it can weaken the gate only on
    the local machine, where a commit can already be waived outright."""
    if source_rev:
        args = ["--attr-source=%s" % source_rev, "check-attr", "-z"]
    elif source_rev == "":
        args = ["check-attr", "-z", "--cached"]
    else:  ## None: working-tree scan -> the working tree's own .gitattributes
        args = ["check-attr", "-z"]
    try:
        out = subprocess.run(
            ["git", "-C", cwd, "-c", "core.attributesFile=/dev/null"]
            + args + list(names) + ["--", path],
            capture_output=True,
            env={**os.environ, "GIT_ATTR_NOSYSTEM": "1"}).stdout
    except OSError:
        return {}
    ## -z output: path NUL attr NUL value NUL, repeated (trailing NUL -> one empty
    ## tail field). Key on attr/value; the path echo is ignored (it is our input).
    fields = out.split(b"\0")
    result = {}
    for i in range(0, len(fields) - 2, 3):
        result[fields[i + 1].decode("utf-8", "replace")] = (
            fields[i + 2].decode("utf-8", "replace"))
    return result


def vendored_value(attrs):
    """True if ATTRS (a check_attrs dict) marks the path vendored/generated -- a
    bare set or an explicit =true; an =false / unset / unspecified does not."""
    return any(attrs.get(name) in ("set", "true") for name in _VENDORED_ATTRS)

## A diff's TRAILING whitespace is SEMANTICALLY significant: a blank context line is
## a single leading space, and a line's trailing blanks may be the very change the
## patch encodes. Stripping either corrupts the patch -- so ONLY the trailing-ws rule
## skips a diff, and R-001 only DETECTS (blocks) rather than auto-substitutes its
## non-ASCII. end-of-file and byte-order-marker still run (a final newline or a
## stripped BOM only makes a patch MORE applicable); detect-only checks and the
## secret scanners always run.
##
## Detection is by the .patch/.diff EXTENSION, and ONLY that -- deliberately. Every
## richer heuristic was shown to leak BOTH ways, which is worse than the gap it
## fills: a false positive silently DISABLES trailing-ws + R-001 on ordinary source.
##   - content (file(1) mime): types a format-patch as application/mbox and a
##     long-header DEP-3 as text/plain, so it MISSES real patches.
##   - content (a hunk-header sniff): misses rename-only / context (diff -c) /
##     combined (@@@) diffs, and FALSE-exempts prose that embeds a hunk line.
##   - name '.patch.'/'.diff.' infix: FALSE-exempts real source (monkey.patch.py,
##     deploy.patch.sh, security.patch.md).
##   - a debian/patches/ path: FALSE-exempts series/README and anything under an
##     unrelated .../debian/patches/... absolute path, and MISSES a patch addressed
##     by a relative spelling that omits the prefix.
## The extension is the one unambiguous signal, and real patches carry it: quilt
## series list *.patch, git format-patch emits NNNN-*.patch. An extensionless or
## oddly-named patch is out of scope -- name it .patch/.diff; a DISABLED patch
## (.patch.disabled) is never applied, so stripping its whitespace is harmless.
##
## KNOWN GAP, accepted on purpose: an EXTENSIONLESS patch under debian/patches/ (e.g.
## a dpkg-source auto-generated debian-changes-<ver>) is not detected and its trailing
## whitespace would be stripped. This is the FAIL-SAFE direction (over-strip, never
## silently disable the gate on real source) and is avoidable by naming it *.patch.
## Do NOT "fix" it by re-adding a debian/patches/ path rule or a content sniff -- both
## were tried and FALSE-exempt real source (a /home/debian/patches/* tree, prose that
## embeds a hunk), which is a worse, silent gate hole.
DIFF_EXTS = (".patch", ".diff")


def is_diff_file(path):
    """True for a committed patch, by .patch/.diff extension only (see DIFF_EXTS
    comment for why nothing richer). Pure, case-insensitive path classification --
    one source of truth, shared identically by the engine (FileContext.is_diff) and
    precommit, and independent of the caller's path spelling."""
    return path.lower().endswith(DIFF_EXTS)


def _matches(path, patterns):
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p)
               for p in patterns)


def is_workflow_yaml(path):
    return _matches(path, (".github/workflows/*.yml", ".github/workflows/*.yaml",
                           "*/.github/workflows/*.yml",
                           "*/.github/workflows/*.yaml"))


def is_apt_conf(path):
    return _matches(path, ("*/apt.conf.d/*", "*/apt.conf", "apt.conf"))


def is_cron_table(path):
    return _matches(path, ("*/cron.d/*", "*/crontab", "crontab"))


class FileContext:
    """One file under examination.

      path        -- the path as the caller named it (repo-relative for a gate
                     run, so a rule's path-keyed self-exemption still matches).
      abspath     -- absolute path on disk, for git queries and writes.
      source      -- decoded UTF-8 text (str). None if undecodable/unreadable.
      is_shell    -- shell script (extension or shebang).
      tree        -- the shfmt AST (lazy), or None if not shell / unparsable.
    """

    def __init__(self, path, source, abspath=None, raw=None, disk_backed=False,
                 source_rev=None):
        self.path = path
        self.abspath = abspath if abspath is not None else path
        self.source = source
        self._raw = raw
        ## True only when the bytes came FROM abspath on disk (from_disk). A
        ## context built from other bytes -- a staged blob, a commit message --
        ## is VIRTUAL: abspath may hold different content, so an external tool
        ## must read a materialized copy, not the path (see materialized()).
        self.disk_backed = disk_backed
        ## The git tree the bytes came from, so classification reads the SAME
        ## tree as the content -- not the working tree that may have diverged.
        ## None = disk (working tree); '' = the index (git ':path'); a commit-ish
        ## = that tree. .gitattributes and any sibling lookup must key on this.
        self.source_rev = source_rev
        self._tree = None
        self._tree_done = False
        self._binary = None
        self._vendored = None
        self._attrs = None
        self._comment_lines = None
        self._comment_lines_done = False

    @classmethod
    def from_disk(cls, abspath, relpath=None):
        """Build from a file on disk. Returns None for a symlink or a
        non-regular file; source is None if the bytes are not valid UTF-8 (the
        raw bytes are kept regardless, so the non-ASCII floor still sees them)."""
        if not os.path.isfile(abspath) or os.path.islink(abspath):
            return None
        try:
            with open(abspath, "rb") as handle:
                raw = handle.read()
        except OSError:
            return None
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            source = None
        return cls(relpath if relpath is not None else abspath, source,
                   abspath=abspath, raw=raw, disk_backed=True)

    @contextlib.contextmanager
    def materialized(self):
        """Yield (path, source_dir): a filesystem path whose bytes ARE this
        context's content, and the directory a '# shellcheck source=' resolves
        against. A disk-backed context yields its own abspath (no copy). A
        VIRTUAL context (a staged blob) writes its bytes to a private temp file
        so an external tool reads the CONTENT, not whatever now sits at abspath;
        source_dir stays the real file's directory, so a relative sourced-file
        path still resolves against the true siblings."""
        src_dir = (os.path.dirname(os.path.abspath(self.abspath))
                   if self.abspath else os.getcwd())
        if self.disk_backed:
            yield self.abspath, src_dir
            return
        data = self.data if self.data is not None else b""
        ## Bound the suffix: a long basename (a 200+ char path component) would
        ## overflow NAME_MAX and raise OSError, which BashParse/Shellcheck swallow
        ## -> the file silently goes unparsed. The suffix is only a readability
        ## hint (dialect comes from the shebang), so the tail is enough.
        suffix = ("-" + os.path.basename(self.path))[-40:]
        handle = tempfile.NamedTemporaryFile(
            prefix="dist-ai-staged-", suffix=suffix, delete=False)
        try:
            handle.write(data)
            handle.close()
            yield handle.name, src_dir
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                ## best-effort cleanup of our own temp file; already-gone or
                ## unremovable is not actionable here
                pass

    @property
    def data(self):
        """The file's raw bytes, for the byte-level text rules (R-001 must flag a
        non-ASCII byte even in a file that is not valid UTF-8, where source is
        None -- the bash grep did). from_disk keeps the exact bytes; a context
        built from text (a commit message, the fixer's intermediate pass)
        encodes its source. None only when both are absent."""
        if self._raw is not None:
            return self._raw
        if self.source is not None:
            return self.source.encode("utf-8")
        return None

    ## --- classification ---------------------------------------------------

    @property
    def is_shell(self):
        if self.source is None:
            return self.path.endswith(SHELL_EXTS)
        if self.path.endswith(SHELL_EXTS):
            return True
        first = self.source.split("\n", 1)[0]
        return bool(SHELL_SHEBANG_RE.match(first))

    @property
    def is_python(self):
        if self.source is None:
            return self.path.endswith(".py")
        if self.path.endswith(".py"):
            return True
        return bool(PYTHON_SHEBANG_RE.match(self.source.split("\n", 1)[0]))

    @property
    def shebang(self):
        if not self.source:
            return ""
        first = self.source.split("\n", 1)[0]
        return first if first.startswith("#!") else ""

    @property
    def is_posix_sh(self):
        """A '#!/bin/sh' / env-sh script (R-090 exempts these)."""
        return bool(re.match(r'#!\s*(\S*/)?(env\s+)?sh(\s|$)', self.shebang))

    @property
    def is_binary(self):
        """True when the content is binary -- exempt from the text rules. A NUL
        byte (git's own binary heuristic) auto-detects genuine binaries (images,
        compiled blobs) so an image never needs a hand-written .gitattributes
        entry to pass R-001 -- the safe path is the default, not a thing to
        recall. The .gitattributes `binary` mark remains the explicit opt-out for
        a NUL-FREE data payload (a raw cat-able fixture), queried from the SAME
        tree as the content (see _query_attrs) so an unstaged/uncommitted
        .gitattributes cannot exempt a blob it does not actually govern. Cached."""
        if self._binary is None:
            data = self.data
            if data is not None and b"\x00" in data:
                self._binary = True
            else:
                self._binary = self._query_attrs().get("binary") == "set"
        return self._binary

    @property
    def is_vendored(self):
        """True when .gitattributes marks the path linguist-vendored or
        linguist-generated -- third-party / generated code kept verbatim, exempt
        from the STYLE + format rules exactly as `binary` is (the engine
        short-circuits on it), while the secret / size / structural checks still
        run. Glob-able, so one line exempts a whole tree and future files under
        it. Cached.

        is_binary is tested FIRST: a binary file is already exempt from the text
        tier and the engine rules decline it, so it is never treated as vendored
        -- and this keeps the NUL-byte binary short-circuit AHEAD of any git
        check-attr, so a NUL blob never triggers an attribute read (an unguarded
        --detect over a hostile FIFO .gitattributes must not hang)."""
        if self.is_binary:
            return False
        if self._vendored is None:
            self._vendored = vendored_value(self._query_attrs())
        return self._vendored

    def _query_attrs(self):
        ## One check-attr call for every classification attribute (CLASSIFY_ATTRS),
        ## cached. '-C <dir-of-file>' so git finds the file's OWN repo regardless
        ## of the caller's cwd -- otherwise a fixer invoked from another directory
        ## queried the wrong repo and the exemption failed open. The attribute
        ## source matches source_rev -- the tree the scanned content came from --
        ## so a stale/uncommitted .gitattributes cannot govern a blob it does not
        ## (a staged-only 'x binary' exempting a HEAD blob under --range was such a
        ## bypass).
        if self._attrs is None:
            self._attrs = check_attrs(
                os.path.dirname(self.abspath) or ".", self.abspath,
                self.source_rev, CLASSIFY_ATTRS)
        return self._attrs

    @property
    def is_diff(self):
        """A .patch/.diff file whose trailing whitespace is significant -- the
        trailing-whitespace rule must not rewrite it, and R-001 must not
        auto-substitute its non-ASCII. Identified by extension (see is_diff_file)."""
        return is_diff_file(self.path)

    @property
    def is_text(self):
        """The trailing-whitespace scope: not binary, and either a known text
        extension/basename or file(1) reports a text mime. The mime probe reads
        the context's OWN bytes (via stdin), not the path on disk -- a staged /
        HEAD blob whose working-tree file diverged or was removed must still be
        classified from the content that is actually being gated."""
        if self.is_binary:
            return False
        base = os.path.basename(self.path)
        if base in TEXT_BASENAMES or self.path.endswith(TEXT_EXTS):
            return True
        if not model.have_on_path("file") or self.data is None:
            return False
        try:
            mime = subprocess.run(
                ["file", "--brief", "--mime", "-"],
                input=self.data, capture_output=True).stdout.decode(
                    "utf-8", "replace")
        except OSError:
            return False
        return any(needle in mime for needle in TEXT_MIME_NEEDLES)

    ## --- parse ------------------------------------------------------------

    @property
    def tree(self):
        """The shfmt AST, parsed once and cached. None if the file is not shell,
        has no source, or shfmt rejects it. Raises bash_ast.ShfmtMissing if
        shfmt is absent (a required tool -- never a silent skip)."""
        if not self._tree_done:
            self._tree_done = True
            if self.is_shell and self.source is not None:
                try:
                    self._tree = bash_ast.parse_normalized(self.source)
                except bash_ast.BashParseError:
                    self._tree = None
        return self._tree

    ## --- waivers ----------------------------------------------------------

    def _comment_line_numbers(self):
        """1-based source line numbers that carry a REAL comment -- shell via the
        shfmt AST, Python via tokenize. None for any other file kind, or a source
        the respective parser rejects, so the caller falls back to a raw scan."""
        if self.is_shell:
            tree = self.tree
            if tree is None:
                return None
            return {comment["Hash"]["Line"]
                    for comment in bash_ast.comments(tree)
                    if comment.get("Hash", {}).get("Line")}
        if self.is_python:
            numbers = set()
            try:
                for token in tokenize.generate_tokens(
                        io.StringIO(self.source).readline):
                    if token.type == tokenize.COMMENT:
                        numbers.add(token.start[0])
            except (tokenize.TokenError, IndentationError, SyntaxError,
                    ValueError):
                return None
            return numbers
        return None

    def _comment_source_lines(self):
        """The full SOURCE LINES that carry a real comment, so a waiver is matched
        WITH its original line context -- the line-leading grammar ('## style-ok:'
        on its own, only whitespace before it) still holds, and a trailing inline
        comment ('cmd ## style-ok: X') does not waive. Restricting to comment
        lines also excludes a heredoc body or a quoted string that merely LOOKS
        like a waiver and would otherwise silently disable a rule file-wide. None
        for a file kind with no comment parser -- or a shell/Python source the
        parser rejects -- where the caller scans raw source: a '## style-ok:' in a
        quoted scalar or heredoc body is not disambiguated. That residual is out
        of threat model (forging a waiver is adversarial, not an AI accident) --
        see _waiver_present."""
        if not self._comment_lines_done:
            self._comment_lines_done = True
            numbers = self._comment_line_numbers()
            if numbers is not None:
                source_lines = self.source.split("\n")
                self._comment_lines = [
                    source_lines[number - 1] for number in numbers
                    if 1 <= number <= len(source_lines)]
        return self._comment_lines

    def _waiver_present(self, pattern):
        """True if PATTERN matches a waiver. Where the file's comments can be
        located (a well-formed shell / Python file) the match is restricted to
        real comment lines; with no locatable comments -- a parserless config
        kind, OR a shell/Python file the parser rejects -- it scans the raw
        source, so a line-leading '## style-ok:' sitting in DATA (a quoted or
        block scalar, a heredoc body) reads as a waiver. Accepted, NOT a hole to
        close: a plain syntax error is still caught (bash -n / the parser report
        it), and suppressing a rule this way ALSO requires planting the waiver
        token -- which is ADVERSARIAL. This gate's threat model is an AI
        ACCIDENT, not a crafted bypass."""
        lines = self._comment_source_lines()
        if lines is not None:
            return any(pattern.search(line) for line in lines)
        return bool(pattern.search(self.source))

    def has_waiver(self, tag):
        """True if the file carries a '## style-ok: <tag>' waiver (shell
        grammar: exactly '##', any or no surrounding horizontal whitespace). The
        trailing '\\r' in the boundary matches a waiver on a CRLF line -- '$'
        alone sits before '\\n', after the '\\r', so a CRLF waiver with no space
        after the tag would otherwise be missed (fail-closed to a spurious hit)."""
        if not self.source:
            return False
        pattern = re.compile(
            r'^[ \t]*##[ \t]*style-ok:[ \t]*' + re.escape(tag)
            + r'(?:[ \t\r]|$)', re.MULTILINE)
        return self._waiver_present(pattern)

    def has_config_waiver(self, tag, slashes=False):
        """True for a '# style-ok: <tag>' waiver in CONFIG comment syntax: one or
        two '#' (systemd/cron/YAML), or '//' when SLASHES (apt)."""
        if not self.source:
            return False
        prefix = r'(?:#{1,2}|//)' if slashes else r'#{1,2}'
        pattern = re.compile(
            r'^[ \t]*' + prefix + r'[ \t]*style-ok:[ \t]*'
            + re.escape(tag) + r'(?:[ \t\r]|$)', re.MULTILINE)
        return self._waiver_present(pattern)

    def has_rule_override(self, rule_id):
        """True if the file carries a per-rule override keyed on the rule's OWN
        id -- '## style-ok: <R-id>' in any supported comment syntax (#, ##, //).
        Every rule honors this through Rule.applies(), so any single rule can be
        suppressed for a file without dedicated waiver-tag wiring."""
        return self.has_config_waiver(rule_id, slashes=True)


## Convenience wrappers mirroring model.fail/note but filling ctx.path.
def fail(ctx, rule, message, node=None):
    return model.fail(rule, message, ctx.path, node)


def note(ctx, rule, message, node=None):
    return model.note(rule, message, ctx.path, node)
