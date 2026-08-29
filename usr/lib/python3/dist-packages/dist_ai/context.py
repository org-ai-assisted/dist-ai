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

SHELL_EXTS = (".sh", ".bsh")
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


def _have(name):
    return any(
        os.access(os.path.join(directory, name), os.X_OK)
        for directory in os.environ.get("PATH", "").split(os.pathsep)
        if directory)


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
        """True when .gitattributes marks the file binary -- exempt from the
        text rules. Cached; queried from the SAME tree as the content (see
        _query_binary), so an unstaged/uncommitted .gitattributes cannot exempt a
        blob it does not actually govern."""
        if self._binary is None:
            self._binary = self._query_binary()
        return self._binary

    def _query_binary(self):
        ## '-C <dir-of-file>' so git finds the file's OWN repo regardless of the
        ## caller's cwd -- otherwise a fixer invoked from another directory
        ## queried the wrong repo and the .gitattributes exemption failed open.
        ## The attribute source must match source_rev -- the tree the scanned
        ## content came from -- or a stale .gitattributes governs a blob it does
        ## not: '' staged -> the INDEX (--cached); a rev (range) -> the blob's OWN
        ## commit (--attr-source), else a staged (uncommitted) '.gitattributes ...
        ## binary' would exempt a HEAD blob it does not govern (an R-001 --range
        ## bypass); None working tree -> the WORKING-TREE .gitattributes (plain
        ## check-attr), since --cached there reads stale index attrs for a file
        ## whose worktree attrs may differ.
        base = ["git", "-C", os.path.dirname(self.abspath) or "."]
        if self.source_rev:
            attr = ["--attr-source=%s" % self.source_rev, "check-attr"]
        elif self.source_rev == "":
            attr = ["check-attr", "--cached"]
        else:  ## None: working-tree scan -> the working tree's own .gitattributes
            attr = ["check-attr"]
        try:
            out = subprocess.run(
                base + attr + ["binary", "--", self.abspath],
                capture_output=True, text=True)
        except OSError:
            return False
        return (out.returncode == 0
                and out.stdout.rstrip("\n").endswith(": binary: set"))

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
        if not _have("file") or self.data is None:
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
        for a file kind with no comment parser, where the caller scans raw source
        (a documented residual: a '## style-ok:' inside a quoted scalar in
        YAML/TOML is not disambiguated)."""
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
        located (shell / Python), the match is restricted to real comment lines;
        elsewhere it scans the raw source, the only option without a parser."""
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
