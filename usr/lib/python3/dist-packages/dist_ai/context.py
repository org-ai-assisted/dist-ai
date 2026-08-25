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

import fnmatch
import os
import re
import subprocess

from dist_ai import bash_ast
from dist_ai import model

SHELL_EXTS = (".sh", ".bsh")
SHELL_SHEBANG_RE = re.compile(r'#!.*(/|\s)(bash|sh|dash)(\s|$)')

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

    def __init__(self, path, source, abspath=None):
        self.path = path
        self.abspath = abspath if abspath is not None else path
        self.source = source
        self._tree = None
        self._tree_done = False
        self._binary = None

    @classmethod
    def from_disk(cls, abspath, relpath=None):
        """Build from a file on disk. Returns None for a symlink or a
        non-regular file; source is None if the bytes are not valid UTF-8."""
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
                   abspath=abspath)

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
        text rules. Cached; queried against the INDEX (--cached) so an unstaged
        .gitattributes cannot silently exempt."""
        if self._binary is None:
            self._binary = self._query_binary()
        return self._binary

    def _query_binary(self):
        ## '-C <dir-of-file>' so git finds the file's OWN repo regardless of the
        ## caller's cwd -- otherwise a fixer invoked from another directory
        ## queried the wrong repo and the .gitattributes exemption failed open.
        try:
            out = subprocess.run(
                ["git", "-C", os.path.dirname(self.abspath) or ".",
                 "check-attr", "--cached", "binary", "--", self.abspath],
                capture_output=True, text=True)
        except OSError:
            return False
        return (out.returncode == 0
                and out.stdout.rstrip("\n").endswith(": binary: set"))

    @property
    def is_text(self):
        """The trailing-whitespace scope: not binary, and either a known text
        extension/basename or file(1) reports a text mime."""
        if self.is_binary:
            return False
        base = os.path.basename(self.path)
        if base in TEXT_BASENAMES or self.path.endswith(TEXT_EXTS):
            return True
        if not _have("file"):
            return False
        try:
            mime = subprocess.run(
                ["file", "--brief", "--mime", "--dereference", "--",
                 self.abspath],
                capture_output=True, text=True).stdout
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

    def has_waiver(self, tag):
        """True if the file carries a '## style-ok: <tag>' waiver (shell
        grammar: exactly '##', any or no surrounding horizontal whitespace)."""
        if not self.source:
            return False
        pattern = re.compile(
            r'^[ \t]*##[ \t]*style-ok:[ \t]*' + re.escape(tag) + r'(?:[ \t]|$)',
            re.MULTILINE)
        return bool(pattern.search(self.source))

    def has_config_waiver(self, tag, slashes=False):
        """True for a '# style-ok: <tag>' waiver in CONFIG comment syntax: one or
        two '#' (systemd/cron/YAML), or '//' when SLASHES (apt)."""
        if not self.source:
            return False
        prefix = r'(?:#{1,2}|//)' if slashes else r'#{1,2}'
        pattern = re.compile(
            r'^[ \t]*' + prefix + r'[ \t]*style-ok:[ \t]*'
            + re.escape(tag) + r'(?:[ \t]|$)', re.MULTILINE)
        return bool(pattern.search(self.source))


## Convenience wrappers mirroring model.fail/note but filling ctx.path.
def fail(ctx, rule, message, node=None):
    return model.fail(rule, message, ctx.path, node)


def note(ctx, rule, message, node=None):
    return model.note(rule, message, ctx.path, node)
