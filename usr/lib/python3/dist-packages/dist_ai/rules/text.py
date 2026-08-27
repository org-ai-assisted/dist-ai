## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Text rules -- no shell parse needed. R-001 (non-ASCII confusables), trailing
whitespace, and the hardened python shebang. Each expresses BOTH detect and fix,
and its fix() yields byte-span Edits on the same apply_edits model the AST rules
use, so the whole engine has one edit representation.

The detect/fix asymmetry is real and preserved: detect() reports ANY non-ASCII
byte; fix() rewrites only the KNOWN confusable table (an intentional UTF-8
fixture is never silently mangled), so a residual non-ASCII still blocks."""

import re

from dist_ai import model
from dist_ai.model import Edit, Rule

## Always-safe confusables: the ASCII form is never a quote or syntax character,
## so substituting changes string CONTENT only. Keys are \u escapes so THIS
## source stays ASCII (it must pass its own R-001).
CONFUSABLES = {
    "\u2014": "--",   ## em dash
    "\u2013": "-",    ## en dash
    "\u2026": "...",  ## horizontal ellipsis
    "\u2192": "->",   ## rightwards arrow
    "\u2190": "<-",   ## leftwards arrow
    "\u00a0": " ",    ## no-break space
    "\u2022": "-",    ## bullet
}

## Smart quotes -> ASCII quotes, and entity spellings of dashes. These ARE syntax
## in code, so applied to PROSE/MARKUP files only.
QUOTES = {
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
}
ENTITIES = {
    "&mdash;": "--", "&ndash;": "-", "&#8212;": "--", "&#8211;": "-",
    "&#x2014;": "--", "&#x2013;": "-", "&#X2014;": "--", "&#X2013;": "-",
}
MARKUP_EXTS = (".html", ".htm", ".md", ".markdown", ".css", ".txt", ".rst")

## The hardened python interpreter line: -B (write no .pyc, so a read-only or
## packaged tree gets no __pycache__ and no stale-bytecode surprise), -s (do NOT
## add the user site-packages dir -- the security-relevant flag: a per-user
## drop-in cannot shadow a stdlib/system import), -u (unbuffered stdout/stderr).
## Matches the helper-scripts convention (17/18 of its python helpers).
PYTHON_SHEBANG = "#!/usr/bin/python3 -Bsu"
PYTHON_SHEBANG_BYTES = PYTHON_SHEBANG.encode("ascii")
## A FIRST line naming a python interpreter, in any spelling: an absolute or
## '/usr/bin/env' path, 'env -S', a versioned name, with or without flags.
## Anchored to the interpreter word so a shell / perl shebang -- or the word
## 'python' anywhere later in the file -- is never matched.
PYTHON_SHEBANG_RE = re.compile(
    rb'^#!(?:\S*/)?(?:env\s+(?:-S\s+)?)?python[0-9.]*(?:\s|$)')

NON_ASCII_RE = re.compile(rb'[^\x00-\x7f]')
## Trailing blanks before end-of-line: a LF, a CRLF, or a lone trailing CR /
## end-of-file. The '\r?' in the end-of-file branch matters -- 'foo  \r' with no
## LF (old-Mac line end) has blanks before a bare CR, which the former fixer
## stripped (peel CR, rstrip) and a plain '\Z' lookahead would miss.
TRAILING_RE = re.compile(rb'[ \t]+(?=\r?\n|\r?\Z)')


def _line_of_byte(data, offset):
    """1-based line number of a byte OFFSET in DATA (bytes)."""
    return data.count(b"\n", 0, offset) + 1


def _substitution_edits(data, table, rule_id):
    """Byte-span Edits replacing every occurrence of each key in TABLE. Keys are
    str; matched by their UTF-8 encoding in DATA (bytes)."""
    for needle, repl in table.items():
        raw = needle.encode("utf-8")
        start = data.find(raw)
        while start != -1:
            yield Edit(start, start + len(raw), repl, rule_id)
            start = data.find(raw, start + len(raw))


class Confusables(Rule):
    """R-001: a non-ASCII byte. fix() substitutes the known confusable set (and,
    in prose/markup only, smart quotes + dash entities); any other non-ASCII is
    left for a human, so detect() still reports it."""

    id = "R-001"
    waiver_tag = "allow-non-ascii"

    def applies(self, ctx):
        ## detect works on RAW bytes (ctx.data), so a non-UTF-8 file's stray
        ## high byte is still caught -- source may be None here.
        return (super().applies(ctx) and ctx.data is not None
                and not ctx.is_binary)

    def detect(self, ctx):
        data = ctx.data
        match = NON_ASCII_RE.search(data)
        if match:
            yield model.fail(
                "R-001", "R-001 non-ASCII character(s)", ctx.path,
                _line_of_byte(data, match.start()))

    def fix(self, ctx):
        ## A confusable substitution rewrites decoded text; a file that does not
        ## decode as UTF-8 cannot be fixed here -- detect() still blocks it.
        if ctx.source is None:
            return
        data = ctx.source.encode("utf-8")
        yield from _substitution_edits(data, CONFUSABLES, "R-001")
        if ctx.path.lower().endswith(MARKUP_EXTS):
            ## Quote/entity rewrites are markup-only and tallied separately, so
            ## the summary distinguishes them (matching the former fixer).
            yield from _substitution_edits(data, QUOTES, "R-001-markup")
            yield from _substitution_edits(data, ENTITIES, "R-001-markup")


class TrailingWhitespace(Rule):
    """Trailing space/tab before end-of-line. Scoped to text files (matching the
    gate's is_text). CR and a final no-newline are preserved (the lookahead never
    consumes them)."""

    id = "trailing-whitespace"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.data is not None and ctx.is_text

    def detect(self, ctx):
        data = ctx.data
        for match in TRAILING_RE.finditer(data):
            yield model.fail(
                "trailing-whitespace", "trailing-whitespace", ctx.path,
                _line_of_byte(data, match.start()))

    def fix(self, ctx):
        ## A stripping edit rewrites the decoded source the engine writes back; a
        ## non-UTF-8 file has no source to rewrite, so decline (detect still
        ## reports its trailing blanks off the raw bytes).
        if ctx.source is None:
            return
        data = ctx.source.encode("utf-8")
        for match in TRAILING_RE.finditer(data):
            yield Edit(match.start(), match.end(), "", "trailing-whitespace")


def _first_line_span(data):
    """(first line WITHOUT its newline, byte offset of its end). end is the LF
    position, or len(data) for a file with no newline."""
    end = data.find(b"\n")
    if end == -1:
        end = len(data)
    return data[:end], end


class PythonShebang(Rule):
    """A python shebang must be the hardened '#!/usr/bin/python3 -Bsu'. Any other
    python interpreter line -- the '/usr/bin/env' form, a bare '#!/usr/bin/python3',
    a partial flag set ('-su', '-u'), a versioned name -- is rewritten to it.

    Fires ONLY on a file that ALREADY declares a python interpreter on line 1: a
    shebang-less importable module is left untouched (adding a shebang would
    wrongly mark it an executable, against Debian policy). A file needing a
    different interpreter line (e.g. an isolated '-I', or a deliberate venv path)
    opts out with the '## style-ok: allow-python-shebang' file waiver."""

    id = "python-shebang"
    waiver_tag = "allow-python-shebang"

    def applies(self, ctx):
        ## Detect off RAW bytes (like R-001) so an extensionless python tool under
        ## usr/bin is covered, not only a '.py' file.
        return (super().applies(ctx) and ctx.data is not None
                and not ctx.is_binary
                and PYTHON_SHEBANG_RE.match(ctx.data) is not None)

    def detect(self, ctx):
        first, _end = _first_line_span(ctx.data)
        if first != PYTHON_SHEBANG_BYTES:
            yield model.fail(
                "python-shebang",
                "python-shebang: use the hardened '%s'" % PYTHON_SHEBANG,
                ctx.path, 1)

    def fix(self, ctx):
        ## A rewrite edits the decoded source the engine writes back; a file that
        ## does not decode as UTF-8 has no source to rewrite (detect still reports
        ## it off the raw bytes).
        if ctx.source is None:
            return
        data = ctx.source.encode("utf-8")
        first, end = _first_line_span(data)
        if first != PYTHON_SHEBANG_BYTES:
            yield Edit(0, end, PYTHON_SHEBANG, "python-shebang")


RULES = (
    Confusables(),
    TrailingWhitespace(),
    PythonShebang(),
)
