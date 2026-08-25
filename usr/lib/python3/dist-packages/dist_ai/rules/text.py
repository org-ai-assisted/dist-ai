## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Text rules -- no shell parse needed. R-001 (non-ASCII confusables) and
trailing whitespace. Each expresses BOTH detect and fix, and its fix() yields
byte-span Edits on the same apply_edits model the AST rules use, so the whole
engine has one edit representation.

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

NON_ASCII_RE = re.compile(rb'[^\x00-\x7f]')
TRAILING_RE = re.compile(rb'[ \t]+(?=\r?\n|\Z)')


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
        return (super().applies(ctx) and ctx.source is not None
                and not ctx.is_binary)

    def detect(self, ctx):
        data = ctx.source.encode("utf-8")
        match = NON_ASCII_RE.search(data)
        if match:
            yield model.fail(
                "R-001", "R-001 non-ASCII character(s)", ctx.path,
                _line_of_byte(data, match.start()))

    def fix(self, ctx):
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
        return super().applies(ctx) and ctx.source is not None and ctx.is_text

    def detect(self, ctx):
        data = ctx.source.encode("utf-8")
        for match in TRAILING_RE.finditer(data):
            yield model.fail(
                "trailing-whitespace", "trailing whitespace", ctx.path,
                _line_of_byte(data, match.start()))

    def fix(self, ctx):
        data = ctx.source.encode("utf-8")
        for match in TRAILING_RE.finditer(data):
            yield Edit(match.start(), match.end(), "", "trailing-whitespace")


RULES = (
    Confusables(),
    TrailingWhitespace(),
)
