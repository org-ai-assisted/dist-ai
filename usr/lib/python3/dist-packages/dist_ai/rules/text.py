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
## A basename that IS a python interpreter ('python', 'python3', 'python3.11').
PYTHON_NAME_RE = re.compile(rb'^python[0-9.]*$')

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
    """(first line WITHOUT its line ending, byte offset of its end). end is the
    position of the first LF *or* CR, or len(data) when the file has neither.
    Honoring CR too matters for the fixer: replacing [0, end) must never reach
    past the first line, or a CR-terminated ('\\r') or CRLF file would have its
    body swallowed by the shebang rewrite."""
    ends = [pos for pos in (data.find(b"\n"), data.find(b"\r")) if pos != -1]
    end = min(ends) if ends else len(data)
    return data[:end], end


def _python_interpreter_shebang(first):
    """True if the '#!' line `first` (bytes, no line ending) launches a python
    interpreter -- directly ('#!/usr/bin/python3', '#! /usr/bin/python3.11') or
    via '/usr/bin/env' with any leading options / VAR=val ('env -S FOO=bar
    python3'). Parses only the FIRST line's own tokens, so a 'python' word on a
    LATER line (or in the body) is never mistaken for the interpreter."""
    if not first.startswith(b"#!"):
        return False
    ## The kernel takes the first token after '#!' (a leading space is allowed)
    ## as the interpreter.
    tokens = first[2:].split()
    if not tokens:
        return False
    if PYTHON_NAME_RE.match(tokens[0].rsplit(b"/", 1)[-1]):
        return True
    ## '/usr/bin/env [options|VAR=val ...] CMD ...': env's command is the first
    ## token that is neither an option, an option's OPERAND, nor a VAR=val. '-u
    ## NAME' / '-C DIR' take a following operand, so skipping only the option word
    ## mistook its operand for the command ('env -S -u FOO python3' read FOO as the
    ## command and missed python3 -- a hardening bypass).
    if tokens[0].rsplit(b"/", 1)[-1] == b"env":
        command = _env_command(tokens[1:])
        return (command is not None
                and PYTHON_NAME_RE.match(command.rsplit(b"/", 1)[-1]) is not None)
    return False


## env short/long options that consume the FOLLOWING token as an operand (only
## when given space-separated -- '-uNAME' / '--unset=NAME' carry it in one token).
_ENV_OPERAND_OPTS = (b"-u", b"--unset", b"-C", b"--chdir", b"-a", b"--argv0")


def _env_command(tokens):
    """The command token env runs, given env's args (bytes list), or None. Skips
    options, their space-separated operands, VAR=val assignments, and '-S'/'--
    split-string' (whose content is simply the following tokens); '--' ends option
    processing. A small, fixed env-option skip -- not a general parser.

    OUT of scope, by design (never reinvent a parser -- and these are evasions, not
    shebangs a developer writes): env's '-S' split-string MINI-LANGUAGE with the
    command crammed into ONE token -- an attached arg ('-S-u FOO python3'), the
    '--split-string=python3' equals form, or a QUOTED body ('-S "FOO=bar python3"')
    whose quotes env strips but a plain '.split()' leaves attached. Emulating -S
    (attached args, '=', quote/escape stripping) is the treadmill the standing rule
    forbids; a real '-S' need uses the space-separated form (handled) or the
    'allow-python-shebang' waiver. The realistic env forms -- 'env python3', 'env
    -S python3 -flags', 'env VAR=val python3', 'env -u/-C/-a OPERAND python3' -- all
    resolve here."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == b"--":
            index += 1
            break
        if token in (b"-S", b"--split-string"):
            index += 1
            continue
        if token in _ENV_OPERAND_OPTS:
            index += 2  ## the option AND its separate operand
            continue
        if token.startswith(b"-") or b"=" in token:
            index += 1  ## a bundled/attached option or a VAR=val assignment
            continue
        break  ## the first plain word is the command
    return tokens[index] if index < len(tokens) else None


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
        ## usr/bin is covered, not only a '.py' file. The interpreter is decided
        ## from LINE 1 alone.
        if not (super().applies(ctx) and ctx.data is not None
                and not ctx.is_binary):
            return False
        first, _end = _first_line_span(ctx.data)
        return _python_interpreter_shebang(first)

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
