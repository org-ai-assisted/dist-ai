## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Real bash parsing for the style tooling, via 'shfmt --to-json'.

The style rules (both detect and fix, via dist-ai-style) need to answer
STRUCTURAL questions about shell: is this token a command, or data inside a
string / heredoc / array? A regex cannot answer that, and hand-rolling a
quote/brace/heredoc state machine is the recurring trap the style guide forbids.

This module resolves the trap by USING a real parser -- 'shfmt --to-json'
(mvdan.cc/sh, the canonical Go shell parser, Debian package 'shfmt') -- and
exposing the few queries the rules need over its typed JSON syntax tree. The rule
is "never HAND-ROLL a parser", not "never parse": here every structural question
is one library call against a battle-tested AST.

shfmt is a HARD dependency. Its absence is a bug (a false green otherwise), so
parse() raises rather than degrading to a regex guess.

Byte offsets: every node carries absolute byte Offsets (Pos/End), so a fixer can
splice a surgical edit into the ORIGINAL source without reprinting (which would
reformat the whole file). Offsets index the UTF-8 encoded bytes of the source.
"""

import json
import os
import re
import shutil
import subprocess


def walk_files(paths):
    """Yield candidate file paths for each entry in PATHS: a file yields itself; a
    DIRECTORY is walked recursively (skipping '.git', not following directory
    symlinks), yielding its regular files in sorted order. A path that does not
    exist raises FileNotFoundError -- a mistyped or absent path is a loud error,
    NEVER a silent skip (the false-green a bare directory used to produce). The
    caller applies its own file-type filter; this only enumerates."""
    for path in paths:
        if os.path.isdir(path) and not os.path.islink(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d != ".git")
                for name in sorted(names):
                    full = os.path.join(root, name)
                    if os.path.isfile(full):
                        yield full
        elif os.path.exists(path):
            yield path
        else:
            raise FileNotFoundError(path)


class ShfmtMissing(Exception):
    """shfmt is not installed -- a required tool is absent (never a silent pass)."""


class BashParseError(Exception):
    """shfmt could not parse the source (a real syntax error, or a dialect it
    rejects). The caller must REPORT or DECLINE, never treat it as clean."""


## The command word of a CallExpr sits in Args[0]; a leading 'VAR=value' run is in
## Assigns, NOT Args, so Args[0] is always the real command in command position.
## This is exactly the command-position judgement the regex checks could only
## approximate.


def shfmt_available():
    return shutil.which("shfmt") is not None


def parse(source, dialect="bash"):
    """Parse shell SOURCE (str) and return the File node (a dict).

    Raises ShfmtMissing if shfmt is absent, BashParseError on a parse failure."""
    if not shfmt_available():
        message = "shfmt not found on PATH"
        raise ShfmtMissing(message)
    try:
        ## '-ln' is the portable short form of the dialect flag (the long
        ## '--language-dialect' was only added in a newer shfmt); '--to-json' has
        ## shipped since shfmt 3.x, which the supported Debian ships.
        result = subprocess.run(
            ["shfmt", "-ln", dialect, "--to-json"],
            input=source.encode("utf-8"),
            capture_output=True,
        )
    except OSError as exc:
        raise ShfmtMissing(str(exc)) from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise BashParseError(message or "shfmt failed to parse the source")
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BashParseError("shfmt emitted unreadable JSON: %s" % exc) from exc


def comments(tree):
    """Yield every comment node (it carries 'Hash' -- the '#' position -- and
    'Text')."""
    for node in iter_nodes(tree):
        if isinstance(node, dict) and "Hash" in node and "Text" in node:
            yield node


def parse_normalized(source, dialect="bash"):
    """Parse SOURCE, correcting a shfmt-vs-bash quirk: shfmt treats a backslash
    that ENDS A COMMENT line as a line-continuation and swallows the next line, so
    a real command hidden right after 'cmd # note \\' vanishes from the tree --
    but bash does NOT continue a comment (verified), so that command really runs.

    We use shfmt's OWN comment nodes to locate such a trailing backslash and
    neutralize it (replace with a SPACE -- same length, so every byte offset and
    line number is preserved), then re-parse so the hidden command is seen. Offset
    preservation means an offset-based fixer can use this too and still splice into
    the ORIGINAL source, leaving the comment's backslash intact.

    Raises ShfmtMissing / BashParseError like parse()."""
    tree = parse(source, dialect)
    lines = source.split("\n")
    changed = False
    for comment in comments(tree):
        index = comment.get("Hash", {}).get("Line", 0) - 1
        if not 0 <= index < len(lines):
            continue
        line = lines[index]
        ## Strip a trailing CR (CRLF input) BEFORE counting backslashes -- else a
        ## '# c \<CR>' line ends in '\r', rstrip("\\") removes nothing, the
        ## continuation is not neutralized, and shfmt stays BLIND to the next line.
        carriage = "\r" if line.endswith("\r") else ""
        body = line[:-1] if carriage else line
        trailing = len(body) - len(body.rstrip("\\"))
        ## Odd trailing-backslash run: the last one escapes the newline and makes
        ## shfmt continue the comment. A comment runs to end of line, so this
        ## backslash is unambiguously comment text -- safe to neutralize.
        if trailing % 2 == 1:
            lines[index] = body[:-1] + " " + carriage
            changed = True
    if changed:
        return parse("\n".join(lines), dialect)
    return tree


def iter_nodes(node):
    """Yield every dict node in the tree, depth-first, document order (node itself
    included). ITERATIVE (explicit stack), not recursive: a deeply nested tree -- an
    ~800-stage pipe / '&&' chain, or ~1600 chained elif -- would else exceed Python's
    recursion limit and crash the linter with an uncaught RecursionError on untrusted
    input. Every rule walks the tree through here, so the bound must be the heap, not
    the C stack. Children are pushed REVERSED so LIFO pops emit them in original order
    and each child's whole subtree precedes the next sibling (pre-order, left to right)."""
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            yield current
            stack.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))


def nodes_of_type(tree, type_name):
    """Yield every node whose Type is TYPE_NAME."""
    for node in iter_nodes(tree):
        if node.get("Type") == type_name:
            yield node


def call_exprs(tree):
    """Yield every CallExpr (a simple command with its Args and Assigns)."""
    yield from nodes_of_type(tree, "CallExpr")


_PIPE_OPS = None


def pipe_ops():
    """The BinaryCmd Op codes for '|' and '|&'. shfmt encodes Op as a NUMERIC
    token whose value can shift between versions, so DERIVE it by parsing known
    pipelines rather than hardcode a magic number -- self-calibrating, and a
    version that renumbered would still be read correctly. Cached."""
    global _PIPE_OPS
    if _PIPE_OPS is None:
        ops = set()
        for snippet in ("a | b", "a |& b"):
            for node in nodes_of_type(parse(snippet), "BinaryCmd"):
                ops.add(node.get("Op"))
        _PIPE_OPS = ops
    return _PIPE_OPS


def pipe_binary_cmds(tree):
    """Yield every BinaryCmd that is a pipe ('|' or '|&')."""
    ops = pipe_ops()
    for node in nodes_of_type(tree, "BinaryCmd"):
        if node.get("Op") in ops:
            yield node


_OR_OPS = None


def or_op():
    """The BinaryCmd Op code(s) for '||' -- DERIVED by parsing rather than hardcoded
    (shfmt numbers Op and may renumber between versions), like pipe_ops. Cached."""
    global _OR_OPS
    if _OR_OPS is None:
        codes = set()
        for node in nodes_of_type(parse("a || b"), "BinaryCmd"):
            codes.add(node.get("Op"))
        _OR_OPS = codes
    return _OR_OPS


_CASE_DBLSEMI_OPS = None


def case_dblsemi_ops():
    """The CaseItem Op code(s) for a ';;' arm terminator -- DERIVED by parsing
    rather than hardcoded (shfmt numbers Op and may renumber between versions),
    like pipe_ops. Parsing a plain ';;' arm excludes the ';&' (fallthrough) and
    ';;&' (continue-testing) terminators, which are DIFFERENT ops. Cached."""
    global _CASE_DBLSEMI_OPS
    if _CASE_DBLSEMI_OPS is None:
        codes = set()
        for clause in nodes_of_type(parse("case x in\na) : ;;\nesac"),
                                    "CaseClause"):
            for item in clause.get("Items", []):
                codes.add(item.get("Op"))
        _CASE_DBLSEMI_OPS = codes
    return _CASE_DBLSEMI_OPS


def func_decls(tree):
    """Yield every FuncDecl (a shell function definition)."""
    yield from nodes_of_type(tree, "FuncDecl")


def iter_stmts(tree):
    """Yield every Stmt node anywhere in TREE (top level, blocks, pipelines,
    function bodies, ...). A Stmt is the dict carrying 'Cmd' (its command node)
    and 'Redirs' (its redirections, including heredocs). Stmt nodes have no 'Type'
    field, so they are identified by the 'Cmd' key."""
    for node in iter_nodes(tree):
        if isinstance(node, dict) and "Cmd" in node and "Type" not in node:
            yield node


def heredoc_bodies(stmt):
    """Yield (redirect, body_line_count) for each HEREDOC redirection on STMT.
    body_line_count is the number of body lines (End.Line - Pos.Line of the
    here-document word), i.e. lines between the opener and the terminator."""
    for redirect in stmt.get("Redirs") or []:
        hdoc = redirect.get("Hdoc")
        if not isinstance(hdoc, dict):
            continue
        lines = hdoc["End"]["Line"] - hdoc["Pos"]["Line"]
        yield redirect, lines


def heredoc_spans(tree):
    """Yield (start, end) byte offsets of every here-document BODY in TREE. A
    command that appears only inside one of these spans (e.g. a '$(...)' in the
    here-document text) is not at a real command-line position: a fixer that
    inserts a comment line there would splice it into the here-document DATA and
    corrupt it."""
    for stmt in iter_stmts(tree):
        for redirect, _lines in heredoc_bodies(stmt):
            hdoc = redirect.get("Hdoc")
            if isinstance(hdoc, dict):
                yield hdoc["Pos"]["Offset"], hdoc["End"]["Offset"]


def defines_function(tree, name):
    """True if the script defines a shell function called NAME. A later 'name ...'
    then calls THAT function, not the coreutils tool -- so a command-name rule
    (e.g. bare 'timeout') must not treat it as the external command."""
    for decl in func_decls(tree):
        function_name = decl.get("Name") or {}
        if function_name.get("Value") == name:
            return True
    return False


def word_span(word):
    """(start, end) absolute byte offsets of WORD in the source."""
    return word["Pos"]["Offset"], word["End"]["Offset"]


def word_source(word, source):
    """The raw source text of WORD (quotes and expansions included), sliced by its
    byte offsets. Use when a rule cares about the word's spelling even though it is
    not a plain literal -- e.g. a path operand like '"${dir}/foo.py"'."""
    data = source.encode("utf-8")
    start, end = word_span(word)
    return data[start:end].decode("utf-8", "replace")


def word_lit(word):
    """The literal string if WORD is a single UNQUOTED Lit part, else None.

    A bare command word ('mkdir'), a short flag ('-iq'), and a literal duration
    ('5') are single Lit parts. A quoted or expanded word ('"$TMPDIR/x"',
    '$dur') is NOT -- so a rewrite that assumes plain, unquoted text safely
    DECLINES it by getting None here."""
    parts = word.get("Parts") or []
    if len(parts) == 1 and parts[0].get("Type") == "Lit":
        return parts[0].get("Value")
    return None


def _deescape_unquoted_lit(value):
    """Strip the backslash-escapes bash removes from an UNQUOTED word before it uses
    it: '\\rm' -> 'rm', 'rm\\ x' -> 'rm x', '\\\\' -> '\\'. shfmt keeps the backslash
    in an unquoted Lit.Value, so a resolver that does not strip it reads '\\rm' as a
    different command than the 'rm' bash actually runs -- a gate bypass."""
    return re.sub(r'\\(.)', r'\1', value)


def word_string(word):
    """WORD's fully-literal string value, or None if any part is a
    parameter/command/arithmetic expansion (its value is not statically known).
    Unwraps normal single-/double-quotes AND unquoted backslash-escapes, so 'false',
    "false", 'false', and \\false all yield 'false' -- the value bash actually runs.
    SCOPE (accident, not adversary): this normalizes ACCIDENTAL quoting/escaping; it
    does NOT decode an ANSI-C $'...' word -- $'\\x72m' stays '\\x72m', not 'rm' -- so a
    hex/octal-encoded command word can still slip a name-based rule. That is a crafted
    form, dropped per the accident-not-adversary threat model (same honesty scope as the
    effective_command raw-source note). (word_lit is stricter: it declines any quoted or
    multi-part word.)"""
    if word is None:
        return None
    out = []
    for part in word.get("Parts") or []:
        kind = part.get("Type")
        if kind == "Lit":
            ## Unquoted: bash strips backslash-escapes before it uses the word.
            out.append(_deescape_unquoted_lit(part.get("Value") or ""))
        elif kind == "SglQuoted":
            ## Normal '...' carries no escapes. An ANSI-C $'...' word also arrives here
            ## with its Value UNDECODED ($'\x72m' -> raw '\x72m'); decoding it is a
            ## crafted-form concern, dropped per accident-not-adversary (see docstring).
            out.append(part.get("Value") or "")
        elif kind == "DblQuoted":
            for inner in part.get("Parts") or []:
                if inner.get("Type") != "Lit":
                    return None
                out.append(inner.get("Value") or "")
        else:
            return None
    return "".join(out)

## A CallExpr's own arguments, always a list (never None).


def args(call):
    return call.get("Args") or []


## A CallExpr's assignments -- an env prefix ('X=y cmd') or a standalone 'X=y'
## statement -- kept SEPARATE from args()/command position by the parser, so a
## quoted mention of 'X=y' inside a string is never one of these.


def assigns(call):
    return call.get("Assigns") or []


def assign_name(assign):
    """The variable NAME of an assignment ('make_use_lintian' of
    'make_use_lintian=false')."""
    return (assign.get("Name") or {}).get("Value")


def assign_value(assign):
    """The value WORD of an assignment, or None for a bare 'X=' with no RHS."""
    return assign.get("Value")


def command_word(call):
    """The Word in command position (Args[0]), or None for an assignment-only
    statement ('VAR=value' with no command)."""
    call_args = args(call)
    return call_args[0] if call_args else None


def command_name(call):
    """The literal command name of CALL, or None when there is no command word or
    the command word carries an EXPANSION. A fully-literal quoted command ('"rm"',
    "'rm'", 'r"m"') resolves to its value via word_string, so a rule keyed on the
    name is not bypassed by quoting; only a real expansion ('$cmd') declines."""
    word = command_word(call)
    return word_string(word) if word is not None else None


def resolve_long(name, names):
    """Resolve a '--' long-option NAME (leading '--' and any '=value' already
    stripped) to the single option in NAMES it denotes under GNU getopt_long's
    unambiguous-prefix rule: an exact member, else the sole member NAME is a
    prefix of. None when it matches zero members or is an AMBIGUOUS prefix of two
    or more -- getopt rejects such an abbreviation, so it denotes no one option.

    NAMES is the caller's KNOWN option set. HONEST SCOPE: a caller passes only
    the options it distinguishes, so an abbreviation made ambiguous by an option
    OUTSIDE NAMES cannot be seen here -- but that is a malformed command getopt
    itself rejects, so it is out of scope."""
    if name in names:
        return name
    matches = [candidate for candidate in names if candidate.startswith(name)]
    return matches[0] if len(matches) == 1 else None


def command_tokens(call, source, value_short=frozenset(), value_long=frozenset()):
    """Classify a command's arguments (Args[1:]) for option parsing, yielding
    (kind, word, text):
      - 'opt'     -- an option word ('-p', '-iq', '--mode', '--mode=700', or the
                     '--' end-of-options marker). text is its source spelling, so
                     an option whose VALUE carries an expansion ('--mode="$x"',
                     which is not a plain literal) is still classed 'opt', never
                     mistaken for an operand.
      - 'value'   -- the SEPARATE value of the preceding value-taking option
                     (space form: the '700' of '--mode 700', the 'foo' of
                     'grep -e foo'). Skipping these is why a later flag is not
                     lost and a value is not mistaken for a flag.
      - 'operand' -- the first non-option word, and everything after it (and
                     everything after a '--').
    value_short: single letters that, as the LAST char of a short cluster, take a
    separate next-word value ('-e' -> the next word). value_long: long option
    NAMES (no leading '--', no '=') that take a separate value in space form
    ('--signal' -> the next word). A long option is matched by getopt_long's
    unambiguous-prefix rule, so '--sig' consumes a value just as '--signal' does
    (see resolve_long). HONEST SCOPE: value_long is the value-taking SUBSET of a
    command's options, so an abbreviation made AMBIGUOUS by a NON-value long
    option (outside value_long) cannot be detected here -- but that is a
    malformed command getopt itself rejects, so it is out of scope (same limit as
    the word_string ANSI-C note)."""
    expect_value = False
    operand_region = False
    for word in args(call)[1:]:
        ## word_string (not word_lit) resolves a fully-literal QUOTED flag ('"-e"',
        ## "'--'") to its value so it classifies as the option it is -- a quoted flag
        ## must not read as an operand and defeat the option scan. A real expansion
        ## still yields None and falls back to the raw source (stays 'opt').
        lit = word_string(word)
        text = lit if lit is not None else word_source(word, source)
        if operand_region:
            yield ("operand", word, text)
            continue
        if expect_value:
            expect_value = False
            yield ("value", word, text)
            continue
        if text == "--":
            yield ("opt", word, text)
            operand_region = True
            continue
        if text.startswith("-") and text != "-":
            yield ("opt", word, text)
            if text.startswith("--"):
                if "=" not in text and resolve_long(text[2:], value_long) \
                        is not None:
                    expect_value = True
            else:
                ## A value-taker letter consumes the REST of the cluster as its
                ## value; only when it is the LAST char does it take the next word.
                cluster = text[1:]
                for position, letter in enumerate(cluster):
                    if letter in value_short:
                        if position == len(cluster) - 1:
                            expect_value = True
                        break
            continue
        operand_region = True
        yield ("operand", word, text)


def word_param_names(word):
    """Set of parameter names expanded anywhere in WORD, including inside double
    quotes -- so 'mkdir ... "$TMPDIR/x"' reports {'TMPDIR'}. Used to tell a
    temp-dir operand from an ordinary path without inspecting raw text."""
    names = set()
    for node in iter_nodes(word):
        if node.get("Type") == "ParamExp":
            param = node.get("Param") or {}
            value = param.get("Value")
            if value:
                names.add(value)
    return names


class LineMap:
    """Map a byte offset to a 1-based (line, col), for diagnostics. Built from the
    source once; shfmt's own Line/Col are also available on each node, so this is
    only needed where an offset is computed rather than taken from a node."""

    def __init__(self, source):
        data = source.encode("utf-8")
        self._starts = [0]
        for index, byte in enumerate(data):
            if byte == 0x0A:
                self._starts.append(index + 1)

    def linecol(self, offset):
        lo, hi = 0, len(self._starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - self._starts[lo] + 1


def apply_edits(source, edits):
    """Apply EDITS to SOURCE and return the new text. Each edit is
    (start, end, replacement) in byte offsets. Edits must not overlap; they are
    applied right-to-left so earlier offsets stay valid. Offsets index UTF-8
    bytes, so the splice is done on the encoded form and decoded back."""
    if not edits:
        return source
    data = bytearray(source.encode("utf-8"))
    for start, end, replacement in sorted(edits, key=lambda e: e[0], reverse=True):
        data[start:end] = replacement.encode("utf-8")
    return data.decode("utf-8")
