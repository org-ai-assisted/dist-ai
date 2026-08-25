## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared shell-analysis helpers for the rule objects: command unwrapping,
context-aware statement walking, the printf -v target analysis, and the
embedded-shell ('-c' / config value) parsing. Each answers a STRUCTURAL question
from the shfmt AST, never a regex guess."""

import re

from dist_ai import bash_ast

## Command wrappers whose real program is a later argument: 'sudo apt-get ...',
## 'doas rm ...'.
EXEC_WRAPPERS = ("sudo", "doas")

## sudo/doas options that take a SEPARATE value ('sudo -u www-data cmd'); their
## value must not be mistaken for the wrapped command.
SUDO_VALUE_SHORT = frozenset("ughprtCTRDU")
SUDO_VALUE_LONG = frozenset({
    "user", "group", "host", "prompt", "role", "type", "close-from",
    "command-timeout", "chroot", "chdir", "other-user"})


def _basename(name):
    """The command BASENAME -- '/bin/rm' and 'rm' are the same program, so a rule
    keying on the name must not be evaded by a path (as shell_c_programs and
    InterpreterPrepend already resolve). None passes through."""
    return name.rsplit("/", 1)[-1] if name is not None else None


def effective_command(call, source):
    """The BASENAME of the program CALL actually runs, unwrapping a leading
    'sudo'/'doas' (skipping its options, their values, and 'VAR=value' prefixes).
    None when the wrapped command word is quoted/expanded or cannot be resolved --
    the safe direction (a rule declines rather than guesses). Path-qualified names
    ('/bin/rm', '/usr/bin/sudo rm') resolve by basename so a rule is not bypassed."""
    name = _basename(bash_ast.command_name(call))
    if name not in EXEC_WRAPPERS:
        return name
    for kind, word, _text in bash_ast.command_tokens(
            call, source, SUDO_VALUE_SHORT, SUDO_VALUE_LONG):
        if kind == "value":
            continue
        if kind == "operand":
            ## The first word past the wrapper's options is the real command; a
            ## leading 'VAR=value' env-assignment is still not the command. Test
            ## the SOURCE, since a quoted value ('FOO="bar"') makes word_lit None
            ## -- otherwise the unwrap aborts and 'sudo FOO="bar" rm' bypasses R-120.
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=',
                        bash_ast.word_source(word, source)):
                continue
            return _basename(bash_ast.word_lit(word))
    return None


## Statement CONTEXT: a command in a loop/if CONDITION is not the same as one in
## a body. R-130 (bare ':') must fire on a filler ':' statement but NOT on the
## ':' condition of 'while :; do'. shfmt's JSON has no parent pointers, so we
## walk the known body vs condition stmt-lists explicitly.
CONTEXT_STMT = "stmt"
CONTEXT_COND = "cond"


def _walk_stmts(stmts, context, out):
    for stmt in stmts or []:
        _walk_command_stmt(stmt, context, out)


def _walk_command_stmt(stmt, context, out):
    if not isinstance(stmt, dict):
        return
    out.append((stmt, context))
    _walk_command(stmt.get("Cmd"), context, out)


def _walk_command(cmd, context, out):
    if not isinstance(cmd, dict):
        return
    kind = cmd.get("Type")
    if kind in ("Block", "Subshell"):
        ## A group/subshell INHERITS its enclosing context -- a block that IS a
        ## loop/if condition keeps its statements in condition context.
        _walk_stmts(cmd.get("Stmts"), context, out)
    elif kind == "IfClause":
        _walk_if(cmd, out)
    elif kind == "WhileClause":
        _walk_stmts(cmd.get("Cond"), CONTEXT_COND, out)
        _walk_stmts(cmd.get("Do"), CONTEXT_STMT, out)
    elif kind == "ForClause":
        _walk_stmts(cmd.get("Do"), CONTEXT_STMT, out)
    elif kind == "CaseClause":
        for item in cmd.get("Items") or []:
            _walk_stmts(item.get("Stmts"), CONTEXT_STMT, out)
    elif kind == "BinaryCmd":
        ## A pipeline / '&&' / '||': both sides KEEP the enclosing context, so a
        ## ':' that is only the left side of a CONDITION pipeline stays 'cond'.
        _walk_command_stmt(cmd.get("X"), context, out)
        _walk_command_stmt(cmd.get("Y"), context, out)
    elif kind == "FuncDecl":
        _walk_command_stmt(cmd.get("Body"), CONTEXT_STMT, out)


def _walk_if(cmd, out):
    _walk_stmts(cmd.get("Cond"), CONTEXT_COND, out)
    _walk_stmts(cmd.get("Then"), CONTEXT_STMT, out)
    else_node = cmd.get("Else")
    if isinstance(else_node, dict):
        ## 'elif' is a nested IfClause in the Else slot; 'else' is a plain block.
        _walk_if(else_node, out) if else_node.get("Cond") else \
            _walk_stmts(else_node.get("Then") or else_node.get("Stmts"),
                        CONTEXT_STMT, out)


def statements(tree):
    """Yield (stmt, context) for every Stmt in TREE, context-aware (a loop/if
    CONDITION vs a body). stmt['Cmd'] is the command node; stmt['Redirs'] its
    redirections."""
    out = []
    _walk_stmts(tree.get("Stmts"), CONTEXT_STMT, out)
    return out


def line_is_bare_colon(source, node):
    """True if NODE's physical line is just ':' (optional surrounding
    whitespace) -- the 'bare colon alone on a line' form for R-130."""
    lines = source.split("\n")
    index = node["Pos"]["Line"] - 1
    return 0 <= index < len(lines) and lines[index].strip() == ":"


## --- printf -v injection guard ---------------------------------------------


def _deescape_unquoted(value):
    """Remove unquoted backslash-escapes from a Lit VALUE the way bash does on an
    unquoted word: '\\-v' -> '-v', '\\\\' -> '\\'. shfmt keeps the backslash in an
    unquoted Lit.Value, so option detection must strip it -- else 'printf \\-v x'
    is not seen as the '-v' option and the R-063 injection guard is bypassed."""
    return re.sub(r'\\(.)', r'\1', value)


def word_literal_prefix(word):
    """The leading LITERAL text of WORD, with quote SYNTAX and unquoted
    backslash-escapes removed, up to the first expansion. 'printf' -> 'printf',
    '"-v"' -> '-v', r'\\-v' -> '-v', '"-v${x}"' -> '-v', '"${x}"' -> ''. Option
    detection must see what bash's own getopt sees AFTER quote AND escape removal,
    so '"-v"' and r'\\-v' are both the '-v' option, not data."""
    out = []
    for part in word.get("Parts") or []:
        kind = part.get("Type")
        if kind == "Lit":
            ## Unquoted Lit: bash strips its backslash-escapes before getopt sees
            ## it. SglQuoted/DblQuoted below carry their own (different) rules.
            out.append(_deescape_unquoted(part.get("Value") or ""))
        elif kind == "SglQuoted":
            out.append(part.get("Value") or "")
        elif kind == "DblQuoted":
            for inner in part.get("Parts") or []:
                if inner.get("Type") != "Lit":
                    return "".join(out)
                out.append(inner.get("Value") or "")
        else:
            ## ParamExp / CmdSubst / arithmetic: the literal prefix ends here.
            return "".join(out)
    return "".join(out)


def printf_v_target(call):
    """The Word carrying the EFFECTIVE 'printf -v' target NAME, or None when the
    printf writes no variable. Follows bash's own printf option parsing over the
    QUOTE-REMOVED argument: options precede the format operand (the first
    non-option word), '--' ends option scanning, '-v' is recognized in both the
    separate ('-v name') and attached ('-vNAME') form and whatever the quoting,
    and a repeated '-v' takes the LAST target before the format."""
    call_args = bash_ast.args(call)
    target = None
    index = 1
    while index < len(call_args):
        word = call_args[index]
        ## word_string is None iff the word carries an expansion; it does NOT
        ## de-escape, so it cannot decide '-v'. The de-escaped literal prefix
        ## does (it is the whole value when there is no expansion).
        has_expansion = bash_ast.word_string(word) is None
        prefix = word_literal_prefix(word)
        if prefix == "--":
            break
        if prefix.startswith("-v"):
            if prefix == "-v" and not has_expansion:
                ## The whole word is exactly '-v' (however spelled): separate
                ## form, the NAME is the next word.
                if index + 1 < len(call_args):
                    target = call_args[index + 1]
                    index += 2
                    continue
                index += 1
                continue
            ## Attached form ('-vNAME' / '-v${x}'): name embedded in this word.
            target = word
            index += 1
            continue
        break
    return target


def word_has_command_expansion(word):
    """True if WORD contains a command substitution ($(...) or backticks) or an
    arithmetic expansion. A printf -v target carrying one can NEVER be made safe
    by check_variable_name -- bash evaluates the array subscript, running the
    substitution -- so it must be flagged whatever parameters were checked."""
    for node in bash_ast.iter_nodes(word):
        if node.get("Type") in ("CmdSubst", "ArithmExp", "ArithmCmd"):
            return True
    return False


def check_variable_name_sites(tree):
    """(offset, scope_start, param_names) for every 'check_variable_name' call:
    its byte offset, the start of the innermost function enclosing it, and the
    set of parameter names its arguments expand."""
    sites = []
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "check_variable_name":
            continue
        params = set()
        for word in bash_ast.args(call)[1:]:
            params |= bash_ast.word_param_names(word)
        offset = call["Pos"]["Offset"]
        sites.append((offset, enclosing_scope_start(tree, offset), params))
    return sites


def enclosing_scope_start(tree, offset):
    """Byte offset where the scope containing OFFSET begins: the body of the
    innermost function enclosing it, or 0 at top level."""
    best = 0
    best_span = None
    for decl in bash_ast.func_decls(tree):
        body = decl.get("Body") or {}
        start = (body.get("Pos") or {}).get("Offset")
        end = (body.get("End") or {}).get("Offset")
        if start is None or end is None:
            continue
        if start <= offset < end:
            span = end - start
            if best_span is None or span < best_span:
                best_span, best = span, start
    return best


## --- embedded shell in a '-c' string / config value ------------------------

SHELL_C_CMDS = frozenset({"sh", "bash", "dash"})


def unquote(text):
    """Strip ONE layer of matching outer quotes from TEXT."""
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def code_only_lines(source, tree):
    """SOURCE's lines with any trailing '#'-comment stripped, located via the
    AST's OWN comment nodes. A '#' inside a '${var#pat}' expansion or a quoted
    string is data, not a comment -- the naive '^[^#]*' regex idiom stops at it
    and misses (or misjudges) whatever follows on the line. 1-indexed: element
    i-1 is line i's code. A None tree (unparsed) yields the raw lines."""
    lines = source.split("\n")
    if tree is None:
        return lines
    for comment in bash_ast.comments(tree):
        pos = comment.get("Hash") or {}
        line_no = pos.get("Line")
        col = pos.get("Col")
        if not line_no or not col or not 1 <= line_no <= len(lines):
            continue
        cut = col - 1
        if 0 <= cut < len(lines[line_no - 1]):
            lines[line_no - 1] = lines[line_no - 1][:cut]
    return lines


## Commands that RUN another command given as an operand -- a shell '-c' reached
## through one of these ('ssh host -- bash -lc PROG', 'sudo bash -c PROG') is
## still an inline program. An allowlist, not "any command", so 'echo bash -c
## "..."' (echo is not a wrapper) is never mistaken for one.
SHELL_C_WRAPPERS = frozenset({
    "ssh", "sudo", "su", "doas", "env", "timeout", "nice", "ionice", "chrt",
    "setsid", "stdbuf", "setpriv"})


def _c_in_command(call, source):
    """Command-position shell '-c': classify the args with command_tokens (which
    reconstructs an attached '-c'prog'' value a raw word_lit cannot, since a
    mixed literal+quoted word has no single literal). Handles separate and
    attached forms and a cluster ('-lc')."""
    tokens = list(bash_ast.command_tokens(
        call, source, frozenset("c"), frozenset()))
    for index, (kind, word, text) in enumerate(tokens):
        if kind != "opt" or text.startswith("--") or not text.startswith("-"):
            continue
        cluster = text[1:]
        if "c" not in cluster:
            continue
        if cluster.index("c") == len(cluster) - 1:
            ## Separate form: the next word is the program.
            if index + 1 < len(tokens) and tokens[index + 1][0] == "value":
                program = tokens[index + 1][1]
                span = program["End"]["Line"] - program["Pos"]["Line"] + 1
                yield (call, bash_ast.word_source(program, source), span)
        else:
            ## Attached form ('-c"prog"'): the program is the rest of this word.
            span = word["End"]["Line"] - word["Pos"]["Line"] + 1
            yield (call, text[cluster.index("c") + 2:], span)
        return


def _is_separate_c_opt(text):
    """True if TEXT is a short-option cluster whose LAST character is 'c' (so the
    NEXT word is the program): '-c', '-lc', '-ec'. A long option, an operand, or
    a quoted word (word_lit None) is not."""
    if text is None or not text.startswith("-") or text.startswith("--") \
            or len(text) < 2:
        return False
    cluster = text[1:]
    return "c" in cluster and cluster.index("c") == len(cluster) - 1


def _c_behind_wrapper(call, words, start, source):
    """Shell '-c PROG' where the shell is an operand of a wrapper (WORDS[START]
    is the shell). Separate form only -- an attached '-c'prog'' behind a wrapper
    is rare and a mixed word has no word_lit, so it is a documented follow-up."""
    for index in range(start + 1, len(words)):
        if _is_separate_c_opt(bash_ast.word_lit(words[index])):
            if index + 1 < len(words):
                program = words[index + 1]
                span = program["End"]["Line"] - program["Pos"]["Line"] + 1
                yield (call, bash_ast.word_source(program, source), span)
            return


def shell_c_programs(tree, source):
    """Yield (call, program_text, line_count) for each 'sh -c <program>' /
    'bash -c' / 'dash -c' in TREE -- whether the shell is the command itself or
    an operand of a wrapper ('ssh host -- bash -lc PROG'). Handles the separate
    ('-c "prog"') and attached ('-c"prog"') forms; the command may be a path
    (basename decides). Only an EXPLICIT shell operand is caught behind a
    wrapper; an implicit-shell form ('su -c PROG', 'ssh host PROG') is a
    documented follow-up (the wrapper runs the login shell, no shell token)."""
    for call in bash_ast.call_exprs(tree):
        name = bash_ast.command_name(call)
        if name is None:
            continue
        base = name.rsplit("/", 1)[-1]
        if base in SHELL_C_CMDS:
            yield from _c_in_command(call, source)
        elif base in SHELL_C_WRAPPERS:
            ## First explicit shell operand among the wrapper's arguments.
            words = bash_ast.args(call)
            for i in range(1, len(words)):
                lit = bash_ast.word_lit(words[i])
                if lit is not None and lit.rsplit("/", 1)[-1] in SHELL_C_CMDS:
                    yield from _c_behind_wrapper(call, words, i, source)
                    break


def embeds_multi_statement(value, strict):
    """True if VALUE (a shell command string) embeds multi-statement logic.
    Non-strict (apt/cron): more than one top-level statement or a pipe;
    '&&'/'||'/subshell glue is tolerated. Strict (systemd): also a '&&'/'||'
    chain or a control keyword. Parsed with shfmt, so a ';'/'|' inside a nested
    quote is data. A value shfmt cannot parse is NOT flagged (the safe direction)."""
    try:
        tree = bash_ast.parse(value)
    except bash_ast.BashParseError:
        return False
    if len(tree.get("Stmts") or []) > 1:
        return True
    if any(True for _ in bash_ast.pipe_binary_cmds(tree)):
        return True
    control = ("IfClause", "WhileClause", "UntilClause", "ForClause",
               "CaseClause")
    pipe_ops = bash_ast.pipe_ops()
    for node in bash_ast.iter_nodes(tree):
        kind = node.get("Type")
        if kind in control:
            return True
        if strict and kind == "BinaryCmd" and node.get("Op") not in pipe_ops:
            return True
    return False


def editable_calls(tree):
    """CallExprs a fixer may auto-edit: every command EXCEPT one whose position
    is inside a here-document body. A command there is not at a real command-line
    position -- editing it would corrupt here-document DATA. The detector still
    sees these (it only reports); only the writer declines them."""
    spans = list(bash_ast.heredoc_spans(tree))
    for call in bash_ast.call_exprs(tree):
        offset = call["Pos"]["Offset"]
        if any(start <= offset < end for start, end in spans):
            continue
        yield call
