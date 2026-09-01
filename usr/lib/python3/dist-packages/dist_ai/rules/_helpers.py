## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared shell-analysis helpers for the rule objects: command unwrapping,
context-aware statement walking, the printf -v target analysis, and the
embedded-shell ('-c' / config value) parsing. Each answers a STRUCTURAL question
from the shfmt AST, never a regex guess."""

import re

from dist_ai import bash_ast

## Command wrappers whose real program is a LATER argument: 'sudo apt-get ...',
## 'doas rm ...', 'env VAR=1 rm ...', 'command rm ...', 'builtin cd ...'. A rule
## keying on the program name (R-120 rm, R-034 echo, R-210 apt-get, R-211 dpkg)
## must peel these or an honest alternate spelling ('command rm', 'env VAR=1 rm')
## bypasses it -- the same evasion R-220 already unwraps via _EXIT_CALL_WRAPPERS.
## 'env'/'command' are everyday idioms, not obfuscation, so this is a real gate hole.
EXEC_WRAPPERS = ("sudo", "doas", "env", "command", "builtin")

## Per-wrapper options that take a SEPARATE value ('sudo -u www-data cmd',
## 'env -u VAR cmd'); their value must not be mistaken for the wrapped command.
SUDO_VALUE_SHORT = frozenset("ughprtCTRDU")
SUDO_VALUE_LONG = frozenset({
    "user", "group", "host", "prompt", "role", "type", "close-from",
    "command-timeout", "chroot", "chdir", "other-user"})
## env: '-u NAME'/'--unset', '-C DIR'/'--chdir', '-S STR'/'--split-string', and
## '-a ARG'/'--argv0 ARG' take a required separate value. '-a'/'--argv0' renames
## the command's argv[0] cosmetically ('env -a x rm ...' still RUNS rm) -- unregistered
## it would mis-read ARG as the command and bypass R-120/R-034/R-210/R-211.
## 'command'/'builtin' have no value-taking options
## ('command -p/-v/-V' are bare flags; 'builtin' takes none).
## '-S'/'--split-string' also EMBEDS the command inside its STRING value ('env -S
## "rm -rf x"' execs rm). We SKIP that value (never mis-read it as the command) but
## deliberately do NOT parse inside it: that spelling is an obfuscation no accident
## produces (the -S idiom is for shebangs, resolved by interpreter rules, not here),
## so it is out of the accident threat model. Skipping the value is what keeps it
## from FALSE-POSITIVING on a path-like string ('env -S "echo /bin/rm"').
ENV_VALUE_SHORT = frozenset("uCSa")
ENV_VALUE_LONG = frozenset({"unset", "chdir", "split-string", "argv0"})
_WRAPPER_VALUE_SPEC = {
    "sudo": (SUDO_VALUE_SHORT, SUDO_VALUE_LONG),
    "doas": (SUDO_VALUE_SHORT, SUDO_VALUE_LONG),
    "env": (ENV_VALUE_SHORT, ENV_VALUE_LONG),
    "command": (frozenset(), frozenset()),
    "builtin": (frozenset(), frozenset()),
}

## 'builtin NAME' runs NAME only when NAME is a shell builtin: 'builtin cd',
## 'builtin echo', 'builtin command rm' all run, but 'builtin rm' / 'builtin
## apt-get' error ('not a shell builtin') and execute NOTHING. So a name-keyed
## rule (R-120 rm, R-210 apt-get, R-211 dpkg) must NOT fire behind 'builtin' for
## a non-builtin word, and effective_command declines it. 'builtin command rm'
## still reaches rm because 'command' IS a builtin (and an exec wrapper). Source:
## 'compgen -b'.
BASH_BUILTINS = frozenset({
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd",
    "command", "compgen", "complete", "compopt", "continue", "declare", "dirs",
    "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc",
    "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local",
    "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read", "readarray",
    "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test",
    "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias",
    "unset", "wait"})


def _basename(name):
    """The command BASENAME -- '/bin/rm' and 'rm' are the same program, so a rule
    keying on the name must not be evaded by a path (as shell_c_programs and
    InterpreterPrepend already resolve). None passes through."""
    return name.rsplit("/", 1)[-1] if name is not None else None


def effective_command(call, source):
    """The BASENAME of the program CALL actually runs, unwrapping leading exec
    wrappers ('sudo'/'doas'/'env'/'command'/'builtin') -- skipping each wrapper's
    options, their values, and 'VAR=value' prefixes. None when the wrapped command
    word is quoted/expanded or cannot be resolved, or when 'command -v'/'-V' NAME
    is a describe (not a run) -- the safe direction (a rule declines rather than
    guesses). Path-qualified names ('/bin/rm', '/usr/bin/sudo rm') resolve by
    basename so a rule is not bypassed."""
    wrapper_raw = bash_ast.command_name(call)
    wrapper = _basename(wrapper_raw)
    if wrapper not in EXEC_WRAPPERS:
        return wrapper
    ## Peel wrapper layers ITERATIVELY, not recursively: a maliciously deep chain
    ## ('sudo' x1500 rm) would else exceed Python's recursion limit and crash the linter
    ## on untrusted input. Each layer strictly shortens Args, so this always terminates.
    while True:
        words = bash_ast.args(call)
        value_short, value_long = _WRAPPER_VALUE_SPEC[wrapper]
        inner = None
        rest = 0
        for position, (kind, word, text) in enumerate(
                bash_ast.command_tokens(
                    call, source, value_short, value_long), start=1):
            if kind == "opt":
                ## 'command -v'/'-V' NAME is describe mode: it prints NAME's path, it
                ## does not RUN NAME, so the wrapped rule (R-120 etc.) must not fire.
                ## Decline (the safe direction) rather than surface NAME as a run. A
                ## short cluster ('-pv') describes if it carries v/V anywhere; '--' and
                ## long options are never command's describe flags.
                if wrapper == "command" and not text.startswith("--") \
                        and ("v" in text[1:] or "V" in text[1:]):
                    return None
                continue
            if kind != "operand":
                continue
            ## The first word past the wrapper's options is the real command; a leading
            ## 'VAR=value' env-assignment ('env VAR=1 rm', 'sudo FOO=bar rm') is still not
            ## the command. Test the SOURCE, since a quoted value ('FOO="bar"') makes
            ## word_lit None -- otherwise the unwrap aborts and the prefix bypasses R-120.
            if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=',
                        bash_ast.word_source(word, source)):
                continue
            inner_raw = bash_ast.word_string(word)
            inner = _basename(inner_raw)
            rest = position
            break
        if inner is None:
            return None
        ## 'builtin NAME' executes NAME only if NAME is a shell builtin; 'builtin
        ## rm' errors and runs nothing, so decline (no name-keyed rule fires).
        ## 'builtin command rm' passes here (command IS a builtin) and reaches rm
        ## through the wrapper peel below. ONLY the bare 'builtin' keyword invokes
        ## the shell builtin: a path-qualified './builtin' is an ordinary external
        ## program (unknown behavior), so the exemption must NOT suppress a rule for
        ## it -- fall through so the peel still flags an inner rm (the safe direction).
        if wrapper == "builtin" and "/" not in (wrapper_raw or "") \
                and inner not in BASH_BUILTINS:
            return None
        ## Not a wrapper -> the real command. A STACKED wrapper ('sudo sudo rm',
        ## 'sudo env VAR=1 rm', 'sudo doas -u root rm') runs it one layer deeper; RE-PARSE
        ## from the inner wrapper with its OWN option spec (command_tokens flattens
        ## everything past the first operand into 'operand', so the inner wrapper's
        ## flags/values are NOT skipped by this pass -- returning the next raw operand
        ## would surface a flag like '-u' and still bypass R-120/R-034/R-210/R-211).
        if inner not in EXEC_WRAPPERS:
            return inner
        wrapper = inner
        wrapper_raw = inner_raw
        call = {"Args": words[rest:]}


## Statement CONTEXT: a command in a loop/if CONDITION is not the same as one in
## a body. R-130 (bare ':') must fire on a filler ':' statement but NOT on the
## ':' condition of 'while :; do'. shfmt's JSON has no parent pointers, so we
## walk the known body vs condition stmt-lists explicitly.
CONTEXT_STMT = "stmt"
CONTEXT_COND = "cond"


def statements(tree):
    """Yield (stmt, context) for every Stmt in TREE, context-aware (a loop/if
    CONDITION vs a body). stmt['Cmd'] is the command node; stmt['Redirs'] its
    redirections. ITERATIVE (explicit work stack), not recursive: a deeply nested
    command tree -- a ~500-deep '&&'/pipe chain, or nested if/elif -- would else
    exceed Python's recursion limit and crash the linter on untrusted input.
    Children are pushed REVERSED so LIFO pops emit them in document order."""
    out = []
    ## Work items: ('stmts', list, ctx) | ('stmt', dict, ctx) | ('cmd', dict, ctx) |
    ## ('if', IfClause dict, ''). shfmt's JSON has no parent pointers, so the
    ## body-vs-condition context is threaded through each item.
    stack = [("stmts", tree.get("Stmts"), CONTEXT_STMT)]
    while stack:
        kind, node, context = stack.pop()
        if kind == "stmts":
            for stmt in reversed(node or []):
                stack.append(("stmt", stmt, context))
        elif kind == "stmt":
            if isinstance(node, dict):
                out.append((node, context))
                stack.append(("cmd", node.get("Cmd"), context))
        elif kind == "if":
            ## 'elif' is a nested IfClause in the Else slot; 'else' is a plain block.
            ## Cond is condition context, Then/Else are body. Pushed in reverse of
            ## emit order (Cond, Then, Else).
            else_node = node.get("Else")
            if isinstance(else_node, dict):
                if else_node.get("Cond"):
                    stack.append(("if", else_node, ""))
                else:
                    stack.append(("stmts",
                                  else_node.get("Then") or else_node.get("Stmts"),
                                  CONTEXT_STMT))
            stack.append(("stmts", node.get("Then"), CONTEXT_STMT))
            stack.append(("stmts", node.get("Cond"), CONTEXT_COND))
        elif kind == "cmd" and isinstance(node, dict):
            ctype = node.get("Type")
            if ctype in ("Block", "Subshell"):
                ## A group/subshell INHERITS its enclosing context -- a block that
                ## IS a loop/if condition keeps its statements in condition context.
                stack.append(("stmts", node.get("Stmts"), context))
            elif ctype == "IfClause":
                stack.append(("if", node, ""))
            elif ctype == "WhileClause":
                stack.append(("stmts", node.get("Do"), CONTEXT_STMT))
                stack.append(("stmts", node.get("Cond"), CONTEXT_COND))
            elif ctype == "ForClause":
                stack.append(("stmts", node.get("Do"), CONTEXT_STMT))
            elif ctype == "CaseClause":
                for item in reversed(node.get("Items") or []):
                    stack.append(("stmts", item.get("Stmts"), CONTEXT_STMT))
            elif ctype == "BinaryCmd":
                ## A pipeline / '&&' / '||': both sides KEEP the enclosing context,
                ## so a ':' that is only the left of a CONDITION pipeline stays 'cond'.
                stack.append(("stmt", node.get("Y"), context))
                stack.append(("stmt", node.get("X"), context))
            elif ctype == "FuncDecl":
                stack.append(("stmt", node.get("Body"), CONTEXT_STMT))
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


def _printf_scan(call_args):
    """(format_operand_index_or_None, last_-v_target_word_or_None) from bash's own
    printf option parsing over the QUOTE-REMOVED args. Options precede the format
    operand (the first non-option word); '--' ends option scanning; '-v' is
    recognized in both the separate ('-v name') and attached ('-vNAME') form and
    whatever the quoting; a repeated '-v' keeps the LAST target. Shared by
    printf_v_target (R-063) and printf_format_word (R-030/R-031) so all three rules
    agree on the SAME option boundary -- a hand-rolled per-rule scan that only
    matched a bare literal '-v' silently missed '-vNAME'/'\\-v'/'"-v"' spellings."""
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
            index += 1
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
    return (index if index < len(call_args) else None), target


def printf_v_target(call):
    """The Word carrying the EFFECTIVE 'printf -v' target NAME, or None when the
    printf writes no variable. See _printf_scan for the option grammar."""
    return _printf_scan(bash_ast.args(call))[1]


def printf_format_word(call):
    """The Word carrying printf's FORMAT operand (the first non-option word after
    '-v'/'--'/options), or None. Same robust scan as printf_v_target, so R-030/R-031
    judge the SAME word the shell treats as the format."""
    call_args = bash_ast.args(call)
    index, _target = _printf_scan(call_args)
    return None if index is None else call_args[index]


def word_has_command_expansion(word):
    """True if WORD contains a command substitution ($(...) or backticks) or an
    arithmetic expansion. A printf -v target carrying one can NEVER be made safe
    by check_variable_name -- bash evaluates the array subscript, running the
    substitution -- so it must be flagged whatever parameters were checked."""
    for node in bash_ast.iter_nodes(word):
        if node.get("Type") in ("CmdSubst", "ArithmExp", "ArithmCmd"):
            return True
    return False


_ENFORCING_EXIT = frozenset({"return", "exit", "continue", "break", "die"})


def _exit_kind(stmt):
    """The control-flow exit keyword STMT performs (return/exit/continue/break/die),
    or None if it does not exit. A '{ ...; }' handler exits only if its LAST statement
    does ('|| { log; return 1; }' enforces; '|| { true; }' falls through to the printf).
    ITERATIVE (descend the Block last-statement chain in a loop), not recursive: a deeply
    nested '{ { { ...; return 1; } } }' would else exceed Python's recursion limit and
    crash the linter on untrusted input."""
    cmd = (stmt or {}).get("Cmd") or {}
    while cmd.get("Type") == "Block":
        stmts = cmd.get("Stmts") or []
        if not stmts:
            return None
        cmd = (stmts[-1] or {}).get("Cmd") or {}
    name = bash_ast.command_name(cmd)
    return name if name in _ENFORCING_EXIT else None


def _offset_in_any(offset, spans):
    return any(start <= offset < end for start, end in spans)


def _func_body_spans(tree):
    """(start, end) span of every function body -- where a 'return' actually returns."""
    spans = []
    for decl in bash_ast.func_decls(tree):
        body = decl.get("Body") or {}
        start = (body.get("Pos") or {}).get("Offset")
        end = (body.get("End") or {}).get("Offset")
        if start is not None and end is not None:
            spans.append((start, end))
    return spans


def _loop_body_spans(tree):
    """(start, end) span of every LOOP CONSTRUCT ('for/while/until ... done') -- where
    'continue'/'break' are lexically valid. The whole node span (not just the Do list) is
    used so a subshell nested in the body is STRICTLY inside it: when a loop's body is a
    single subshell the Do-list span equals the subshell span and cannot be told apart,
    but the loop node also spans the header and 'done', so the subshell is innermost and a
    'continue' trapped in it is correctly rejected (see _innermost_reaches)."""
    spans = []
    for node in bash_ast.iter_nodes(tree):
        if isinstance(node, dict) \
                and node.get("Type") in ("WhileClause", "UntilClause", "ForClause"):
            span = _node_span(node)
            if span is not None:
                spans.append(span)
    return spans


def _node_span(node):
    start = (node.get("Pos") or {}).get("Offset")
    end = (node.get("End") or {}).get("Offset")
    return (start, end) if start is not None and end is not None else None


def _subshell_subst_spans(tree):
    """(start, end) span of every SUBSHELL / command- or process-substitution -- an
    execution boundary a 'return'/'exit'/'continue'/'break' cannot cross to reach code
    OUTSIDE it (a subshell/subst runs in a child), nor can a caller's guard reach INTO."""
    spans = []
    for node in bash_ast.iter_nodes(tree):
        if isinstance(node, dict) \
                and node.get("Type") in ("Subshell", "CmdSubst", "ProcSubst"):
            span = _node_span(node)
            if span is not None:
                spans.append(span)
    return spans


def boundary_spans(tree):
    """Execution-region boundaries: FUNCTION bodies (run later, not at the guard's load
    time) plus subshells/substitutions (run in a child). Byte-span containment only equals
    execution REACHABILITY within a single such region -- crossing one breaks the guard."""
    return _func_body_spans(tree) + _subshell_subst_spans(tree)


def no_boundary_between(a, b, spans):
    """True if NO boundary span separates offsets A and B -- none contains exactly one of
    them. A guard reaches a printf only when they share every enclosing execution region;
    a top-level guard cannot reach a printf inside a later function, nor across a subshell."""
    for start, end in spans:
        if (start <= a < end) != (start <= b < end):
            return False
    return True


def _innermost_reaches(offset, scope_spans, barrier_spans):
    """True if the innermost span enclosing OFFSET among SCOPE_SPANS+BARRIER_SPANS is a
    SCOPE span. For continue/break the scope is a loop body and the barrier a subshell/subst:
    a 'continue' inside a subshell-in-a-loop is trapped in the subshell (barrier innermost)
    and never reaches the loop, so it is not a valid guard."""
    best = None
    best_is_scope = False
    for span in scope_spans:
        start, end = span
        if start <= offset < end and (best is None or (end - start) < (best[1] - best[0])):
            best, best_is_scope = span, True
    for span in barrier_spans:
        start, end = span
        if start <= offset < end and (best is None or (end - start) < (best[1] - best[0])):
            best, best_is_scope = span, False
    return best is not None and best_is_scope


def _stmt_list_span(stmts):
    starts = [(s.get("Pos") or {}).get("Offset") for s in (stmts or [])]
    ends = [(s.get("End") or {}).get("Offset") for s in (stmts or [])]
    starts = [o for o in starts if o is not None]
    ends = [o for o in ends if o is not None]
    if not starts or not ends:
        return None
    return (min(starts), max(ends))


def _statement_list_spans(tree):
    """The (start, end) byte span of every STATEMENT-LIST -- the top level, each
    subshell/brace-group body, and each if/loop/case BRANCH. Branch granularity
    matters: a guard in an if's THEN must not count for a printf in its ELSE."""
    spans = []

    def add(stmts):
        span = _stmt_list_span(stmts)
        if span is not None:
            spans.append(span)

    add(tree.get("Stmts"))
    for node in bash_ast.iter_nodes(tree):
        if not isinstance(node, dict):
            continue
        kind = node.get("Type")
        ## A command/process substitution has its OWN statement list too -- a guard's
        ## 'return' inside '$(...)' / '<(...)' exits only the substitution, so its span
        ## must not reach a printf outside it (same class as R-194's CmdSubst fix).
        if kind in ("Block", "Subshell", "CmdSubst", "ProcSubst"):
            add(node.get("Stmts"))
        elif kind == "IfClause":
            add(node.get("Cond"))
            add(node.get("Then"))
            ## Walk the WHOLE elif/else chain: shfmt nests each 'elif' as an Else dict
            ## with NO Type (iter_nodes never dispatches on it), so a guard in a later
            ## elif condition/body or the final 'else' would else inherit the outer span.
            els = node.get("Else")
            while isinstance(els, dict):
                add(els.get("Cond"))
                add(els.get("Then"))
                add(els.get("Stmts"))
                els = els.get("Else")
        elif kind in ("WhileClause", "UntilClause"):
            add(node.get("Cond"))
            add(node.get("Do"))
        elif kind == "ForClause":
            add(node.get("Do"))
        elif kind == "CaseClause":
            for item in node.get("Items") or []:
                add(item.get("Stmts"))
    return spans


def enclosing_container_span(tree, offset):
    """(start, end) of the innermost STATEMENT-LIST enclosing OFFSET. A guard
    enforces a printf only when the printf falls in this span (the same branch, or
    an enclosing one), so a guard in a sibling branch, a subshell, or a command
    substitution cannot reach a printf outside it."""
    best = None
    for span in _statement_list_spans(tree):
        start, end = span
        if start <= offset < end and (best is None or (end - start) < (best[1] - best[0])):
            best = span
    return best if best is not None else (offset, offset + 1)


def check_variable_name_sites(tree):
    """(guard_offset, container_span, param_names) for every 'check_variable_name'
    in a RECOGNIZED ENFORCING form -- 'check_variable_name ARGS || <exit-like>'
    (return/exit/continue/break/die or a '{ ...; }' handler). A decoy guard whose
    result does NOT gate control flow no longer silences R-063: a bare call (status
    discarded) is not an '||' form; one inside a command substitution or subshell,
    or in a dead/sibling branch, has a container_span that does not reach the printf.
    Fail-CLOSED -- an unrecognized guard shape leaves R-063 firing."""
    sites = []
    or_ops = bash_ast.or_op()
    func_spans = _func_body_spans(tree)
    loop_spans = _loop_body_spans(tree)
    barrier_spans = _subshell_subst_spans(tree)
    for node in bash_ast.nodes_of_type(tree, "BinaryCmd"):
        if node.get("Op") not in or_ops:
            continue
        xstmt = node.get("X") or {}
        ## A NEGATED check ('! check_variable_name ... || return') is NOT a guard: '!'
        ## inverts, so on a BAD name the check's failure becomes success, the '|| return'
        ## never runs, and the printf executes unguarded.
        if xstmt.get("Negated"):
            continue
        left = xstmt.get("Cmd") or {}
        if bash_ast.command_name(left) != "check_variable_name":
            continue
        exit_kind = _exit_kind(node.get("Y"))
        if exit_kind is None:
            continue
        offset = (left.get("Pos") or {}).get("Offset")
        if offset is None:
            continue
        ## The exit must actually leave the printf's path: 'return' needs an enclosing
        ## function, 'continue'/'break' a loop REACHABLE without a subshell/subst barrier
        ## (a 'continue' trapped in a subshell-in-a-loop never reaches the loop); 'exit'/
        ## 'die' work anywhere. A top-level 'check || return' just errors and falls through.
        if exit_kind == "return" and not _offset_in_any(offset, func_spans):
            continue
        if exit_kind in ("continue", "break") \
                and not _innermost_reaches(offset, loop_spans, barrier_spans):
            continue
        params = set()
        for word in bash_ast.args(left)[1:]:
            params |= bash_ast.word_param_names(word)
        sites.append((offset, enclosing_container_span(tree, offset), params))
    return sites


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
        if _is_separate_c_opt(bash_ast.word_string(words[index])):
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
                lit = bash_ast.word_string(words[i])
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
        ## A subshell/brace-group/command-or-process-substitution holding >1 statement
        ## is multi-statement embedded logic just like top-level ';'-separated commands
        ## -- it must not hide the payload: '(cd /s; ./p.sh; ...)' AND '$(cd /s; ./p.sh;
        ## ...)' / backtick / '<(...)' (all share the Stmts shape) belong in a script.
        ## Both modes flag it (a single-statement '(a && b)' stays &&-glue, tolerated in
        ## non-strict and caught by the strict BinaryCmd check below).
        if kind in ("Subshell", "Block", "CmdSubst", "ProcSubst") \
                and len(node.get("Stmts") or []) > 1:
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
