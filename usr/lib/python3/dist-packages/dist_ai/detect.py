## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Parser-backed style DETECTOR -- the read-side twin of pre-push-fix.

The shell-STRUCTURE rules of pre-push-static (command position, quote/heredoc
state, embedded-shell in config values) are the ones a regex could only
APPROXIMATE, each carrying a documented fail-open ("a command after a closed
quote is missed", "a command inside a string is a rare residual"). This module
answers those questions from the real shfmt AST (dist_ai.bash_ast) instead, so a
command is told from data that only looks like one -- exactly, not heuristically.

Scope is deliberately the parser-benefiting rules. The pure-text greps that strip
comments first (R-070 ';;', R-074 flow-chaining, R-062 '--' denylist, R-026
empty-array guard, R-213 lintian, R-001 ASCII, the strict-mode block, ...) are
honest simple matches with no command/quote ambiguity, so they stay in the gate
as greps -- moving them here would add code without removing a blind spot.

Each rule is a function yielding Finding(severity, rule, message, path, line).
The gate consumes the findings and renders them through its own fail()/note(), so
the on-screen output and every existing per-rule gate test are unchanged.
"""

import collections
import fnmatch
import os
import re

from dist_ai import bash_ast

SHELL_EXTS = (".sh", ".bsh")
SHELL_SHEBANG_RE = re.compile(r'#!.*(/|\s)(bash|sh|dash)(\s|$)')


def is_shell_file(path, source):
    """True for a shell script -- a .sh/.bsh extension or a bash/sh/dash shebang.
    Mirrors pre-push-static's is_shell_file so detector and gate agree on the
    shell set."""
    if path.endswith(SHELL_EXTS):
        return True
    first = source.split("\n", 1)[0]
    return bool(SHELL_SHEBANG_RE.match(first))


Finding = collections.namedtuple(
    "Finding", ["severity", "rule", "message", "path", "line"])

FAIL = "FAIL"
NOTE = "NOTE"

## Command wrappers whose real program is a later argument: 'sudo apt-get ...',
## 'doas rm ...'. The legacy _pkg_cmd_re named exactly sudo/doas, so unwrapping
## them keeps a wrapped invocation flagged (matching the former gate).
EXEC_WRAPPERS = ("sudo", "doas")


def waiver(source, tag):
    """True if SOURCE carries a file-wide '## style-ok: <tag>' waiver (any or no
    horizontal whitespace around the tokens), matching the gate's grammar."""
    pattern = re.compile(
        r'^[ \t]*##[ \t]*style-ok:[ \t]*' + re.escape(tag) + r'(?:[ \t]|$)',
        re.MULTILINE)
    return bool(pattern.search(source))


def config_waiver(source, tag, slashes=False):
    """True if SOURCE carries a '# style-ok: <tag>' waiver in CONFIG comment
    syntax -- one or two '#' (systemd/cron/YAML), or '//' when SLASHES (apt). The
    shell waiver() requires '##'; config files comment with a single '#'."""
    prefix = r'(?:#{1,2}|//)' if slashes else r'#{1,2}'
    pattern = re.compile(
        r'^[ \t]*' + prefix + r'[ \t]*style-ok:[ \t]*'
        + re.escape(tag) + r'(?:[ \t]|$)', re.MULTILINE)
    return bool(pattern.search(source))


def shebang(source):
    """The script's first line if it is a shebang, else ''."""
    first = source.split("\n", 1)[0]
    return first if first.startswith("#!") else ""


def is_posix_sh(source):
    """True for a '#!/bin/sh' / env-sh script (R-090 exempts these: 'command -v'
    is the portable idiom there and its bash-only remedies do not apply)."""
    line = shebang(source)
    return bool(re.match(r'#!\s*(\S*/)?(env\s+)?sh(\s|$)', line))


## sudo/doas options that take a SEPARATE value ('sudo -u www-data cmd'); their
## value must not be mistaken for the wrapped command.
SUDO_VALUE_SHORT = frozenset("ughprtCTRDU")
SUDO_VALUE_LONG = frozenset({
    "user", "group", "host", "prompt", "role", "type", "close-from",
    "command-timeout", "chroot", "chdir", "other-user"})


def effective_command(call, source):
    """The literal name of the program CALL actually runs, unwrapping a leading
    'sudo'/'doas' (skipping its options, their values, and 'VAR=value' prefixes).
    None when the wrapped command word is quoted/expanded or cannot be resolved --
    the safe direction (a rule declines rather than guesses)."""
    name = bash_ast.command_name(call)
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
            return bash_ast.word_lit(word)
    return None


## Statement CONTEXT: a command in a loop/if CONDITION is not the same as one in a
## body. R-130 (bare ':') must fire on a filler ':' statement but NOT on the ':'
## condition of 'while :; do'. shfmt's JSON has no parent pointers, so we walk the
## known body vs condition stmt-lists explicitly.
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


def _line_of(node):
    return node["Pos"]["Line"]


def _fail(rule, message, path, node):
    return Finding(FAIL, rule, message, path, _line_of(node))


def _line_is_bare(source, node):
    """True if NODE's physical line is just ':' (optional surrounding
    whitespace) -- the legacy 'bare colon alone on a line' form for R-130."""
    lines = source.split("\n")
    index = node["Pos"]["Line"] - 1
    return 0 <= index < len(lines) and lines[index].strip() == ":"


## --- command-position rules -----------------------------------------------


def r090_command_v(path, source, tree):
    """R-090: 'command -v' (prefer helper-scripts 'has' / 'type -P')."""
    if is_posix_sh(source) or waiver(source, "no-has"):
        return
    if path in ("usr/bin/pre-push-static",
                ".github/actions/install-deps/install-helper-scripts.sh"):
        return
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "command":
            continue
        first = bash_ast.args(call)[1:2]
        ## word_string (quote-aware), not word_lit: a detector matching a
        ## forbidden LITERAL token must catch its quoted spellings too --
        ## 'command "-v" foo' IS 'command -v foo'. word_lit declines any quoted
        ## word (that is for the rewriters, which need a plain-literal target).
        if first and bash_ast.word_string(first[0]) == "-v":
            yield _fail("R-090", "R-090 command -v", path, call)


def r103_exec(path, source, tree):
    """R-103: process-replacement 'exec <command>'. An fd-redirection exec
    ('exec 9>lock', 'exec >file') has no command argument, so it is not matched."""
    if waiver(source, "allow-exec"):
        return
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "exec":
            continue
        call_args = bash_ast.args(call)
        if len(call_args) < 2:
            ## An fd-redirection exec ('exec 9>lock', 'exec >file') has no command
            ## argument -- the redirect is on the statement, not an Arg.
            continue
        first = bash_ast.word_lit(call_args[1])
        if first is not None and first.startswith("["):
            ## Usage/help TEXT describing an 'exec' SUBCOMMAND and its options
            ## ('exec [--workdir DIR] -- CMD'). No real script execs the '['
            ## builtin, so a '[' right after exec is documentation, not process
            ## replacement (mirrors the legacy gate's carve-out).
            continue
        yield _fail("R-103", "R-103 process-replacement exec", path, call)


def r120_rm(path, source, tree):
    """R-120: 'rm' (use safe-rm). 'git rm' / 'shred' have a different command
    word, so they never match; 'sudo rm' is unwrapped and caught."""
    if path == "usr/bin/pre-push-static" or waiver(source, "no-safe-rm"):
        return
    for call in bash_ast.call_exprs(tree):
        if effective_command(call, source) == "rm":
            yield _fail("R-120", "R-120 rm not safe-rm", path, call)


def r034_echo(path, source, tree):
    """R-034: 'echo' as a command (use printf)."""
    if waiver(source, "allow-echo"):
        return
    for call in bash_ast.call_exprs(tree):
        if effective_command(call, source) == "echo":
            yield _fail("R-034", "R-034 echo not printf", path, call)


## --- printf -v injection guard ---------------------------------------------


def _word_literal_prefix(word):
    """The leading LITERAL text of WORD, with quote SYNTAX removed, up to the
    first expansion. 'printf' -> 'printf', '"-v"' -> '-v', '"-v${x}"' -> '-v',
    '-v${x}' -> '-v', '"${x}"' -> ''. Option detection must see what bash's own
    getopt sees AFTER quote removal, so '"-v"' is the '-v' option, not data --
    quotes are syntax, and word_source (raw) / word_lit (unquoted-single-Lit)
    both miss that."""
    out = []
    for part in word.get("Parts") or []:
        kind = part.get("Type")
        if kind == "Lit":
            out.append(part.get("Value") or "")
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


def _printf_v_target(call):
    """The Word carrying the EFFECTIVE 'printf -v' target NAME, or None when the
    printf writes no variable. Follows bash's own printf option parsing, over the
    QUOTE-REMOVED argument (all verified against bash):

      - Options precede the FORMAT operand; the first non-option word is the format
        and ENDS option scanning, so a later '-v' ('printf "%s" -v "$x"') is a data
        argument, not the option -- not a target.
      - '--' also ends option scanning ('printf -- -v x' prints '-v').
      - The '-v' option is recognized whatever the quoting ('-v', '"-v"'), in both
        the SEPARATE form (name is the next word) and the ATTACHED form
        ('-vNAME'/'"-vNAME"'/'-v${x}' -- name embedded in this word); quote removal
        makes '"-v"' the option, which a raw-text check would miss.
      - Multiple '-v' -> bash uses the LAST, so the last target before the format
        is the effective one ('printf -v safe -v "$x"' writes "$x")."""
    call_args = bash_ast.args(call)
    target = None
    index = 1
    while index < len(call_args):
        word = call_args[index]
        full = bash_ast.word_string(word)
        if full == "--":
            break
        prefix = _word_literal_prefix(word)
        if prefix.startswith("-v"):
            if full == "-v":
                ## Exactly '-v': separate form, name is the NEXT word.
                if index + 1 < len(call_args):
                    target = call_args[index + 1]
                    index += 2
                    continue
                index += 1
                continue
            ## '-v' with more text in the SAME word: attached form, name embedded.
            target = word
            index += 1
            continue
        ## First non-option word: the format operand. Option scanning ends.
        break
    return target


def _check_variable_name_sites(tree):
    """(offset, scope_start, param_names) for every 'check_variable_name' call: its
    byte offset, the start of the innermost function enclosing it, and the set of
    parameter names its arguments expand. A guard is matched to a printf target by
    the SAME innermost scope, textual precedence, and covering the target's
    parameters."""
    sites = []
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "check_variable_name":
            continue
        params = set()
        for word in bash_ast.args(call)[1:]:
            params |= bash_ast.word_param_names(word)
        offset = call["Pos"]["Offset"]
        sites.append((offset, _enclosing_scope_start(tree, offset), params))
    return sites


def _enclosing_scope_start(tree, offset):
    """Byte offset where the scope containing OFFSET begins: the body of the
    innermost function enclosing it, or 0 at top level. A guard counts only when
    it sits between here and the printf -- so a check in a sibling function, or
    after the printf, does not."""
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


def r063_printf_v_unchecked(path, source, tree):
    """R-063: a 'printf -v <name>' whose target NAME is dynamic (built from an
    expansion, not a fixed literal) must be guarded by 'check_variable_name' on
    that same name earlier in the enclosing function. Bash evaluates an array
    subscript inside the -v target, so an unchecked name of the form 'x[$(cmd)]'
    RUNS cmd -- a command injection driven by whatever supplied the name. A
    literal target ('printf -v out ...') carries no expansion and is spared; a
    pure command-substitution name ('printf -v "$(f)"') shares no parameter with
    any guard, so it can never be counted as guarded.

    A guard counts only when it is in the SAME innermost function as the printf,
    textually BEFORE it, and its checked parameters COVER every parameter of the
    target name -- a name built from several expansions ('"${a}${b}"') is safe
    only if each of a and b was checked, since bash evaluates the whole subscript.

    SCOPE (honest limit -- this catches the accidental unguarded printf -v, not an
    adversary deliberately hiding the guard): control-flow REACHABILITY is not
    modelled, so a check parked in an unreachable branch ('if false; then check ...
    fi') in the same function still counts. Modelling dominance needs a CFG, and a
    block-level scope would FALSE-POSITIVE the real idiom (guard at function top,
    printf -v in a case/if arm, as in github-policy-lib.bsh). Also: only a direct
    'printf' is analyzed, not a 'command'/'builtin printf' dispatch (absent from
    the codebase, never an accidental spelling)."""
    if waiver(source, "allow-unchecked-printf-v"):
        return
    guards = _check_variable_name_sites(tree)
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "printf":
            continue
        name_word = _printf_v_target(call)
        if name_word is None:
            continue
        if bash_ast.word_string(name_word) is not None:
            ## Statically-known name: no expansion, so no injectable subscript.
            continue
        target_params = bash_ast.word_param_names(name_word)
        offset = call["Pos"]["Offset"]
        scope_start = _enclosing_scope_start(tree, offset)
        ## Union of parameters checked by same-scope guards textually before the
        ## printf. The target is guarded only if EVERY one of its parameters is
        ## covered (an uncovered component can still smuggle an injectable
        ## subscript). An empty target_params (a command-substitution name) is
        ## never a subset of anything non-trivially -- it is left unguarded below.
        covered = set()
        for guard_offset, guard_scope, guard_params in guards:
            if guard_scope == scope_start and guard_offset < offset:
                covered |= guard_params
        if target_params and target_params <= covered:
            continue
        yield _fail(
            "R-063",
            "R-063 printf -v dynamic name unguarded by check_variable_name "
            "(an unchecked name runs the command in name[$(...)])",
            path, call)


def r130_null_command(path, source, tree):
    """R-130: ':' used as a command -- a bare filler ':' statement, or the
    ': > file' truncation idiom. Spares ': "${var:=default}"' (a word follows)
    and the 'while :; do' loop condition (condition context)."""
    for stmt, context in statements(tree):
        cmd = stmt.get("Cmd")
        if not isinstance(cmd, dict) or cmd.get("Type") != "CallExpr":
            continue
        if bash_ast.command_name(cmd) != ":":
            continue
        has_redirect = bool(stmt.get("Redirs"))
        only_colon = len(bash_ast.args(cmd)) == 1
        if not only_colon:
            continue
        if has_redirect:
            ## The ': > file' truncation idiom (opaque under xtrace).
            yield _fail("R-130", "R-130 ':' used as a command", path, cmd)
        elif context == CONTEXT_STMT and _line_is_bare(source, cmd):
            ## A bare ':' ALONE on its line -- a filler no-op statement. NOT a
            ## ':' stub sharing a line ('f() { :; }', 'case x) : ;;'), which is
            ## the standard empty-body idiom, nor a loop/if condition.
            yield _fail("R-130", "R-130 ':' used as a command", path, cmd)


def r212_allow_downgrades(path, source, tree):
    """R-212: '--allow-downgrades' is forbidden. Detected as a real argument
    word, so a mention inside a string ('never use --allow-downgrades') is not
    flagged."""
    if path == "usr/bin/pre-push-static" or waiver(source, "allow-downgrades"):
        return
    for call in bash_ast.call_exprs(tree):
        for word in bash_ast.args(call):
            ## word_string, not word_lit: catch the quoted spellings too
            ## ('"--allow-downgrades"' / "'--allow-downgrades'" still pass the
            ## flag to apt-get); still spares a prose mention (a multi-word
            ## string never equals the exact flag).
            if bash_ast.word_string(word) == "--allow-downgrades":
                yield _fail("R-212", "R-212 --allow-downgrades forbidden",
                            path, word)


def r213_lintian_disabled(path, source, tree):
    """R-213: 'make_use_lintian=false' disables the lintian gate on a genmkfile
    build; forbidden without authorization -- fix the lintian findings instead.
    Detected as a real ASSIGNMENT of 'make_use_lintian' to a literal 'false'
    (env prefix or standalone, quoted value or not), so a quoted mention
    ('"make_use_lintian=false" is forbidden') and a longer name ending in it
    ('disable_make_use_lintian=false') are NOT flagged, while an assignment
    after a separator ('true; make_use_lintian=false genmkfile ...') IS.
    Waiver: '## style-ok: allow-lintian-disable'."""
    if path == "usr/bin/pre-push-static" \
            or waiver(source, "allow-lintian-disable"):
        return
    for call in bash_ast.call_exprs(tree):
        for assign in bash_ast.assigns(call):
            if bash_ast.assign_name(assign) == "make_use_lintian" \
                    and bash_ast.word_string(
                        bash_ast.assign_value(assign)) == "false":
                yield _fail("R-213",
                            "R-213 lintian disabled (make_use_lintian=false) "
                            "without authorization", path, assign)


## R-211 state-changing dpkg actions (a read-only query is spared).
DPKG_STATE_ACTIONS = {
    "--install", "--unpack", "--configure", "--remove", "--purge",
    "--record-avail", "--set-selections", "--clear-selections",
    "--update-avail", "--merge-avail", "--forget-old-unavail",
    "--triggers-only", "-i", "-r", "-P", "-A",
}


def r210_apt_get(path, source, tree):
    """R-210 (ADVISORY): 'apt-get' in command position -- prefer
    'apt-get-noninteractive'."""
    if path == "usr/bin/pre-push-static" \
            or os.path.basename(path) in ("apt-get-noninteractive",
                                          "dpkg-noninteractive") \
            or waiver(source, "allow-apt-get"):
        return
    for call in bash_ast.call_exprs(tree):
        if effective_command(call, source) == "apt-get":
            yield Finding(
                NOTE, "R-210",
                "R-210 (ADVISORY): 'apt-get' in command position -- prefer "
                "'apt-get-noninteractive' ('## style-ok: allow-apt-get' to "
                "silence): '%s:%d'" % (path, _line_of(call)), path,
                _line_of(call))


def r211_dpkg(path, source, tree):
    """R-211 (ADVISORY): a STATE-CHANGING 'dpkg' -- prefer 'dpkg-noninteractive'.
    A read-only query ('dpkg -l', '--compare-versions') and the 'dpkg-*' tools
    are spared."""
    if path == "usr/bin/pre-push-static" \
            or os.path.basename(path) in ("apt-get-noninteractive",
                                          "dpkg-noninteractive") \
            or waiver(source, "allow-dpkg"):
        return
    for call in bash_ast.call_exprs(tree):
        if effective_command(call, source) != "dpkg":
            continue
        ## Only a state-changing action, as a whole plain-literal argument word.
        args_after = bash_ast.args(call)
        wrapped = bash_ast.command_name(call) in EXEC_WRAPPERS
        start = 1
        if wrapped:
            ## Skip past the wrapper and its options to dpkg's own args.
            for index in range(1, len(args_after)):
                if bash_ast.word_string(args_after[index]) == "dpkg":
                    start = index + 1
                    break
        state_changing = any(
            bash_ast.word_string(word) in DPKG_STATE_ACTIONS
            for word in args_after[start:])
        if state_changing:
            yield Finding(
                NOTE, "R-211",
                "R-211 (ADVISORY): state-changing 'dpkg' in command position -- "
                "prefer 'dpkg-noninteractive' ('## style-ok: allow-dpkg' to "
                "silence): '%s:%d'" % (path, _line_of(call)), path,
                _line_of(call))


## --- grep / mkdir / timeout (the detector side of the fixable rules) --------

## Temp-dir parameter names whose mkdir operand makes R-172 apply.
TMP_PARAMS = {"TMPDIR", "TEMPDIR", "TEMP", "TMP"}

## grep options that take a SEPARATE value. A value-taker's own value must not be
## read as a flag ('grep -e -q' -- the '-q' is '-e's pattern), and the scan must
## skip PAST it so a later real '-q' is still seen ('grep -e foo -q').
GREP_VALUE_SHORT = frozenset("efmABCdD")
GREP_VALUE_LONG = frozenset({
    "regexp", "file", "max-count", "after-context", "before-context",
    "context", "color", "colour", "binary-files", "devices", "directories",
    "label", "group-separator", "exclude", "exclude-dir", "exclude-from",
    "include"})

## A zero (no-op) GNU timeout duration: bounds nothing, so there is no SIGTERM to
## back with a kill-after -- R-200 exempts it (mirrors the fixer).
ZERO_DURATION = re.compile(r'^(?:0+(?:\.0*)?|\.0+)[smhd]?$')


def _grep_quiet(call, source):
    """(is_quiet, is_short_quiet) for a grep CALL: does its option region carry a
    quiet flag, and is that flag a SHORT cluster ('-q','-iq')? Uses the shared
    option scanner, so a value-taking option's VALUE is skipped ('grep -e foo -q'
    still sees the '-q'; 'grep -e -q' does not treat the '-q' value as a flag)."""
    is_quiet = False
    is_short = False
    for kind, _word, text in bash_ast.command_tokens(
            call, source, GREP_VALUE_SHORT, GREP_VALUE_LONG):
        if kind != "opt":
            continue
        if text in ("--quiet", "--silent"):
            is_quiet = True
        elif text.startswith("-") and not text.startswith("--"):
            ## In a short cluster, chars up to the first value-taker are real
            ## flags; the value-taker and the rest are its value. 'q' among the
            ## flags is a quiet flag.
            cluster = text[1:]
            flags = cluster
            for position, letter in enumerate(cluster):
                if letter in GREP_VALUE_SHORT:
                    flags = cluster[:position]
                    break
            if "q" in flags:
                is_quiet = True
                is_short = True
    return is_quiet, is_short


def r161_grep_quiet(path, source, tree):
    """R-161, both halves: (1) a quiet grep CONSUMING a pipe (a pipefail/SIGPIPE
    bug), and (2) a grep with a SHORT quiet flag (use --quiet). A grep reported by
    (1) is not re-reported by (2)."""
    if path == "usr/bin/pre-push-static":
        return
    pipe_reported = set()
    for pipe in bash_ast.pipe_binary_cmds(tree):
        right = pipe.get("Y")
        cmd = right.get("Cmd") if isinstance(right, dict) else None
        if not isinstance(cmd, dict) or cmd.get("Type") != "CallExpr":
            continue
        if bash_ast.command_name(cmd) != "grep":
            continue
        is_quiet, _ = _grep_quiet(cmd, source)
        if is_quiet:
            pipe_reported.add(id(cmd))
            yield _fail("R-161", "R-161 quiet grep consuming a pipe", path, cmd)
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "grep" or id(call) in pipe_reported:
            continue
        _, is_short = _grep_quiet(call, source)
        if is_short:
            yield _fail("R-161",
                        "R-161 grep short quiet flag (use --quiet)", path, call)


def r172_mkdir_tmp_mode(path, source, tree):
    """R-172: a temp-dir mkdir must set the mode ATOMICALLY with the long
    '--mode'. A short '-m' fails (the fixer upgrades it); no mode at all fails as
    a TOCTOU hole."""
    if path == "usr/bin/pre-push-static" or waiver(source, "allow-mkdir-no-mode"):
        return
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "mkdir":
            continue
        is_temp = any(bash_ast.word_param_names(word) & TMP_PARAMS
                      for word in bash_ast.args(call)[1:])
        if not is_temp:
            continue
        has_long = False
        has_short_m = False
        ## '-m' and '--mode' take a value; scan options only (values and the
        ## operand region are skipped), so '--mode="$x"' counts, a '-m' after
        ## '--' does not, and 'mkdir -- "$TMPDIR" -m' is not misread.
        for kind, _word, text in bash_ast.command_tokens(
                call, source, frozenset("m"), frozenset({"mode"})):
            if kind != "opt":
                continue
            if text == "--mode" or text.startswith("--mode="):
                has_long = True
            elif text.startswith("-") and not text.startswith("--") \
                    and "m" in text[1:]:
                has_short_m = True
        if has_long:
            continue
        if has_short_m:
            yield _fail("R-172", "R-172 mkdir temp dir: use --mode not -m",
                        path, call)
        else:
            yield _fail(
                "R-172",
                "R-172 mkdir temp dir missing --mode (TOCTOU; set perms "
                "atomically, not via a later chmod)", path, call)


def r200_timeout_kill_after(path, source, tree):
    """R-200: a bare 'timeout N cmd' (SIGTERM only) must carry '--kill-after'/'-k'
    so a wedged child still gets SIGKILL. Spares an informational 'timeout
    --help', a no-op zero duration, and (parsing the whole logical command) a
    kill-after that sits on a continuation line -- a false-negative the line-gate
    could not avoid."""
    if waiver(source, "allow-bare-timeout"):
        yield Finding(NOTE, "R-200",
                      "R-200 skipped: 'style-ok: allow-bare-timeout' waiver in "
                      "'%s'" % path, path, 1)
        return
    if bash_ast.defines_function(tree, "timeout"):
        yield Finding(NOTE, "R-200",
                      "R-200 skipped: '%s' defines its own timeout() -- calls "
                      "target it, not coreutils" % path, path, 1)
        return
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) != "timeout":
            continue
        call_args = bash_ast.args(call)
        if len(call_args) < 2:
            continue
        has_kill = False
        informational = False
        duration = None
        ## timeout's value-taking options: -k/--kill-after and -s/--signal. The
        ## scanner skips their values, so a '--signal TERM' value is not read as
        ## the duration and an expanded '--kill-after="$k"' still counts.
        for kind, word, text in bash_ast.command_tokens(
                call, source, frozenset("ks"),
                frozenset({"kill-after", "signal"})):
            if kind == "value":
                continue
            if kind == "operand":
                ## The first operand is the duration.
                duration = bash_ast.word_lit(word)
                break
            if text == "--kill-after" or text.startswith("--kill-after=") \
                    or (text.startswith("-k") and not text.startswith("--")):
                has_kill = True
            if text in ("--help", "--version", "--usage"):
                informational = True
        if has_kill or informational:
            continue
        if duration is not None and ZERO_DURATION.match(duration):
            continue
        yield _fail(
            "R-200",
            "R-200 timeout without --kill-after= (SIGTERM alone can be ignored)",
            path, call)


## --- embedded interpreter programs -----------------------------------------

## Interpreters whose inline program is invisible to shellcheck/ruff/coverage and
## has no importable home a test can reach -- it belongs in its own file.
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php"}
PY_INTERPRETERS = {"python", "python3"}


def r190_inline_interpreter(path, source, tree):
    """R-190: a substantial interpreter program (>5 body lines) in a shell heredoc
    belongs in its own file. The heredoc body is read straight from the AST, so
    the former hand-rolled delimiter tracking (and its documented misses) is gone."""
    if waiver(source, "allow-inline-interpreter"):
        return
    for stmt in bash_ast.iter_stmts(tree):
        cmd = stmt.get("Cmd")
        if not isinstance(cmd, dict) or cmd.get("Type") != "CallExpr":
            continue
        if bash_ast.command_name(cmd) not in INTERPRETERS:
            continue
        for _redirect, lines in bash_ast.heredoc_bodies(stmt):
            if lines > 5:
                yield Finding(
                    FAIL, "R-190",
                    "R-190 inline interpreter program (%d lines) belongs in its "
                    "own file" % lines, path, cmd["Pos"]["Line"])


def r193_python_dashdash_script(path, source, tree):
    """R-193: call an in-repo +x script directly via its shebang, not through a
    'python3 -- <path>.py' prefix (which drops the shebang's interpreter flags).
    Exact via the AST: python in command position with '--' then a literal '.py'
    path -- a quoted mention or a generic '-- "$@"' dispatcher is not a call."""
    if waiver(source, "allow-python-dashdash"):
        return
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) not in PY_INTERPRETERS:
            continue
        ## The '--' must be PYTHON'S OWN option terminator: python's single-dash
        ## options may precede it (incl value-takers '-W error' / '-X k=v', whose
        ## values the scanner skips), but NOT a '-m'/'-c' or a script/module
        ## operand -- after those python is already running something and a later
        ## '--' belongs to IT ('python3 -m coverage run -- harness.py' is
        ## coverage's separator, not a 'python3 -- file' call).
        tokens = list(bash_ast.command_tokens(
            call, source, frozenset("WX"), frozenset()))
        for index, (kind, _word, text) in enumerate(tokens):
            if kind == "value":
                continue
            if kind == "opt" and text == "--":
                after = tokens[index + 1] if index + 1 < len(tokens) else None
                ## The operand often carries an expansion ('"${dir}/foo.py"'), so
                ## check its raw spelling; strip a trailing quote so a '.py' at
                ## the path end is seen.
                if after and after[2].rstrip("\"'").endswith(".py"):
                    yield _fail(
                        "R-193",
                        "R-193 call the +x script directly via its shebang, not "
                        "through an interpreter prefix", path, call)
                break
            if kind == "opt" and (text in ("-m", "-c")
                                  or (not text.startswith("--")
                                      and ("m" in text[1:] or "c" in text[1:]))):
                ## '-m'/'-c' (or a cluster carrying one): python runs a module or
                ## command string; a later '--' is not python's own.
                break
            if kind == "operand":
                break


## --- embedded shell in a '-c' string / config value ------------------------

SHELL_C_CMDS = frozenset({"sh", "bash", "dash"})


def _unquote(text):
    """Strip ONE layer of matching outer quotes from TEXT (the inner shell of a
    '-c' argument or a config value)."""
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def shell_c_programs(tree, source):
    """Yield (call, program_text, line_count) for each 'sh -c <program>' /
    'bash -c' / 'dash -c' in TREE. program_text is the raw source of the program
    argument (quotes included); line_count is how many physical lines it spans.
    Handles both the SEPARATE form ('-c "prog"') and the ATTACHED form
    ('-c"prog"'). The command may be a path ('/bin/bash'); the basename decides."""
    for call in bash_ast.call_exprs(tree):
        name = bash_ast.command_name(call)
        if name is None or name.rsplit("/", 1)[-1] not in SHELL_C_CMDS:
            continue
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
                ## Attached form ('-c"prog"'): the program is the rest of this
                ## word after the 'c'.
                span = word["End"]["Line"] - word["Pos"]["Line"] + 1
                yield (call, text[cluster.index("c") + 2:], span)
            break


def _embeds_multi_statement(value, strict):
    """True if VALUE (a shell command string) embeds multi-statement logic.
    Non-strict (apt/cron): more than one top-level statement (a ';' or newline) or
    a pipe; '&&'/'||'/subshell glue is tolerated. Strict (systemd): also a
    '&&'/'||' chain or a shell control keyword. Parsed with shfmt -- a ';' or '|'
    inside a nested quote is correctly string DATA, closing the former regex's
    documented false positive. A value shfmt cannot parse (config-specific syntax)
    is NOT flagged (the safe direction)."""
    try:
        tree = bash_ast.parse(value)
    except bash_ast.BashParseError:
        return False
    ## More than one top-level statement (a ';' or newline separator), a pipe, or
    ## an inlined control construct (if/for/while/until/case) -- all "a script was
    ## inlined". A '&&'/'||' chain and a subshell are GLUE (an apt hook / cron
    ## entry has no native cwd/conditional), tolerated in non-strict; systemd has
    ## a native directive for each, so strict flags them too.
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


def r192_shell_inline_shell_c(path, source, tree):
    """R-192: a substantial inline shell program (>5 lines) passed to a shell
    '-c' from a shell script belongs in its own file. The '-c' program string is
    read straight from the AST (no quote-parity guessing)."""
    if waiver(source, "allow-inline-interpreter"):
        return
    for call, _program, line_count in shell_c_programs(tree, source):
        if line_count > 5:
            yield _fail(
                "R-192",
                "R-192 inline shell program (%d lines) passed to a shell '-c' "
                "belongs in its own file" % line_count, path, call)


## --- unauthorized skip ------------------------------------------------------

## The per-skip authorization: '## style-ok: allow-skip: <reason>' on the exit
## line (trailing) or the line directly above it. Per-skip, not file-wide, so
## every skip is individually justified. The REASON is mandatory (a ':' then a
## non-blank char): a bare 'allow-skip' with no rationale still reads as an
## unjustified skip.
ALLOW_SKIP = re.compile(r'##[ \t]*style-ok:[ \t]*allow-skip:[ \t]*\S')


def r220_unauthorized_skip(path, source, tree):
    """R-220: a test SKIP ('exit 77' / 'return 77', the reserved skip code) must
    be authorized by a per-skip '## style-ok: allow-skip: <why>' waiver on the
    line or the line above. An AI adding a skip to go green is the failure this
    closes: a REQUIRED dependency's absence is an environment bug and must be
    'exit 1' (FATAL), never a skip; only a genuinely OPTIONAL target may skip, and
    it must say why. Command-position via the AST, so 'exit 77' in a string or a
    comment is not a real skip."""
    lines = source.split("\n")
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_name(call) not in ("exit", "return"):
            continue
        call_args = bash_ast.args(call)
        if len(call_args) < 2 or bash_ast.word_lit(call_args[1]) != "77":
            continue
        line = call["Pos"]["Line"]
        here = lines[line - 1] if 0 <= line - 1 < len(lines) else ""
        above = lines[line - 2] if line - 2 >= 0 else ""
        if ALLOW_SKIP.search(here) or ALLOW_SKIP.search(above):
            continue
        yield _fail(
            "R-220",
            "R-220 unauthorized skip: 'exit 77' without '## style-ok: "
            "allow-skip: <reason>' -- a required-dep absence must be 'exit 1' "
            "(FATAL); only an optional target may skip, and must say why",
            path, call)


## Rules that run over a parsed shell file, in gate dispatch order.
SHELL_RULES = (
    r192_shell_inline_shell_c,
    r220_unauthorized_skip,
    r090_command_v,
    r103_exec,
    r120_rm,
    r034_echo,
    r063_printf_v_unchecked,
    r130_null_command,
    r161_grep_quiet,
    r172_mkdir_tmp_mode,
    r190_inline_interpreter,
    r193_python_dashdash_script,
    r200_timeout_kill_after,
    r210_apt_get,
    r211_dpkg,
    r212_allow_downgrades,
    r213_lintian_disabled,
)


def detect_shell(path, source):
    """Run every shell rule over PATH's SOURCE and return a list of Findings.
    Raises bash_ast.ShfmtMissing if shfmt is absent. On a parse failure returns
    [] -- the gate reports the syntax error via 'bash -n' and its own report."""
    try:
        tree = bash_ast.parse_normalized(source)
    except bash_ast.BashParseError:
        return []
    findings = []
    for rule in SHELL_RULES:
        findings.extend(rule(path, source, tree))
    return findings


## --- config-hosted embedded shell: systemd / apt / cron / workflow YAML ------


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


EXEC_DIRECTIVE = re.compile(r'^[ \t]*(Exec[A-Za-z]*)=(.*)$', re.MULTILINE)
APT_HOOK = re.compile(
    r'(^|[^A-Za-z0-9])(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs)([^A-Za-z0-9]|$)')
CRON_ENV = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*[ \t]*=')


def r191_systemd_unit(path, source):
    """R-191: a systemd unit must not embed a multi-statement shell script in an
    'Exec*=' directive. Flags an 'Exec*=' that invokes a shell '-c' whose program
    embeds multiple statements (strict: ';', a pipe, '&&'/'||', or a control
    keyword), or a directive that spans physical lines. The '-c' program is
    parsed, so a ';'/'&' inside a nested quote is data, not a separator."""
    if path.endswith(".md") or not EXEC_DIRECTIVE.search(source) \
            or "Exec" not in source:
        return
    if config_waiver(source, "allow-embedded-script"):
        yield Finding(NOTE, "R-191",
                      "R-191 skipped: 'style-ok: allow-embedded-script' waiver "
                      "in '%s'" % path, path, 1)
        return
    lines = source.split("\n")
    index = 0
    while index < len(lines):
        match = EXEC_DIRECTIVE.match(lines[index])
        if not match:
            index += 1
            continue
        directive, value = match.group(1), match.group(2)
        start = index + 1
        spanned = False
        while value.endswith("\\") and index + 1 < len(lines):
            value = value[:-1]
            index += 1
            value += lines[index]
            spanned = True
        index += 1
        try:
            vtree = bash_ast.parse(value)
        except bash_ast.BashParseError:
            continue
        programs = list(shell_c_programs(vtree, value))
        if not programs:
            continue
        multi = spanned or any(
            _embeds_multi_statement(_unquote(program_text), strict=True)
            for _call, program_text, _lc in programs)
        if multi:
            yield Finding(
                FAIL, "R-191",
                "R-191 systemd unit embeds a multi-statement shell script in %s; "
                "move the logic to a dedicated script (shebang) and call it"
                % directive, path, start)


def _double_quoted_spans(line):
    """Yield the inner text of each double-quoted run on LINE (apt config values
    are double-quoted). Not escape-aware -- apt values do not carry escaped
    quotes in practice."""
    rest = line
    while '"' in rest:
        after = rest.split('"', 1)[1]
        if '"' not in after:
            break
        inner, rest = after.split('"', 1)
        yield inner


def r194_apt_hook(path, source):
    """R-194: an apt configuration hook ('Pre-Invoke' / 'Post-Invoke' /
    'Pre-Install-Pkgs') runs its double-quoted value via 'sh -c'; a
    multi-statement value belongs in a script. The value is parsed, not defanged
    by regex."""
    if not is_apt_conf(path) or not APT_HOOK.search(source):
        return
    if config_waiver(source, "allow-embedded-script", slashes=True):
        yield Finding(NOTE, "R-194",
                      "R-194 skipped: 'style-ok: allow-embedded-script' waiver "
                      "in '%s'" % path, path, 1)
        return
    for number, line in enumerate(source.split("\n"), start=1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        ## The directive must be in config position, before any quoted value.
        before = line.split('"', 1)[0]
        if not APT_HOOK.search(before):
            continue
        for inner in _double_quoted_spans(line):
            if _embeds_multi_statement(inner, strict=False):
                yield Finding(
                    FAIL, "R-194",
                    "R-194 apt hook embeds a multi-statement shell command; move "
                    "the logic to a dedicated script (shebang) and call it",
                    path, number)


def r195_cron_table(path, source):
    """R-195: a cron entry's command field runs via 'sh -c'; a multi-statement
    command belongs in a script. The command field (before the first unescaped
    '%') is parsed, not defanged."""
    if not is_cron_table(path):
        return
    if config_waiver(source, "allow-embedded-script"):
        yield Finding(NOTE, "R-195",
                      "R-195 skipped: 'style-ok: allow-embedded-script' waiver "
                      "in '%s'" % path, path, 1)
        return
    for number, line in enumerate(source.split("\n"), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or CRON_ENV.match(stripped):
            continue
        ## A cron command ends at the first UNESCAPED '%'; the rest is stdin.
        command = re.split(r'(?<!\\)%', line, maxsplit=1)[0]
        if _embeds_multi_statement(command, strict=False):
            yield Finding(
                FAIL, "R-195",
                "R-195 cron entry embeds a multi-statement shell command; move "
                "the logic to a dedicated script (shebang) and call it",
                path, number)


def r100_yaml_inline_shell(path, source):
    """R-100: a workflow 'run:' step must not embed a substantial inline shell
    SCRIPT (more than 5 top-level shell statements). The count comes from a real
    bash parse of the run: body, not a line count, so a single command wrapped
    over many backslash-continued lines is ONE statement (not a block), and a
    heredoc's data lines are not miscounted. A run: body that does not parse as
    bash (e.g. it inlines a '${{ }}' expression) is left to the command-injection
    rules, not flagged here. Uses a real YAML parse (marks) to locate each 'run:'
    scalar and its start line."""
    if not is_workflow_yaml(path):
        return
    if config_waiver(source, "allow-inline-shell"):
        yield Finding(NOTE, "R-100",
                      "R-100 skipped: 'style-ok: allow-inline-shell' waiver in "
                      "'%s'" % path, path, 1)
        return
    import yaml
    try:
        root = yaml.compose(source)
    except yaml.YAMLError:
        return
    if root is None:
        return
    for key_node, value_node in _yaml_run_scalars(root):
        try:
            tree = bash_ast.parse_normalized(value_node.value or "")
        except bash_ast.BashParseError:
            continue
        count = len(tree.get("Stmts") or [])
        if count > 5:
            yield Finding(
                FAIL, "R-100",
                "R-100 workflow embeds an inline shell script (%d statements) "
                "in a 'run:' step; extract it to a ci/ script and call it"
                % count, path, key_node.start_mark.line + 1)


def _yaml_run_scalars(node):
    """Yield (key_node, value_node) for every 'run:' mapping entry whose value is
    a scalar, anywhere in the composed YAML NODE."""
    import yaml
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode) \
                    and key_node.value == "run" \
                    and isinstance(value_node, yaml.ScalarNode):
                yield key_node, value_node
            yield from _yaml_run_scalars(value_node)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            yield from _yaml_run_scalars(item)


## Config rules keyed by their file predicate. Each takes (path, source).
CONFIG_RULES = (
    r191_systemd_unit,
    r194_apt_hook,
    r195_cron_table,
    r100_yaml_inline_shell,
)


def detect_file(path, source, is_shell):
    """Run every applicable rule over PATH. IS_SHELL is the gate's own
    shell-file verdict (so detector and gate agree on the shell set). Shell rules
    run over the parsed shell tree; the config rules self-select by path."""
    findings = []
    if is_shell:
        findings.extend(detect_shell(path, source))
    for rule in CONFIG_RULES:
        findings.extend(rule(path, source))
    return findings
