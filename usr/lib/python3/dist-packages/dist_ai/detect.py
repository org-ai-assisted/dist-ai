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
import os
import re

from dist_ai import bash_ast

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
            ## leading 'VAR=value' env-assignment is still not the command.
            lit = bash_ast.word_lit(word)
            if lit is not None and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', lit):
                continue
            return lit
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
        if first and bash_ast.word_lit(first[0]) == "-v":
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
            if bash_ast.word_lit(word) == "--allow-downgrades":
                yield _fail("R-212", "R-212 --allow-downgrades forbidden",
                            path, word)


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
                if bash_ast.word_lit(args_after[index]) == "dpkg":
                    start = index + 1
                    break
        state_changing = any(
            bash_ast.word_lit(word) in DPKG_STATE_ACTIONS
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


## Rules that run over a parsed shell file, in gate dispatch order.
SHELL_RULES = (
    r090_command_v,
    r103_exec,
    r120_rm,
    r034_echo,
    r130_null_command,
    r161_grep_quiet,
    r172_mkdir_tmp_mode,
    r190_inline_interpreter,
    r193_python_dashdash_script,
    r200_timeout_kill_after,
    r210_apt_get,
    r211_dpkg,
    r212_allow_downgrades,
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
