## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shell-structure rules, each a Rule object. detect() answers a command-position
/ quote / heredoc question from the shfmt AST; the three mechanically-fixable
rules (R-161, R-172, R-200) also carry fix(), sharing the very constants their
detect() uses -- so the detector and the rewriter cannot drift."""

import ast
import re

from dist_ai import bash_ast
from dist_ai import model
from dist_ai.model import Edit, Rule
from dist_ai.rules import _helpers as h


def _fail(ctx, rule, message, node):
    return model.fail(rule, message, ctx.path, node)


def _note(ctx, rule, message, line):
    return model.note(rule, message, ctx.path, line)


## --- command-position rules -----------------------------------------------


class CommandV(Rule):
    """R-090: 'command -v' (prefer helper-scripts 'has' / 'type -P')."""

    id = "R-090"
    waiver_tag = "no-has"
    _exempt = (".github/actions/install-deps/install-helper-scripts.sh",)

    def applies(self, ctx):
        return (super().applies(ctx)
                and not ctx.is_posix_sh
                and ctx.path not in self._exempt)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) != "command":
                continue
            ## Any short-option run carrying 'v' is the 'command -v' describe
            ## mode: '-v', '-pv', '-p -v'. word_string (quote-aware): 'command
            ## "-v" foo' counts too. Stop at the first non-option (the name).
            for word in bash_ast.args(call)[1:]:
                opt = bash_ast.word_string(word)
                if opt is None or not opt.startswith("-"):
                    break
                if opt == "--":
                    break  ## end of options; 'command -- -v' RUNS '-v', not -v mode
                if not opt.startswith("--") and "v" in opt[1:]:
                    yield _fail(ctx, "R-090", "R-090 command -v", call)
                    break


class Exec(Rule):
    """R-103: process-replacement 'exec <command>'. An fd-redirection exec
    ('exec 9>lock') has no command argument, so it is not matched."""

    id = "R-103"
    waiver_tag = "allow-exec"

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) != "exec":
                continue
            call_args = bash_ast.args(call)
            if len(call_args) < 2:
                continue
            first = bash_ast.word_lit(call_args[1])
            if first is not None and first.startswith("["):
                ## Usage TEXT describing an 'exec' subcommand ('exec [--workdir
                ## DIR] -- CMD'); no real script execs the '[' builtin.
                continue
            yield _fail(ctx, "R-103", "R-103 process-replacement exec", call)


class Rm(Rule):
    """R-120: 'rm' (use safe-rm). 'git rm'/'shred' differ; 'sudo rm' is caught."""

    id = "R-120"
    waiver_tag = "no-safe-rm"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if h.effective_command(call, ctx.source) == "rm":
                yield _fail(ctx, "R-120", "R-120 rm not safe-rm", call)


class Echo(Rule):
    """R-034: 'echo' as a command (use printf)."""

    id = "R-034"
    waiver_tag = "allow-echo"

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if h.effective_command(call, ctx.source) == "echo":
                yield _fail(ctx, "R-034", "R-034 echo not printf", call)


class PrintfVUnchecked(Rule):
    """R-063: a 'printf -v <name>' whose target NAME is dynamic must be guarded
    by 'check_variable_name' on that name earlier in the enclosing function -- an
    unchecked name of the form 'x[$(cmd)]' RUNS cmd. A literal target is spared.
    The guard must be same-scope, textually before, and cover every parameter of
    the target name (bash evaluates the whole subscript)."""

    id = "R-063"
    waiver_tag = "allow-unchecked-printf-v"

    def detect(self, ctx):
        tree = ctx.tree
        guards = h.check_variable_name_sites(tree)
        for call in bash_ast.call_exprs(tree):
            if bash_ast.command_name(call) != "printf":
                continue
            name_word = h.printf_v_target(call)
            if name_word is None:
                continue
            if bash_ast.word_string(name_word) is not None:
                ## Statically-known name: no injectable subscript.
                continue
            target_params = bash_ast.word_param_names(name_word)
            offset = call["Pos"]["Offset"]
            ## A guard counts only when its ENFORCING container (the branch/scope it
            ## gates) reaches THIS printf -- guard_span contains the printf offset and
            ## the guard is textually before it. A decoy guard (sibling branch,
            ## subshell, command substitution, or a bare non-'||' call) never does.
            covered = set()
            for guard_offset, guard_span, guard_params in guards:
                if guard_span[0] <= offset < guard_span[1] and guard_offset < offset:
                    covered |= guard_params
            ## A command substitution / arithmetic in the target name is never
            ## made safe by a guard (it runs when bash evaluates the subscript),
            ## so a name mixing a checked param with a '$(...)' must still flag.
            if not h.word_has_command_expansion(name_word) \
                    and target_params and target_params <= covered:
                continue
            yield _fail(
                ctx, "R-063",
                "R-063 printf -v dynamic name unguarded by check_variable_name "
                "(an unchecked name runs the command in name[$(...)])", call)


class NullCommand(Rule):
    """R-130: ':' used as a command -- a bare filler ':' statement, or the
    ': > file' truncation idiom. Spares ': "${var:=default}"' and 'while :'."""

    id = "R-130"

    def detect(self, ctx):
        for stmt, context in h.statements(ctx.tree):
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
                yield _fail(ctx, "R-130", "R-130 ':' used as a command", cmd)
            elif context == h.CONTEXT_STMT and h.line_is_bare_colon(
                    ctx.source, cmd):
                yield _fail(ctx, "R-130", "R-130 ':' used as a command", cmd)


## --- grep (detect both halves; fix the short-cluster half) -----------------

## grep options that take a SEPARATE value; a value-taker's value must not be
## read as a flag ('grep -e -q' -- the '-q' is '-e's pattern).
GREP_VALUE_SHORT = frozenset("efmABCdD")
GREP_VALUE_LONG = frozenset({
    "regexp", "file", "max-count", "after-context", "before-context",
    "context", "color", "colour", "binary-files", "devices", "directories",
    "label", "group-separator", "exclude", "exclude-dir", "exclude-from",
    "include"})

## The long spelling of each NO-ARG short grep option, for the R-161 fix. A
## cluster containing any letter outside this map is left as-is.
GREP_LONG = {
    "i": "--ignore-case", "q": "--quiet", "v": "--invert-match",
    "n": "--line-number", "c": "--count", "l": "--files-with-matches",
    "L": "--files-without-match", "w": "--word-regexp", "x": "--line-regexp",
    "E": "--extended-regexp", "F": "--fixed-strings", "G": "--basic-regexp",
    "P": "--perl-regexp", "o": "--only-matching", "s": "--no-messages",
    "h": "--no-filename", "H": "--with-filename", "r": "--recursive",
    "R": "--dereference-recursive", "a": "--text", "z": "--null-data",
    "Z": "--null", "b": "--byte-offset",
}
GREP_ARG_TAKING_LONG = {
    "--regexp", "--file", "--max-count", "--after-context",
    "--before-context", "--context", "--color", "--colour", "--binary-files",
    "--devices", "--directories", "--label", "--group-separator", "--exclude",
    "--exclude-dir", "--exclude-from", "--include",
}


def _grep_quiet(call, source):
    """(is_quiet, is_short_quiet) for a grep CALL. Shared scanner skips a
    value-taker's value."""
    is_quiet = False
    is_short = False
    for kind, _word, text in bash_ast.command_tokens(
            call, source, GREP_VALUE_SHORT, GREP_VALUE_LONG):
        if kind != "opt":
            continue
        if text in ("--quiet", "--silent"):
            is_quiet = True
        elif text.startswith("-") and not text.startswith("--"):
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


def _grep_option_words(call):
    """The leading option Words of a grep CALL (Args[1:] up to the first operand
    or '--'). Declines (stops) at a quoted/expanded word it cannot classify."""
    options = []
    for word in bash_ast.args(call)[1:]:
        lit = bash_ast.word_lit(word)
        if lit is None:
            return options
        if lit == "--":
            break
        if not lit.startswith("-") or lit == "-":
            break
        options.append((word, lit))
    return options


def _grep_has_arg_taker(options):
    """True if any grep option expects a separate value -- then a following
    '-q'-shaped token is ambiguous and the whole grep is left for the gate."""
    for _word, lit in options:
        if lit.startswith("--"):
            name = lit.split("=", 1)[0]
            if "=" not in lit and name in GREP_ARG_TAKING_LONG:
                return True
        elif lit.startswith("-"):
            if set(lit[1:]) & GREP_VALUE_SHORT:
                return True
    return False


class GrepQuiet(Rule):
    """R-161: (1) a quiet grep CONSUMING a pipe (pipefail/SIGPIPE bug -- NOT
    fixable, relocating a redirect is multi-token) and (2) a grep with a SHORT
    quiet cluster (fixable: expand to long options). A grep reported by (1) is
    not re-reported by (2)."""

    id = "R-161"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        tree = ctx.tree
        pipe_reported = set()
        for pipe in bash_ast.pipe_binary_cmds(tree):
            right = pipe.get("Y")
            cmd = right.get("Cmd") if isinstance(right, dict) else None
            if not isinstance(cmd, dict) or cmd.get("Type") != "CallExpr":
                continue
            if bash_ast.command_name(cmd) != "grep":
                continue
            is_quiet, _ = _grep_quiet(cmd, ctx.source)
            if is_quiet:
                pipe_reported.add(id(cmd))
                yield _fail(ctx, "R-161", "R-161 quiet grep consuming a pipe",
                            cmd)
        for call in bash_ast.call_exprs(tree):
            if bash_ast.command_name(call) != "grep" \
                    or id(call) in pipe_reported:
                continue
            _, is_short = _grep_quiet(call, ctx.source)
            if is_short:
                yield _fail(ctx, "R-161",
                            "R-161 grep short quiet flag (use --quiet)", call)

    def fix(self, ctx):
        for call in h.editable_calls(ctx.tree):
            if bash_ast.command_name(call) != "grep":
                continue
            options = _grep_option_words(call)
            if _grep_has_arg_taker(options):
                continue
            for word, lit in options:
                cluster = lit[1:]
                if "q" not in cluster:
                    continue
                if not all(char in GREP_LONG for char in cluster):
                    continue
                start, end = bash_ast.word_span(word)
                yield Edit(start, end,
                           " ".join(GREP_LONG[char] for char in cluster),
                           "R-161")


## --- mkdir temp-dir mode (detect; fix the short-'-m' half) ------------------

## Temp-dir parameter names whose mkdir operand makes R-172 apply.
TMP_PARAMS = {"TMPDIR", "TEMPDIR", "TEMP", "TMP"}

## A jammed short '-m' mode, possibly BUNDLED behind other short flags
## ('-pm700' = -p -m 700). GNU mkdir gives the FIRST 'm' in the cluster the rest as
## its argument, so the prefix EXCLUDES a lowercase 'm': else a greedy match on
## '-mpm700' picks the LAST m and rewrites an INVALID mode ('-m pm700', mkdir fails)
## into a VALID one ('-mp --mode=700', mkdir succeeds), silencing R-172.
## group(1) = the preceding flags, group(2) = the octal mode.
MKDIR_M_JAMMED = re.compile(r'^-([a-ln-zA-Z]*)m([0-7]{3,4})$')

## The atomic 'mkdir --parents ... --mode=' form trips shellcheck SC2174 by
## design; insert the disable so R-172's mandated form stays shellcheck-clean.
SC2174_DISABLE = re.compile(
    r'#[ \t]*shellcheck[ \t]+disable=[A-Z0-9, ]*SC2174(?![0-9])')
SC2174_DIRECTIVE = "# shellcheck disable=SC2174"


class MkdirTmpMode(Rule):
    """R-172: a temp-dir mkdir must set the mode ATOMICALLY via long '--mode'. A
    short '-m' fails (fix upgrades it); no mode at all fails as a TOCTOU hole
    (not fixable -- a mode value cannot be guessed)."""

    id = "R-172"
    waiver_tag = "allow-mkdir-no-mode"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) != "mkdir":
                continue
            is_temp = any(bash_ast.word_param_names(word) & TMP_PARAMS
                          for word in bash_ast.args(call)[1:])
            if not is_temp:
                continue
            has_long = False
            has_short_m = False
            for kind, _word, text in bash_ast.command_tokens(
                    call, ctx.source, frozenset("m"), frozenset({"mode"})):
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
                yield _fail(ctx, "R-172",
                            "R-172 mkdir temp dir: use --mode not -m", call)
            else:
                yield _fail(
                    ctx, "R-172",
                    "R-172 mkdir temp dir missing --mode (TOCTOU; set perms "
                    "atomically, not via a later chmod)", call)

    def fix(self, ctx):
        text = ctx.source
        data = text.encode("utf-8")
        disabled_lines = set()
        for call in h.editable_calls(ctx.tree):
            if bash_ast.command_name(call) != "mkdir":
                continue
            call_args = bash_ast.args(call)
            if not any(bash_ast.word_param_names(word) & TMP_PARAMS
                       for word in call_args[1:]):
                continue
            has_parents = False
            has_mode = False
            tokens = list(bash_ast.command_tokens(
                call, text, frozenset("m"), frozenset({"mode"})))
            for index, (kind, word, lit) in enumerate(tokens):
                if kind != "opt":
                    continue
                if lit == "--mode" or lit.startswith("--mode="):
                    has_mode = True
                    continue
                if not lit.startswith("--"):
                    cluster = lit[1:]
                    if "p" in cluster:
                        has_parents = True
                    jammed = MKDIR_M_JAMMED.match(lit)
                    if jammed:
                        prefix, mode = jammed.group(1), jammed.group(2)
                        start, end = bash_ast.word_span(word)
                        ## keep any flags bundled before the '-m' (e.g. '-pm700'
                        ## -> '-p --mode=700'); a bare '-m700' -> '--mode=700'.
                        replacement = ("-" + prefix + " " if prefix else "") \
                            + "--mode=" + mode
                        yield Edit(start, end, replacement, "R-172")
                        has_mode = True
                    elif lit == "-m" and index + 1 < len(tokens) \
                            and tokens[index + 1][0] == "value":
                        mode_word = tokens[index + 1][1]
                        mode_lit = bash_ast.word_lit(mode_word)
                        start, m_end = bash_ast.word_span(word)
                        mode_start, end = bash_ast.word_span(mode_word)
                        ## Splice '-m ... 700' -> '--mode=700' ONLY when nothing
                        ## but whitespace sits between the flag and its value. A
                        ## redirection ('mkdir -m >/dev/null 700 ...') lives on
                        ## the Stmt, not in Args, so it falls in this gap -- and a
                        ## span from '-m' to the mode word would DELETE it. Leave
                        ## that (rare) shape for the gate.
                        between = data[m_end:mode_start]
                        if mode_lit and re.fullmatch(r'[0-7]{3,4}', mode_lit) \
                                and between.strip() == b'':
                            yield Edit(start, end, "--mode=" + mode_lit,
                                       "R-172")
                            has_mode = True
                elif lit == "--parents":
                    has_parents = True
            if has_parents and has_mode:
                edit = self._sc2174_edit(data, call, disabled_lines)
                if edit is not None:
                    yield edit

    @staticmethod
    def _sc2174_edit(data, call, disabled_lines):
        """The '# shellcheck disable=SC2174' insertion above an atomic
        '--parents ... --mode' mkdir, or None when it is already present or the
        line is an odd-backslash continuation. All offsets are BYTE offsets."""
        line_start = data.rfind(b"\n", 0, call["Pos"]["Offset"]) + 1
        if line_start in disabled_lines:
            return None
        line_end = data.find(b"\n", line_start)
        line = data[line_start:(line_end if line_end != -1 else len(data))] \
            .decode("utf-8", "replace")
        prev_start = data.rfind(b"\n", 0, line_start - 1) + 1 \
            if line_start > 0 else 0
        prev_line = data[prev_start:max(line_start - 1, 0)] \
            .decode("utf-8", "replace").rstrip("\r")
        if SC2174_DISABLE.search(line) or SC2174_DISABLE.search(prev_line):
            return None
        trailing = len(prev_line) - len(prev_line.rstrip("\\"))
        if trailing % 2 == 1:
            return None
        indent = line[:len(line) - len(line.lstrip())]
        disabled_lines.add(line_start)
        return Edit(line_start, line_start,
                    indent + SC2174_DIRECTIVE + "\n", "R-172")


## --- timeout kill-after (detect; fix the bare literal-duration form) --------

## A zero (no-op) GNU timeout duration -- bounds nothing, no SIGTERM to back.
ZERO_DURATION = re.compile(r'^(?:0+(?:\.0*)?|\.0+)[smhd]?$')
## A POSITIVE literal duration (strtod-style, optional [smhd] unit) -- the only
## form the fix rewrites (a zero duration would emit a disabled '--kill-after=0').
TIMEOUT_DURATION = re.compile(
    r'^(?:[0-9]*[1-9][0-9]*(?:\.[0-9]*)?|[0-9]*\.[0-9]*[1-9][0-9]*)[smhd]?$')
TIMEOUT_WAIVER = "allow-bare-timeout"


class TimeoutKillAfter(Rule):
    """R-200: a bare 'timeout N cmd' (SIGTERM only) must carry '--kill-after'/'-k'
    so a wedged child still gets SIGKILL. Spares an informational 'timeout
    --help', a no-op zero duration, and a script defining its own timeout()."""

    id = "R-200"

    def detect(self, ctx):
        tree = ctx.tree
        if ctx.has_waiver(TIMEOUT_WAIVER):
            yield _note(ctx, "R-200",
                        "R-200 skipped: 'style-ok: allow-bare-timeout' waiver "
                        "in '%s'" % ctx.path, 1)
            return
        if bash_ast.defines_function(tree, "timeout"):
            yield _note(ctx, "R-200",
                        "R-200 skipped: '%s' defines its own timeout() -- calls "
                        "target it, not coreutils" % ctx.path, 1)
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
            for kind, word, text in bash_ast.command_tokens(
                    call, ctx.source, frozenset("ks"),
                    frozenset({"kill-after", "signal"})):
                if kind == "value":
                    continue
                if kind == "operand":
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
                ctx, "R-200",
                "R-200 timeout without --kill-after= (SIGTERM alone can be "
                "ignored)", call)

    def fix(self, ctx):
        tree = ctx.tree
        ## In lockstep with detect's exemptions: a waived file or one defining
        ## its own timeout() is not rewritten.
        if ctx.has_waiver(TIMEOUT_WAIVER) or bash_ast.defines_function(
                tree, "timeout"):
            return
        for call in h.editable_calls(tree):
            if bash_ast.command_name(call) != "timeout":
                continue
            call_args = bash_ast.args(call)
            if len(call_args) < 3:
                ## Need a duration and at least one wrapped command word.
                continue
            duration = bash_ast.word_lit(call_args[1])
            if not duration or not TIMEOUT_DURATION.match(duration):
                continue
            start, _ = bash_ast.word_span(call_args[1])
            yield Edit(start, start, "--kill-after=%s " % duration, "R-200")


## --- embedded interpreter programs -----------------------------------------

INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php"}
PY_INTERPRETERS = {"python", "python3"}


class InlineInterpreter(Rule):
    """R-190: a substantial interpreter program (>5 body lines) in a shell
    heredoc belongs in its own file."""

    id = "R-190"
    waiver_tag = "allow-inline-interpreter"

    def detect(self, ctx):
        for stmt in bash_ast.iter_stmts(ctx.tree):
            cmd = stmt.get("Cmd")
            if not isinstance(cmd, dict) or cmd.get("Type") != "CallExpr":
                continue
            if bash_ast.command_name(cmd) not in INTERPRETERS:
                continue
            for _redirect, lines in bash_ast.heredoc_bodies(stmt):
                if lines > 5:
                    yield model.fail(
                        "R-190",
                        "R-190 inline interpreter program (%d lines) belongs in "
                        "its own file" % lines, ctx.path, cmd["Pos"]["Line"])


class PythonDashDashScript(Rule):
    """R-193: call an in-repo +x script directly via its shebang, not through a
    'python3 -- <path>.py' prefix (which drops the shebang's interpreter flags)."""

    id = "R-193"
    waiver_tag = "allow-python-dashdash"

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) not in PY_INTERPRETERS:
                continue
            tokens = list(bash_ast.command_tokens(
                call, ctx.source, frozenset("WX"), frozenset()))
            for index, (kind, _word, text) in enumerate(tokens):
                if kind == "value":
                    continue
                if kind == "opt" and text == "--":
                    after = tokens[index + 1] if index + 1 < len(tokens) \
                        else None
                    if after and after[2].rstrip("\"'").endswith(".py"):
                        yield _fail(
                            ctx, "R-193",
                            "R-193 call the +x script directly via its shebang, "
                            "not through an interpreter prefix", call)
                    break
                if kind == "opt" and (text in ("-m", "-c")
                                      or (not text.startswith("--")
                                          and ("m" in text[1:]
                                               or "c" in text[1:]))):
                    break
                if kind == "operand":
                    break


class ShellInlineShellC(Rule):
    """R-192: a substantial inline shell program (>5 lines) passed to a shell
    '-c' from a shell script belongs in its own file."""

    id = "R-192"
    waiver_tag = "allow-inline-interpreter"

    def detect(self, ctx):
        ## Command-position shell '-c' only. Catching a shell behind a wrapper
        ## ('ssh host -- bash -lc PROG', 'su - u -c PROG') needs a wrapper
        ## allowlist + effective-command + value-option handling done right; a
        ## bare "any shell-name operand + -c" heuristic both false-positives
        ## ('echo bash -c "<6 lines>"') and misses 'su -c'. Left as a follow-up.
        for call, _program, line_count in h.shell_c_programs(
                ctx.tree, ctx.source):
            if line_count > 5:
                yield _fail(
                    ctx, "R-192",
                    "R-192 inline shell program (%d lines) passed to a shell "
                    "'-c' belongs in its own file" % line_count, call)


## --- unauthorized skip ------------------------------------------------------

ALLOW_SKIP = re.compile(r'##[ \t]*style-ok:[ \t]*allow-skip:[ \t]*\S')
## A SIGNED decimal literal: bash tolerates a leading '+' or '-' on an exit/return
## code, so a bare '[0-9]+' would miss 'exit +77' / 'exit -179' and leave them
## ungated.
_DECIMAL_INT = re.compile(r'[+-]?[0-9]+')


## Statically evaluate a CONSTANT '$(( ))' exit code, so a skip disguised as
## 'exit $((70+7))' (runs 77) is caught. Kept to plain constant arithmetic
## ('+ - * / %', literals, parens) -- shifts/bitwise/power, whose bash edge
## semantics or huge intermediates are not worth matching, and any variable or
## command expansion, DECLINE (return None), the 'guess nothing' safe direction.
_ARITH_CONST_CHARS = re.compile(r'\A[0-9+\-*/%() \t]+\Z')


def _trunc_div(dividend, divisor):
    """Integer division truncated toward zero (bash '/' semantics; Python '//'
    floors). Integer-only: a float '/' OverflowErrors past ~1e308 and loses
    precision above 2**53, so a huge constant would crash or misevaluate."""
    quotient = abs(dividend) // abs(divisor)
    return -quotient if (dividend < 0) != (divisor < 0) else quotient


def _eval_const_arith(node):
    """The int value of an ast arithmetic node built from integer literals and the
    shared '+ - * / %' operators, else None. bash truncates '/' toward zero and takes
    '%' with the dividend's sign, so both are matched rather than using Python's
    flooring operators."""
    if isinstance(node, ast.Expression):
        return _eval_const_arith(node.body)
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, int) and not isinstance(
            node.value, bool) else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        val = _eval_const_arith(node.operand)
        if val is None:
            return None
        return val if isinstance(node.op, ast.UAdd) else -val
    if isinstance(node, ast.BinOp):
        left = _eval_const_arith(node.left)
        right = _eval_const_arith(node.right)
        if left is None or right is None:
            return None
        op = node.op
        if isinstance(op, ast.Add):
            return left + right
        if isinstance(op, ast.Sub):
            return left - right
        if isinstance(op, ast.Mult):
            return left * right
        if isinstance(op, (ast.Div, ast.FloorDiv)):
            return None if right == 0 else _trunc_div(left, right)
        if isinstance(op, ast.Mod):
            return None if right == 0 else left - right * _trunc_div(left, right)
    return None


def _const_arith_exit_value(word, source):
    """The int value of WORD when it is a single, purely-CONSTANT '$(( ))' arithmetic
    expansion, else None. A dynamic '$((rc+1))' or an exotic base/operator DECLINES,
    the same safe direction as word_string returning None for a real expansion."""
    parts = word.get("Parts") or []
    if len(parts) != 1 or parts[0].get("Type") != "ArithmExp":
        return None
    inner = bash_ast.word_source(word, source).strip()
    if not (inner.startswith("$((") and inner.endswith("))")):
        return None
    ## Strip inner whitespace: ast.parse(mode="eval") rejects a LEADING space as
    ## indentation ('$(( 70 + 7 ))' would else raise IndentationError and decline).
    inner = inner[3:-2].strip()
    if not _ARITH_CONST_CHARS.match(inner):
        return None
    try:
        return _eval_const_arith(ast.parse(inner, mode="eval"))
    except (SyntaxError, ValueError):
        return None


def _is_skip_code_77(word):
    """True if WORD is an 'exit'/'return' argument that RUNS AS 77. Bash truncates
    the code to 8 bits and parses it as a signed decimal (leading zeros / '+' / '-'
    included), so 'exit 077', 'exit +77', 'exit 333' (333 mod 256) and 'exit -179'
    (-179 mod 256) ALL exit 77 -- a literal '== 77' misses every one and lets an
    unwaived skip slip. Normalize mod 256 (Python's floored '%' is non-negative, so
    a negative code lands right); a non-literal (expansion, or a quoted non-number)
    is not a recognizable skip."""
    if word is None or _DECIMAL_INT.fullmatch(word) is None:
        return False
    return int(word, 10) % 256 == 77


## Prefixes bash treats as running the SAME exit/return builtin: '\exit' (alias
## lookup suppressed) is the command word itself; 'builtin'/'command' are a
## separate leading word that shifts the code one argument right. Unwrapping them
## keeps a skip from evading the gate by an honest alternate spelling -- the same
## reason the apt/dpkg rules unwrap sudo/doas via effective_command.
_EXIT_CALL_WRAPPERS = ("builtin", "command")


def _skip_exit_code_word(call, source):
    """The exit/return CODE word for CALL if it is a test skip, else None.
    Resolves the spellings bash runs identically as the exit/return builtin:
      - a leading-backslash or QUOTED name ('\\exit 77', '"exit" 77') -- word_string
        (quote-aware) is used throughout, since command_name drops a quoted word;
      - a 'builtin'/'command' prefix, including its options and a '--'
        ('builtin -- exit 77', 'command -p exit 77'); but 'command -v'/'-V' only
        DESCRIBE the command and do not run it, so those are NOT a skip;
      - a '--' end-of-options before the code ('exit -- 77');
      - a purely-CONSTANT arithmetic code ('exit $((70+7))' runs 77).
    None (not exit/return, or the code word is missing/dynamically expanded) is the
    safe direction -- the caller declines rather than guesses."""
    words = bash_ast.args(call)
    if not words:
        return None
    name = bash_ast.word_string(words[0])
    if name is None:
        return None
    name = name.lstrip("\\")
    index = 1
    while name in _EXIT_CALL_WRAPPERS:
        ## Unwrap EACH builtin/command layer -- bash runs a NESTED wrap like
        ## 'command builtin exit 77' through all of them, so a single 'if' unwrap
        ## would let the double-wrapped skip slip R-220. Skip this wrapper's options
        ## and a '--' to reach the wrapped word, then loop for a further wrapper.
        while index < len(words):
            word = bash_ast.word_string(words[index])
            if word is None:
                return None
            if word == "--":
                index += 1
                break
            if len(word) > 1 and word[0] == "-":
                opts = word[1:]
                if name == "command":
                    ## 'command -v'/'-V' prints a description instead of running -> not a skip.
                    if "v" in opts or "V" in opts:
                        return None
                    ## Only '-p' is a real run modifier; any OTHER option char is one
                    ## bash rejects ('command -x: invalid option') before exit runs, so
                    ## the whole word is not a skip.
                    if opts.strip("p"):
                        return None
                else:
                    ## 'builtin' takes NO options: 'builtin -p exit ...' is a bash usage
                    ## error (exit never runs), so a leading '-word' is not a skip.
                    return None
                index += 1
                continue
            break
        if index >= len(words):
            return None
        name = (bash_ast.word_string(words[index]) or "").lstrip("\\")
        index += 1
    if name not in ("exit", "return"):
        return None
    ## exit/return: a '--' ends its options before the numeric code.
    if index < len(words) and bash_ast.word_string(words[index]) == "--":
        index += 1
    if index >= len(words):
        return None
    ## word_string resolves a literal/quoted code; a CONSTANT '$(( ))' has no literal
    ## value (word_string is None) yet still runs as a fixed code, so evaluate it --
    ## 'exit $((70+7))' is the same 77 skip as 'exit 77'. Return it as a decimal string
    ## so _is_skip_code_77 applies the same mod-256 normalization.
    code = bash_ast.word_string(words[index])
    if code is not None:
        return code
    value = _const_arith_exit_value(words[index], source)
    return None if value is None else str(value)


def _skip_waived(comment_by_line, line):
    """True if an 'allow-skip' waiver STARTS the real comment on the skip's own
    line or the line directly above. COMMENT_BY_LINE maps a line number to that
    line's shfmt comment TEXT (reconstructed with its leading '#'); the waiver is
    matched anchored at the comment start, NEVER against the raw source line. That
    is the only spoof-proof form: a '## style-ok: allow-skip:' string inside a
    quoted value cannot authorize a skip even when it shares the line with an
    UNRELATED real comment ('echo "...allow-skip..." && exit 77  # note'), because
    the string is not the comment's own text. Mirrors has_waiver, which likewise
    requires the waiver to start the comment (a trailing 'cmd ## style-ok:' still
    counts -- the comment text begins at its '##', whatever code precedes it)."""
    for number in (line, line - 1):
        comment = comment_by_line.get(number)
        if comment is not None and ALLOW_SKIP.match(comment):
            return True
    return False


class UnauthorizedSkip(Rule):
    """R-220: a test SKIP ('exit 77'/'return 77') must be authorized by a
    per-skip '## style-ok: allow-skip: <why>' waiver on the line or the line
    above. A required-dep absence must be 'exit 1' (FATAL), never a skip."""

    id = "R-220"

    def detect(self, ctx):
        ## Map each line to its REAL comment text (leading '#' restored), so the
        ## waiver is matched against the comment itself, not the raw line: a
        ## '## style-ok: allow-skip:' string in a quoted value cannot spoof a skip,
        ## the same spoof has_waiver guards against.
        comment_by_line = {}
        for comment in bash_ast.comments(ctx.tree):
            number = comment.get("Hash", {}).get("Line")
            if number:
                comment_by_line[number] = "#" + comment.get("Text", "")
        for call in bash_ast.call_exprs(ctx.tree):
            ## _skip_exit_code_word resolves exit/return incl. the '\exit' /
            ## 'builtin exit' / 'command exit' spellings, then word_string
            ## (quote-aware) so 'exit "77"' is the same skip as 'exit 77';
            ## _is_skip_code_77 normalizes a leading '+' and decimal leading zeros
            ## ('exit +77' / 'exit 077' both run as 77).
            code_word = _skip_exit_code_word(call, ctx.source)
            if code_word is None or not _is_skip_code_77(code_word):
                continue
            line = call["Pos"]["Line"]
            if _skip_waived(comment_by_line, line):
                continue
            yield _fail(
                ctx, "R-220",
                "R-220 unauthorized skip: 'exit 77' without '## style-ok: "
                "allow-skip: <reason>' -- a required-dep absence must be 'exit "
                "1' (FATAL); only an optional target may skip, and must say why",
                call)


## --- apt / dpkg advisories --------------------------------------------------

DPKG_STATE_ACTIONS = {
    "--install", "--unpack", "--configure", "--remove", "--purge",
    "--record-avail", "--set-selections", "--clear-selections",
    "--update-avail", "--merge-avail", "--forget-old-unavail",
    "--triggers-only", "-i", "-r", "-P", "-A",
}
_NONINTERACTIVE = ("apt-get-noninteractive", "dpkg-noninteractive")


class AptGet(Rule):
    """R-210 (ADVISORY): 'apt-get' in command position -- prefer
    'apt-get-noninteractive'."""

    id = "R-210"
    advisory = True
    waiver_tag = "allow-apt-get"

    def applies(self, ctx):
        import os
        return (super().applies(ctx)
                and os.path.basename(ctx.path) not in _NONINTERACTIVE)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if h.effective_command(call, ctx.source) == "apt-get":
                line = call["Pos"]["Line"]
                yield _note(
                    ctx, "R-210",
                    "R-210 (ADVISORY): 'apt-get' in command position -- prefer "
                    "'apt-get-noninteractive' ('## style-ok: allow-apt-get' to "
                    "silence): '%s:%d'" % (ctx.path, line), line)


class Dpkg(Rule):
    """R-211 (ADVISORY): a STATE-CHANGING 'dpkg' -- prefer 'dpkg-noninteractive'.
    A read-only query ('dpkg -l') and the 'dpkg-*' tools are spared."""

    id = "R-211"
    advisory = True
    waiver_tag = "allow-dpkg"

    def applies(self, ctx):
        import os
        return (super().applies(ctx)
                and os.path.basename(ctx.path) not in _NONINTERACTIVE)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if h.effective_command(call, ctx.source) != "dpkg":
                continue
            args_after = bash_ast.args(call)
            wrapped = bash_ast.command_name(call) in h.EXEC_WRAPPERS
            start = 1
            if wrapped:
                for index in range(1, len(args_after)):
                    if bash_ast.word_string(args_after[index]) == "dpkg":
                        start = index + 1
                        break
            ## word_string (quote-aware): 'dpkg "--install" pkg' is state-changing.
            state_changing = any(
                bash_ast.word_string(word) in DPKG_STATE_ACTIONS
                for word in args_after[start:])
            if state_changing:
                line = call["Pos"]["Line"]
                yield _note(
                    ctx, "R-211",
                    "R-211 (ADVISORY): state-changing 'dpkg' in command "
                    "position -- prefer 'dpkg-noninteractive' ('## style-ok: "
                    "allow-dpkg' to silence): '%s:%d'" % (ctx.path, line), line)


## apt's truthy tokens (case-insensitive); every other value -- 'false', 'no',
## '0', 'off', '2', an unknown word, empty -- reads FALSE. Verified empirically
## with 'apt-config -o OPT=<v> shell RET OPT/b'.
_APT_TRUE = frozenset({"true", "yes", "on", "1", "with", "enable"})


def _enables_allow_downgrades(text):
    """True if TEXT is an '--allow-downgrades' argument that ENABLES downgrades:
    the bare flag, or '=<value>' whose value is an apt truthy token. A disabling
    value ('=false'/'=0'/...) is a harmless no-op and is NOT the risk this rule
    guards, so it must not be flagged."""
    if text is None:
        return False
    if text == "--allow-downgrades":
        return True
    prefix = "--allow-downgrades="
    if text.startswith(prefix):
        return text[len(prefix):].lower() in _APT_TRUE
    return False


class AllowDowngrades(Rule):
    """R-212: enabling '--allow-downgrades' is forbidden (bare flag, or
    '=<truthy>'); the disabling forms are a no-op and are spared."""

    id = "R-212"
    waiver_tag = "allow-downgrades"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            for word in bash_ast.args(call):
                if _enables_allow_downgrades(bash_ast.word_string(word)):
                    yield _fail(ctx, "R-212",
                                "R-212 --allow-downgrades forbidden", word)


class LintianDisabled(Rule):
    """R-213: 'make_use_lintian=false' disables the lintian gate; forbidden
    without authorization -- fix the lintian findings instead."""

    id = "R-213"
    waiver_tag = "allow-lintian-disable"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        ## A bare / env-prefix assignment ('make_use_lintian=false [cmd]') is a
        ## CallExpr's Assign; an 'export'/'declare make_use_lintian=false' is a
        ## DeclClause whose Args carry the Assign -- shfmt models the two
        ## differently, so BOTH are scanned (a non-Assign flag word in Args, e.g.
        ## 'declare -r', yields no name and is skipped).
        assigns = []
        for call in bash_ast.call_exprs(ctx.tree):
            assigns.extend(bash_ast.assigns(call))
        for decl in bash_ast.nodes_of_type(ctx.tree, "DeclClause"):
            assigns.extend(decl.get("Args") or [])
        for assign in assigns:
            if bash_ast.assign_name(assign) == "make_use_lintian" \
                    and bash_ast.word_string(
                        bash_ast.assign_value(assign)) == "false":
                yield _fail(
                    ctx, "R-213",
                    "R-213 lintian disabled (make_use_lintian=false) "
                    "without authorization", assign)


def _set_option_words(call):
    """The option tokens of a 'set' call, up to a bare '--' (after which the
    tokens are POSITIONAL parameters, not options). Yields (lit, is_short_cluster,
    is_o_group): lit is the token text; is_short_cluster True for a '-xxx' bundle;
    is_o_group True for a '-o'/'+o' (its name argument is consumed and skipped)."""
    words = bash_ast.args(call)[1:]
    i = 0
    while i < len(words):
        lit = bash_ast.word_string(words[i])
        if lit is None:
            i += 1
            continue
        if lit == "--":
            return
        if lit in ("-o", "+o"):
            yield lit, False, True
            i += 2  ## skip the option NAME argument
            continue
        if len(lit) > 1 and lit[0] in "-+":
            yield lit, True, False
        i += 1


class ErrexitToggle(Rule):
    """R-011: 'set +e' / 'set +o errexit' (or a '+' cluster containing 'e')
    disables errexit -- forbidden. A '+u'/'+x' with no 'e' is not this rule."""

    id = "R-011"
    waiver_tag = "allow-errexit-toggle"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) != "set":
                continue
            words = bash_ast.args(call)[1:]
            for i, word in enumerate(words):
                lit = bash_ast.word_string(word)
                if lit is None or lit == "--" or not lit.startswith("+"):
                    if lit == "--":
                        break
                    continue
                if lit == "+o":
                    nxt = (bash_ast.word_string(words[i + 1])
                           if i + 1 < len(words) else None)
                    if nxt == "errexit":
                        yield _fail(ctx, "R-011", "R-011 errexit toggle", call)
                        break
                elif "e" in lit[1:]:
                    yield _fail(ctx, "R-011", "R-011 errexit toggle", call)
                    break


class SetOptions(Rule):
    """R-013: shell options must be set by long '-o <name>', ONE per line. A short
    enable of errexit/nounset ('set -e', 'set -eu', 'set -euo pipefail') and more
    than one option group on a single 'set' line ('set -o a -o b') are flagged; a
    lone 'set -o <name>', a 'set --' positional form, and a bare 'set -x'/'set -E'
    (no e/u) are spared. Scanning stops at a bare '--' (rest positional)."""

    id = "R-013"
    waiver_tag = "allow-short-set"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) != "set":
                continue
            short_eu = False
            o_groups = 0
            for lit, is_short, is_o in _set_option_words(call):
                if is_o:
                    o_groups += 1
                elif is_short and lit[0] == "-" and (
                        "e" in lit[1:] or "u" in lit[1:]):
                    short_eu = True
            if short_eu or o_groups > 1:
                yield _fail(
                    ctx, "R-013",
                    "R-013 set options long-form one-per-line", call)


## A shellcheck directive comment: '# shellcheck <body>'. bash_ast.comments()
## yields the text AFTER the '#', so the leading '#' is not in the match.
_SC_SOURCE = re.compile(r'^\s*shellcheck\s+source=(\S+)')
_SC_DEVNULL = re.compile(r'^\s*shellcheck\s+source=/dev/null(?:\s|$)')
_SC_SC1091 = re.compile(r'^\s*shellcheck\s+disable=(?:[A-Z0-9]+,)*SC1091(?![0-9])')


class ShellcheckSourceRelative(Rule):
    """R-080: a 'shellcheck source=' directive path must be script-RELATIVE
    (start with './' or '../') so shellcheck resolves it from the script's own
    directory. An absolute or bare path is flagged."""

    id = "R-080"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for comment in bash_ast.comments(ctx.tree):
            match = _SC_SOURCE.match(comment.get("Text", ""))
            if match and not match.group(1).startswith("."):
                yield _fail(
                    ctx, "R-080",
                    "R-080 shellcheck source= must be relative (start with ./ "
                    "or ../)", comment.get("Pos"))


class ShellcheckSourceDevNull(Rule):
    """R-081: 'shellcheck source=/dev/null' silences SC1091 without letting
    shellcheck follow the real file -- point source= at the file instead."""

    id = "R-081"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for comment in bash_ast.comments(ctx.tree):
            if _SC_DEVNULL.match(comment.get("Text", "")):
                yield _fail(ctx, "R-081", "R-081 source=/dev/null",
                            comment.get("Pos"))


class Sc1091Disable(Rule):
    """R-085 (advisory): a '# shellcheck disable=...SC1091...' on a line
    IMMEDIATELY above or below a '# shellcheck source=' directive is DEAD --
    shellcheck follows the source and never raises SC1091. A disable with no
    adjacent source= is load-bearing (a runtime path shellcheck cannot follow),
    so it is spared. Advisory, waivable with 'allow-sc1091-disable'. The location
    is embedded in the message because a NOTE carries no separate location field."""

    id = "R-085"
    waiver_tag = "allow-sc1091-disable"
    advisory = True

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        comments = list(bash_ast.comments(ctx.tree))
        source_lines = set()
        for comment in comments:
            if _SC_SOURCE.match(comment.get("Text", "")):
                line = (comment.get("Pos") or {}).get("Line")
                if line is not None:
                    source_lines.add(line)
        for comment in comments:
            if not _SC_SC1091.match(comment.get("Text", "")):
                continue
            line = (comment.get("Pos") or {}).get("Line")
            if line is None:
                continue
            if (line - 1) in source_lines or (line + 1) in source_lines:
                directive = ("#" + comment.get("Text", "")).strip()
                yield _note(
                    ctx, "R-085",
                    "R-085 dead SC1091 disable adjacent to a source= directive "
                    "at '%s:%d': %s" % (ctx.path, line, directive), line)


## shfmt case-terminator operator constant for ';;' (DblSemicolon). ';&' and
## ';;&' fall-through terminators are different ops and are not this rule.
_CASE_DBLSEMI = 30


class DoubleSemi(Rule):
    """R-070: a case-arm ';;' terminator ENDING a line must be on its own line,
    not glued to the arm's last command ('foo ;;' / 'foo;;' as the whole line).
    Read from the CaseItem terminator position in the AST, so a ';;' inside a
    string or a '#' comment is never a terminator. The fully-inline arm form
    'case ... ) cmd ;; esac' (real code AFTER the ';;' on the same physical line)
    is EXEMPT (style guide): the rule only targets a ';;' at END-OF-LINE, matching
    the former EOL grep -- so a compact one-line case stays as-is."""

    id = "R-070"

    def applies(self, ctx):
        return super().applies(ctx)

    @staticmethod
    def _at_end_of_line(data, offset):
        """True if only whitespace (or a '#' comment) follows the ';;' whose
        first byte is at OFFSET, up to the newline. Real code after it (the
        fully-inline 'esac' / next pattern) means the ';;' is not end-of-line."""
        index = offset + 2  ## past the ';;'
        length = len(data)
        while index < length and data[index:index + 1] != b"\n":
            char = data[index:index + 1]
            if char in (b" ", b"\t", b"\r"):
                index += 1
                continue
            return char == b"#"  ## a trailing comment counts as end-of-line
        return True

    def _glued_items(self, ctx, data):
        for clause in bash_ast.nodes_of_type(ctx.tree, "CaseClause"):
            for item in clause.get("Items", []):
                if item.get("Op") != _CASE_DBLSEMI:
                    continue
                pos = item.get("OpPos") or {}
                op_line = pos.get("Line")
                op_offset = pos.get("Offset")
                stmts = item.get("Stmts") or []
                if op_line is None or op_offset is None or not stmts:
                    continue
                if (stmts[-1].get("End") or {}).get("Line") != op_line:
                    continue  ## ';;' already on its own line
                if self._at_end_of_line(data, op_offset):
                    yield item

    def detect(self, ctx):
        data = ctx.source.encode("utf-8")
        for item in self._glued_items(ctx, data):
            yield _fail(ctx, "R-070", "R-070 ';;' on own line", item.get("OpPos"))


class FlowChaining(Rule):
    """R-074: a control-flow keyword (break / continue / return) must not be
    glued onto a preceding statement with ';' ('foo; break'). Detected from a
    COMMAND-position break/continue/return (so a 'return_value=...' assignment is
    not it) whose keyword is preceded, on the same physical line, by a ';'. exit
    is deliberately excluded (a frequent separator inside awk/sed program strings
    and the tolerated one-liner guard idiom)."""

    id = "R-074"
    _KEYWORDS = frozenset({"break", "continue", "return"})

    def applies(self, ctx):
        return super().applies(ctx)

    def _chained_calls(self, ctx, data):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) not in self._KEYWORDS:
                continue
            start = (call.get("Pos") or {}).get("Offset")
            if start is None:
                continue
            ## Walk back over HORIZONTAL whitespace only (never a newline, so a
            ## keyword on its own line whose previous line ends in ';' is spared).
            i = start - 1
            while i >= 0 and data[i:i + 1] in (b" ", b"\t"):
                i -= 1
            if i >= 0 and data[i:i + 1] == b";":
                yield call, i

    def detect(self, ctx):
        data = ctx.source.encode("utf-8")
        for call, _semi in self._chained_calls(ctx, data):
            yield _fail(
                ctx, "R-074", "R-074 ';'-chained break/continue/return", call)


class InterpreterPrepend(Rule):
    """R-102: run a script by its shebang, not by prepending 'bash'/'sh' ('bash
    ci/build', 'sh foo.sh'). Command position comes from the AST, so 'du -sh
    /path' (command is du) and 'wrapper.sh /etc/x' (command is wrapper.sh) are
    not mistaken for an 'sh' prepend. Flags when the FIRST operand is a script:
    a literal path with a '.sh'/'.bsh'/'.bash' extension or containing a '/'. A
    flag ('bash -c', 'bash --norc') or a variable/quoted operand is spared.

    (Shell files only for now; the embedded shell of a workflow 'run:' block --
    the former grep also scanned .yml -- is a follow-up on WorkflowInlineShell.)"""

    id = "R-102"
    _SCRIPT_EXT = (".sh", ".bsh", ".bash")
    ## Long options whose VALUE is the next word (a config path, not the script).
    _VALUE_OPTS = frozenset({"--rcfile", "--init-file"})

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) not in ("bash", "sh"):
                continue
            ## Skip leading OPTIONS to reach the script operand, so 'bash -x
            ## build.sh' is caught, not just 'bash build.sh'. Handle the forms
            ## that would otherwise misfire: '--' ends options (the next word IS
            ## the script); a '-c' cluster is an inline PROGRAM (R-192) and a
            ## '-n' cluster is a noexec syntax-check -- neither runs the script;
            ## '-s' reads the script from STDIN; '-o'/'-O'/'--rcfile' take a
            ## VALUE word that is not the script.
            script = None
            skip_next = False
            after_ddash = False
            for word in bash_ast.args(call)[1:]:
                operand = bash_ast.word_string(word)
                if operand is None:
                    break  ## a variable/expanded operand -> spared
                if skip_next:
                    skip_next = False
                    continue
                if after_ddash:
                    script = operand
                    break
                if operand == "--":
                    after_ddash = True
                    continue
                if operand[:1] in ("-", "+") and len(operand) > 1:
                    cluster = operand[1:]
                    is_long = operand[:2] in ("--", "++")
                    if not is_long and ("c" in cluster or "n" in cluster):
                        script = None
                        break
                    if not is_long and "s" in cluster:
                        break  ## '-s' -> script comes from stdin, no file
                    ## '-o'/'-O' take a VALUE; in a short cluster the FIRST of them
                    ## consumes the REST as its argument, so the value is the NEXT
                    ## word only when it is the cluster's LAST char ('-eo pipefail'),
                    ## never when a value is attached ('-oe' == -o with value 'e').
                    o_pos = next((i for i, ch in enumerate(cluster)
                                  if ch in "oO"), -1)
                    if operand in self._VALUE_OPTS \
                            or (o_pos != -1 and o_pos == len(cluster) - 1):
                        skip_next = True
                    continue
                script = operand
                break
            if script is not None and (
                    script.endswith(self._SCRIPT_EXT) or "/" in script):
                yield _fail(ctx, "R-102",
                            "R-102 interpreter prepend (use shebang)", call)


class TrapInline(Rule):
    """R-051: a 'trap' handler must be a named function, not an inline command
    string ('trap "rm -f ${t}" EXIT'). Spared: an unquoted name ('trap cleanup
    EXIT'), an empty handler ('trap "" EXIT' clears it), and the parameterized
    dispatch idiom -- a quoted string that is exactly ONE name (function or
    '${var}') followed by VARIABLE-expansion arguments only ('trap "$h $sig"
    "$sig"'), since bash passes the handler no signal argument. A literal
    argument anywhere ('${cmd} -f x') keeps it flagged. Scoped to real 'trap'
    calls from the AST, so a 'trap' in a comment or a string is not a live trap."""

    id = "R-051"
    ## Opening quote, one name (function or ${var}/$var/name), then variable
    ## arguments only, then the matching closing quote. Anchored to the WHOLE
    ## handler so any literal argument breaks the match and the trap is flagged.
    _ALLOW = re.compile(
        r"""^(['"])(?:\$\{[A-Za-z_]\w*\}|\$?[A-Za-z_]\w*)"""
        r"""(?:\s+\$\{?[A-Za-z_]\w*\}?)*\1$""")

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) != "trap":
                continue
            call_args = bash_ast.args(call)
            if len(call_args) < 2:
                continue
            raw = bash_ast.word_source(call_args[1], ctx.source)
            if not raw or raw[0] not in "'\"":
                continue  ## unquoted -> a named function/reset, spared
            if len(raw) >= 2 and not raw[1:-1]:
                continue  ## empty handler ('' / "") clears the trap, spared
            if self._ALLOW.match(raw):
                continue  ## name + variable args -> dispatch idiom, spared
            yield _fail(ctx, "R-051", "R-051 trap inline command", call)


def _printf_calls(tree):
    """(stmt, call) for every COMMAND-position printf. From the AST, so a printf
    inside a single-quoted awk program, inside another printf's data string, or
    in a '#' comment is not a shell printf and is never yielded -- the quote/
    comment tracking the former line walker hand-rolled is free here."""
    for stmt in bash_ast.iter_stmts(tree):
        cmd = stmt.get("Cmd")
        if (isinstance(cmd, dict) and cmd.get("Type") == "CallExpr"
                and bash_ast.command_name(cmd) == "printf"):
            yield stmt, cmd


def _format_interpolates(raw):
    """True if a printf format word's SOURCE can interpolate a '$' or backtick --
    one appears OUTSIDE a single-quoted '...' segment. Single quotes suppress ALL
    expansion and cannot be escaped inside, so a '$' within '...' is literal;
    adjacent segments simply concatenate ('x''$y' is two literal segments, 'x'$y
    interpolates $y). A backslash outside single quotes escapes the next char."""
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "'":
            close = raw.find("'", i + 1)
            i = n if close == -1 else close + 1
        elif c == "\\":
            i += 2
        elif c in "$`":
            return True
        else:
            i += 1
    return False


def _printf_format(call, source):
    """(inner, single_quoted) for a printf CALL's format argument, or (None,
    False) if it has none. The format operand is found via the SHARED robust option
    scan (h.printf_format_word, the same scan R-063 uses for the -v target): '-v
    NAME', attached '-vNAME', a quoted/escaped '-v', and '--' are all skipped -- so
    a spelled '-v' can no longer smuggle the real format past R-030. inner is the
    format with its surrounding quotes stripped; single_quoted marks a format that
    cannot interpolate (see the quote-segment scan below)."""
    word = h.printf_format_word(call)
    if word is None:
        return None, False
    raw = bash_ast.word_source(word, source)
    if not raw:
        return None, False
    ## Strip the outer quotes for the display / allowed-verb comparison when the
    ## whole word is ONE quoted string; a concatenation keeps its raw form.
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        inner = raw[1:-1]
    else:
        inner = raw
    ## single_quoted := the format cannot interpolate. Parse quote SEGMENTS, not the
    ## outer chars: 'x'$name'y' interpolates $name (concatenated UNQUOTED), but
    ## 'x''$name' is two single-quoted segments where $name stays literal.
    return inner, not _format_interpolates(raw)


class BareNewlinePrintf(Rule):
    """R-031: a printf that emits a newline must pass the data explicitly --
    'printf \\n' (newline baked into the format) or a bare 'printf %s\\n' with the
    data argument omitted must be 'printf %s\\n' "". Flags a printf whose format
    is '(%s)?\\n+' and that carries NO data argument (a trailing '#' comment is
    not a data argument)."""

    id = "R-031"
    waiver_tag = "printf-format"
    ## finding is DISPLAYED as the composite "R-030/R-031"; honor that spelling as
    ## an override too, so the tag a user copies from the finding actually works.
    override_ids = ("R-030/R-031",)
    _NEWLINE_ONLY = re.compile(r'^(?:%s)?(?:\\n)+$')

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for _stmt, call in _printf_calls(ctx.tree):
            call_args = bash_ast.args(call)
            fmt_word = h.printf_format_word(call)
            ## Skip when: no format; a '-v' target (writes to a var, emits nothing);
            ## or a DATA argument follows the format. '--' / '-v NAME' are OPTIONS,
            ## not the data arg -- 'printf -- \n' still needs the explicit "" (the old
            ## 'len(args) != 2' missed it by counting '--' as a data argument).
            if fmt_word is None or h.printf_v_target(call) is not None \
                    or call_args[-1] is not fmt_word:
                continue
            inner, _single = _printf_format(call, ctx.source)
            if inner is not None and self._NEWLINE_ONLY.match(inner):
                yield _fail(
                    ctx, "R-030/R-031",
                    'R-030/R-031 newline printf needs explicit "" arg', call)


## A '$' or backtick in a double-quoted / unquoted format is the ONLY way data
## reaches the format at runtime (a '$var' / '$(...)' / '`...`' expansion). A
## format with neither is a fixed literal that interpolates nothing, whatever
## printf verbs it spells. (A backslash-escaped '\$' is still matched -- a rare
## conservative over-flag whose fix is the same trivial single-quote.)
_PRINTF_EXPANSION = re.compile(r'[$`]')


class PrintfFormatString(Rule):
    """R-030: a printf format must not INTERPOLATE data into itself -- data goes
    in the data argument. A format is flagged ONLY when it can interpolate: a
    DOUBLE-quoted or UNQUOTED format containing a '$' or backtick reads a
    '$var' / command substitution straight INTO the format (the injection this
    prevents). A SINGLE-quoted format -- OR any format with no expansion metachar
    (a fixed literal like '%02x', '%(%Y)T', '%-12s') -- interpolates nothing and
    is allowed whatever verbs it uses; the data still goes in the data argument."""

    id = "R-030"
    waiver_tag = "printf-format"
    _ALLOWED = frozenset({
        "%s", "%s\\n", "%s\\0", "%q", "%q\\n", "%b", "%b\\n", "0x%x", "%x"})

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for _stmt, call in _printf_calls(ctx.tree):
            inner, single_quoted = _printf_format(call, ctx.source)
            ## Safe: no format, a single-quoted literal, an allowlisted verb, or a
            ## double/unquoted format with NO '$'/backtick (cannot interpolate).
            if (inner is None or single_quoted or inner in self._ALLOWED
                    or _PRINTF_EXPANSION.search(inner) is None):
                continue
            yield _fail(
                ctx, "R-030",
                "R-030 printf format string must not interpolate data ('$'/'`') "
                "-- put the data in the argument, not the format", call)


class HeaderFirst(Rule):
    """R-002: a '## style-ok:' waiver must sit BELOW the '## Copyright' header,
    not above it. Flag when the first header-comment 'style-ok:' line precedes
    the first '## Copyright' line (both anchored to a real '##' header comment,
    so a mention inside a string or echo does not count)."""

    id = "R-002"
    _STYLE = re.compile(r'^[ \t]*##[ \t]*style-ok:')
    _COPYRIGHT = re.compile(r'^[ \t]*##[ \t]+Copyright')

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        style_line = copyright_line = None
        for number, line in enumerate(ctx.source.split("\n"), 1):
            if style_line is None and self._STYLE.match(line):
                style_line = number
            if copyright_line is None and self._COPYRIGHT.match(line):
                copyright_line = number
        if (style_line is not None and copyright_line is not None
                and style_line < copyright_line):
            yield model.fail(
                "R-002",
                "R-002 header: '## style-ok' at line %d precedes '## Copyright' "
                "at line %d; move the waiver below the header"
                % (style_line, copyright_line), ctx.path, style_line)


## The seven strict-mode directives R-010 requires, matched WHOLE-LINE at column
## zero (a directive repeated seven times must not satisfy the block).
_STRICT_DIRECTIVES = (
    "set -o errexit", "set -o nounset", "set -o pipefail", "set -o errtrace",
    "shopt -s inherit_errexit", "shopt -s shift_verbose", "export LC_ALL=C",
)
_STRICT_HEADER_LINES = 160
## A real was_executed()/was_sourced() guard CALL (command position), not a
## comment or an assignment ('was_executed=1') or a mention ('${was_sourced}').
## Matched per code-only LINE (comments pre-stripped by code_only_lines), so a
## '${var#pat}' '#' earlier on the line no longer hides the guard call.
_SOURCE_GUARD = re.compile(
    r'(?:^|[ \t;&|!(])(?:was_executed|was_sourced)(?:[ \t;&|)]|$)')
_GUARD_ERREXIT = re.compile(r'^[ \t]+set -o errexit[ \t]*$', re.MULTILINE)
_INHERIT_ERREXIT = re.compile(r'^[ \t]*shopt -s inherit_errexit[ \t]*$',
                              re.MULTILINE)
_SHIFT_VERBOSE = re.compile(r'^[ \t]*shopt -s shift_verbose[ \t]*$',
                            re.MULTILINE)
_INDENTED_LC_ALL = re.compile(r'^[ \t]+export LC_ALL=C[ \t]*$', re.MULTILINE)


class StrictModeBlock(Rule):
    """R-010: an executed script must enable the seven-directive strict-mode
    block (set -o errexit/nounset/pipefail/errtrace, shopt -s inherit_errexit/
    shift_verbose, export LC_ALL=C) at column zero in its first 160 lines.

    Exempt: '## style-ok: no-strict' (a sourced-only fragment must not leak
    strict mode into the sourcing shell). Source-able DUAL-mode scripts keep zero
    column-zero strict lines and guard the block behind a was_executed()/
    was_sourced() check -- those are exempt from the all-seven rule, but when the
    guarded block DOES enable errexit (indented 'set -o errexit'), the indented
    shopt half + 'export LC_ALL=C' are still enforced (they are the copied-in
    lines authors forget). A partial top-level block (1..6) is not clean and
    stays subject to the all-seven check."""

    id = "R-010"
    waiver_tag = "no-strict"

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        source = ctx.source
        header = "\n".join(source.split("\n")[:_STRICT_HEADER_LINES])
        header_lines = set(line.strip("\r") for line in header.split("\n"))
        present = sum(1 for directive in _STRICT_DIRECTIVES
                      if directive in header_lines)
        guarded = any(_SOURCE_GUARD.search(line)
                      for line in h.code_only_lines(source, ctx.tree))
        if present == 0 and guarded:
            ## Source-able guarded script: exempt from all-seven. Enforce the
            ## indented shopt half + export only when the guard enables errexit.
            if _GUARD_ERREXIT.search(source):
                missing = []
                if not _INHERIT_ERREXIT.search(source):
                    missing.append("shopt -s inherit_errexit")
                if not _SHIFT_VERBOSE.search(source):
                    missing.append("shopt -s shift_verbose")
                if not _INDENTED_LC_ALL.search(source):
                    missing.append("export LC_ALL=C")
                if missing:
                    yield model.fail(
                        "R-010",
                        "R-010 shopt block: source-able guarded script enables "
                        "errexit but its was_executed block is missing: "
                        + ", ".join(missing), ctx.path, 1)
            return
        if present < len(_STRICT_DIRECTIVES):
            yield model.fail(
                "R-010",
                "R-010 strict-mode block: only %d/%d distinct strict-mode "
                "directives in the first %d lines"
                % (present, len(_STRICT_DIRECTIVES), _STRICT_HEADER_LINES),
                ctx.path, 1)


class TmpHardcode(Rule):
    """R-170: a hardcoded '/tmp' path (use the ${TMP} temp dir). '/tmp' as an
    absolute path -- not preceded by a path/word char (so 'debian/tmp',
    '${d}/tmp', '~/tmp' are subdirectories, not the system path) and not followed
    by one (so '/tmpfs', '/tmp.bak' are other names; a following '/' IS a real
    path). Comment lines are skipped. The temp-dir variable INITIALISATIONS
    ('TMP=/tmp', 'export TMPDIR=/tmp', the bwrap '--setenv TMPDIR /tmp'), the one
    place the literal must appear, are spared -- whole-line, so a line carrying
    both an init and a real hardcode is a narrow accepted residual."""

    id = "R-170"
    waiver_tag = "no-tmp-hardcode"
    ## No '^[^#]*' comment skip here -- comments are stripped up front by
    ## code_only_lines (AST-aware), so a '${var#pat}' '#' no longer hides a real
    ## '/tmp' later on the same line.
    _MATCH = re.compile(
        r'(?:^|[^A-Za-z0-9._/}~)])/tmp(?:$|[^A-Za-z0-9._-])')
    _SPARE = re.compile(
        r"(?:^|[ \t;&|(:])(?:export|readonly|local|declare)?[ \t]*"
        r"(?:TMP|TMPDIR|TEMP|TEMPDIR)=['\"]?/tmp['\"]?(?:[ \t;&|)]|$)"
        r"|--setenv[ \t]+(?:TMP|TMPDIR|TEMP|TEMPDIR)[ \t]+"
        r"['\"]?/tmp['\"]?(?:[ \t;&|)]|$)")

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for number, line in enumerate(
                h.code_only_lines(ctx.source, ctx.tree), 1):
            if self._MATCH.search(line) and not self._SPARE.search(line):
                yield model.fail(
                    "R-170", "R-170 hardcoded /tmp (use ${TMP})", ctx.path,
                    number)


class HelpFromComments(Rule):
    """R-153: never build help/usage by scraping the script's OWN comments (e.g.
    a grep of a '^##' anchor over "$0"). Flags a NON-comment line carrying BOTH a
    '^#'/'^##' anchor literal AND a '$0' / '${BASH_SOURCE' self-reference (in
    either order). A plain 'dirname "${BASH_SOURCE[0]}"' or 'head "$0"' has no
    anchor and is spared; a comment line naming the anti-pattern is spared."""

    id = "R-153"
    _ANCHOR_THEN_SELF = re.compile(r'\^##?.*(?:\$0|\$\{?BASH_SOURCE)')
    _SELF_THEN_ANCHOR = re.compile(r'(?:\$0|\$\{?BASH_SOURCE).*\^##?')

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        for number, line in enumerate(ctx.source.split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue
            if (self._ANCHOR_THEN_SELF.search(line)
                    or self._SELF_THEN_ANCHOR.search(line)):
                yield model.fail(
                    "R-153", "R-153 help scraped from comments", ctx.path,
                    number)


## git global options (before the subcommand) whose VALUE is the next word.
_GIT_VALUE_OPTS = frozenset({
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
    "--config-env"})


def _git_subcommand_index(call_args):
    """Index of git's SUBCOMMAND, skipping global options before it ('git -C
    dir check-ref-format' puts it at 3, not 1). None if it cannot be resolved
    (a quoted/expanded option word)."""
    index = 1
    while index < len(call_args):
        word = bash_ast.word_string(call_args[index])
        if word is None:
            return None
        if not word.startswith("-"):
            return index
        if word in _GIT_VALUE_OPTS:
            index += 2  ## the option AND its separate value word
        else:
            index += 1  ## a flag, or an attached '--opt=value'
    return None


class DashDashDenylist(Rule):
    """R-062: a standalone '--' passed to a tool that does NOT accept the
    end-of-options marker (it becomes a literal operand and misbehaves).
    Denylisted callers: 'git check-ref-format' and 'stcat'. fix() drops the '--'.
    Command position and the git subcommand are read from the AST, so a '--' that
    is a data operand of some OTHER command on the line is not mistaken for one of
    these (the former line-regex could not tell them apart)."""

    id = "R-062"
    ## (command-name, required-subcommand-or-None) that reject '--'.
    _DENY = (("git", "check-ref-format"), ("stcat", None))

    def applies(self, ctx):
        return super().applies(ctx)

    def _denied_dashdash(self, call):
        """The standalone '--' word of a denylisted call, or None. A '--' is
        standalone when the whole word is exactly '--' (so '--branch' is spared)."""
        name = bash_ast.command_name(call)
        call_args = bash_ast.args(call)
        for deny_name, sub in self._DENY:
            if name != deny_name:
                continue
            start = 1
            if sub is not None:
                idx = (_git_subcommand_index(call_args)
                       if deny_name == "git" else 1)
                if idx is None or not (idx < len(call_args)
                        and bash_ast.word_string(call_args[idx]) == sub):
                    return None
                start = idx + 1
            for word in call_args[start:]:
                if bash_ast.word_string(word) == "--":
                    return word
            return None
        return None

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if self._denied_dashdash(call) is not None:
                yield _fail(ctx, "R-062",
                            "R-062 '--' passed to a tool that rejects it", call)

    def fix(self, ctx):
        data = ctx.source.encode("utf-8")
        for call in h.editable_calls(ctx.tree):
            word = self._denied_dashdash(call)
            if word is None:
                continue
            start, end = bash_ast.word_span(word)
            ## Drop one leading space with the '--' so no double space is left.
            if start > 0 and data[start - 1:start] == b" ":
                start -= 1
            yield Edit(start, end, "", "R-062")


class EmptyArrayGuard(Rule):
    """R-026: the obsolete empty-array guard '${name[@]+"${name[@]}"}' (a
    workaround for bash < 4.4's nounset expanding an empty '[@]' to an error). On
    bash 4.4+ '"${name[@]}"' is safe, so the '+alternate' guard is dead syntax.
    Flags a '${name[@]+...}' (a bare '+' immediately after '[@]', NOT ':+' which
    is a different, still-meaningful operator). Not auto-fixed: collapsing the
    guard to its inner expansion needs the inner text, which is not always the
    plain '${name[@]}' -- left for a human."""

    id = "R-026"
    ## ${ name [@] + ...} -- bare '+' right after '[@]', no ':' before it.
    _GUARD = re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*\[@\]\+')

    def applies(self, ctx):
        return super().applies(ctx)

    def detect(self, ctx):
        ## The guard lives INSIDE a word's parameter expansion; shfmt keeps the
        ## raw '${...}' text, so match it on the source but only where a real
        ## expansion node sits (never in a comment or a single-quoted literal).
        data = ctx.source.encode("utf-8")
        for node in bash_ast.nodes_of_type(ctx.tree, "ParamExp"):
            pos = node.get("Pos") or {}
            start_off = pos.get("Offset")
            end_off = (node.get("End") or {}).get("Offset")
            if start_off is None or end_off is None:
                continue
            raw = data[start_off:end_off]
            if self._GUARD.match(raw.decode("utf-8", "surrogateescape")):
                yield _fail(ctx, "R-026",
                            "R-026 obsolete empty-array guard (bash 4.4+; drop "
                            "the +alternate on [@])", pos)


## In gate dispatch order (unchanged from the former SHELL_RULES tuple).
RULES = (
    ShellInlineShellC(),
    ErrexitToggle(),
    SetOptions(),
    ShellcheckSourceRelative(),
    ShellcheckSourceDevNull(),
    Sc1091Disable(),
    DoubleSemi(),
    FlowChaining(),
    InterpreterPrepend(),
    BareNewlinePrintf(),
    PrintfFormatString(),
    HeaderFirst(),
    StrictModeBlock(),
    TrapInline(),
    TmpHardcode(),
    HelpFromComments(),
    DashDashDenylist(),
    EmptyArrayGuard(),
    UnauthorizedSkip(),
    CommandV(),
    Exec(),
    Rm(),
    Echo(),
    PrintfVUnchecked(),
    NullCommand(),
    GrepQuiet(),
    MkdirTmpMode(),
    InlineInterpreter(),
    PythonDashDashScript(),
    TimeoutKillAfter(),
    AptGet(),
    Dpkg(),
    AllowDowngrades(),
    LintianDisabled(),
)
