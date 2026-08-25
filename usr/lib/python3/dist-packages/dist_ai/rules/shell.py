## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shell-structure rules, each a Rule object. detect() answers a command-position
/ quote / heredoc question from the shfmt AST; the three mechanically-fixable
rules (R-161, R-172, R-200) also carry fix(), sharing the very constants their
detect() uses -- so the detector and the rewriter cannot drift."""

import re

from dist_ai import bash_ast
from dist_ai import model
from dist_ai.model import Edit, Rule
from dist_ai.rules import _helpers as h

## Self-exemption: the legacy bash gate carries every forbidden token in its own
## regex/doc text. It is a shell file, so the shell rules would flag it; skip it
## by path. (Retired with the gate in the final migration phase.)
GATE_PATH = "usr/bin/pre-push-static"


def _fail(ctx, rule, message, node):
    return model.fail(rule, message, ctx.path, node)


def _note(ctx, rule, message, line):
    return model.note(rule, message, ctx.path, line)


## --- command-position rules -----------------------------------------------


class CommandV(Rule):
    """R-090: 'command -v' (prefer helper-scripts 'has' / 'type -P')."""

    id = "R-090"
    waiver_tag = "no-has"
    _exempt = (GATE_PATH,
               ".github/actions/install-deps/install-helper-scripts.sh")

    def applies(self, ctx):
        return (super().applies(ctx)
                and not ctx.is_posix_sh
                and ctx.path not in self._exempt)

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) != "command":
                continue
            first = bash_ast.args(call)[1:2]
            ## word_string (quote-aware), not word_lit: 'command "-v" foo' IS
            ## 'command -v foo'. Declining quoted words is the rewriters' concern.
            if first and bash_ast.word_string(first[0]) == "-v":
                yield _fail(ctx, "R-090", "R-090 command -v", call)


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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
            scope_start = h.enclosing_scope_start(tree, offset)
            covered = set()
            for guard_offset, guard_scope, guard_params in guards:
                if guard_scope == scope_start and guard_offset < offset:
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
        return super().applies(ctx) and ctx.path != GATE_PATH

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

## A short '-m' carrying a jammed numeric mode ('-m700').
MKDIR_M_JAMMED = re.compile(r'^-m([0-7]{3,4})$')

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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
                        start, end = bash_ast.word_span(word)
                        yield Edit(start, end, "--mode=" + jammed.group(1),
                                   "R-172")
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


class UnauthorizedSkip(Rule):
    """R-220: a test SKIP ('exit 77'/'return 77') must be authorized by a
    per-skip '## style-ok: allow-skip: <why>' waiver on the line or the line
    above. A required-dep absence must be 'exit 1' (FATAL), never a skip."""

    id = "R-220"

    def detect(self, ctx):
        lines = ctx.source.split("\n")
        for call in bash_ast.call_exprs(ctx.tree):
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
        return (super().applies(ctx) and ctx.path != GATE_PATH
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
        return (super().applies(ctx) and ctx.path != GATE_PATH
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
                    if bash_ast.word_lit(args_after[index]) == "dpkg":
                        start = index + 1
                        break
            state_changing = any(
                bash_ast.word_lit(word) in DPKG_STATE_ACTIONS
                for word in args_after[start:])
            if state_changing:
                line = call["Pos"]["Line"]
                yield _note(
                    ctx, "R-211",
                    "R-211 (ADVISORY): state-changing 'dpkg' in command "
                    "position -- prefer 'dpkg-noninteractive' ('## style-ok: "
                    "allow-dpkg' to silence): '%s:%d'" % (ctx.path, line), line)


class AllowDowngrades(Rule):
    """R-212: '--allow-downgrades' is forbidden."""

    id = "R-212"
    waiver_tag = "allow-downgrades"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.path != GATE_PATH

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            for word in bash_ast.args(call):
                if bash_ast.word_string(word) == "--allow-downgrades":
                    yield _fail(ctx, "R-212",
                                "R-212 --allow-downgrades forbidden", word)


class LintianDisabled(Rule):
    """R-213: 'make_use_lintian=false' disables the lintian gate; forbidden
    without authorization -- fix the lintian findings instead."""

    id = "R-213"
    waiver_tag = "allow-lintian-disable"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.path != GATE_PATH

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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
    """R-070: a case-arm ';;' terminator must be on its own line, not glued to the
    arm's last command ('foo ;;' / 'foo;;'). Read from the CaseItem terminator
    position in the AST -- flag when the ';;' shares a line with the arm's last
    statement -- so a ';;' inside a string or a '#' comment is never mistaken for
    a terminator."""

    id = "R-070"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.path != GATE_PATH

    def _glued_items(self, ctx):
        for clause in bash_ast.nodes_of_type(ctx.tree, "CaseClause"):
            for item in clause.get("Items", []):
                if item.get("Op") != _CASE_DBLSEMI:
                    continue
                op_line = (item.get("OpPos") or {}).get("Line")
                stmts = item.get("Stmts") or []
                if op_line is None or not stmts:
                    continue
                if (stmts[-1].get("End") or {}).get("Line") == op_line:
                    yield item

    def detect(self, ctx):
        for item in self._glued_items(ctx):
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
        return super().applies(ctx) and ctx.path != GATE_PATH

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

    def applies(self, ctx):
        return super().applies(ctx) and ctx.path != GATE_PATH

    def detect(self, ctx):
        for call in bash_ast.call_exprs(ctx.tree):
            if bash_ast.command_name(call) not in ("bash", "sh"):
                continue
            call_args = bash_ast.args(call)
            if len(call_args) < 2:
                continue
            operand = bash_ast.word_string(call_args[1])
            if operand is None or operand.startswith("-"):
                continue  ## a variable/expanded operand, or a flag -> spared
            if operand.endswith(self._SCRIPT_EXT) or "/" in operand:
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
        return super().applies(ctx) and ctx.path != GATE_PATH

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


class HeaderFirst(Rule):
    """R-002: a '## style-ok:' waiver must sit BELOW the '## Copyright' header,
    not above it. Flag when the first header-comment 'style-ok:' line precedes
    the first '## Copyright' line (both anchored to a real '##' header comment,
    so a mention inside a string or echo does not count)."""

    id = "R-002"
    _STYLE = re.compile(r'^[ \t]*##[ \t]*style-ok:')
    _COPYRIGHT = re.compile(r'^[ \t]*##[ \t]+Copyright')

    def applies(self, ctx):
        return super().applies(ctx) and ctx.path != GATE_PATH

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
## Matched per LINE (like the bash grep), so '[^#]*' never crosses a newline.
_SOURCE_GUARD = re.compile(
    r'^[^#]*(?:^|[ \t;&|!(])(?:was_executed|was_sourced)(?:[ \t;&|)]|$)')
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
        return super().applies(ctx) and ctx.path != GATE_PATH

    def detect(self, ctx):
        source = ctx.source
        header = "\n".join(source.split("\n")[:_STRICT_HEADER_LINES])
        header_lines = set(line.strip("\r") for line in header.split("\n"))
        present = sum(1 for directive in _STRICT_DIRECTIVES
                      if directive in header_lines)
        guarded = any(_SOURCE_GUARD.search(line)
                      for line in source.split("\n"))
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
    _MATCH = re.compile(
        r'^[^#]*(?:^|[^A-Za-z0-9._/}~)])/tmp(?:$|[^A-Za-z0-9._-])')
    _SPARE = re.compile(
        r"(?:^|[ \t;&|(:])(?:export|readonly|local|declare)?[ \t]*"
        r"(?:TMP|TMPDIR|TEMP|TEMPDIR)=['\"]?/tmp['\"]?(?:[ \t;&|)]|$)"
        r"|--setenv[ \t]+(?:TMP|TMPDIR|TEMP|TEMPDIR)[ \t]+"
        r"['\"]?/tmp['\"]?(?:[ \t;&|)]|$)")

    def applies(self, ctx):
        return super().applies(ctx) and ctx.path != GATE_PATH

    def detect(self, ctx):
        for number, line in enumerate(ctx.source.split("\n"), 1):
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
        return super().applies(ctx) and ctx.path != GATE_PATH

    def detect(self, ctx):
        for number, line in enumerate(ctx.source.split("\n"), 1):
            if line.lstrip().startswith("#"):
                continue
            if (self._ANCHOR_THEN_SELF.search(line)
                    or self._SELF_THEN_ANCHOR.search(line)):
                yield model.fail(
                    "R-153", "R-153 help scraped from comments", ctx.path,
                    number)


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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
                if not (len(call_args) > 1
                        and bash_ast.word_string(call_args[1]) == sub):
                    return None
                start = 2
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
        return super().applies(ctx) and ctx.path != GATE_PATH

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
