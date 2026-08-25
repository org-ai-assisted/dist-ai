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
            if target_params and target_params <= covered:
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
                        if mode_lit and re.fullmatch(r'[0-7]{3,4}', mode_lit):
                            start, _ = bash_ast.word_span(word)
                            _, end = bash_ast.word_span(mode_word)
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
        ## embedded_*: also catch a shell '-c' behind a wrapper ('ssh host --
        ## bash -lc PROG'), which is an inline program just the same.
        for call, _program, line_count in h.embedded_shell_c_programs(
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
        for call in bash_ast.call_exprs(ctx.tree):
            for assign in bash_ast.assigns(call):
                if bash_ast.assign_name(assign) == "make_use_lintian" \
                        and bash_ast.word_string(
                            bash_ast.assign_value(assign)) == "false":
                    yield _fail(
                        ctx, "R-213",
                        "R-213 lintian disabled (make_use_lintian=false) "
                        "without authorization", assign)


## In gate dispatch order (unchanged from the former SHELL_RULES tuple).
RULES = (
    ShellInlineShellC(),
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
