## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Config-hosted embedded-shell rules: systemd Exec=, apt hooks, cron tables,
workflow YAML 'run:' steps. Each self-selects by file shape and parses the shell
it hosts, so a ';'/'|' inside a nested quote is data, not a separator. These run
over every file (they no-op on a non-matching path) -- detection only, no fix."""

import os
import re
import tempfile

from dist_ai import bash_ast
from dist_ai import context as ctxmod
from dist_ai import model
from dist_ai.model import Rule
from dist_ai.rules import _helpers as h

## An installed python package module: imported, never run, and Debian ships it
## 0644 -- so the shebang rule (R-180) does not apply. Anchored to a real python
## library path so a stray 'usr/bin/dist-packages/tool.py' is NOT exempted.
PYTHON_MODULE_PATH = re.compile(
    r'/lib/python3[^/]*/(?:dist|site)-packages/.*\.py$')

EXEC_DIRECTIVE = re.compile(r'^[ \t]*(Exec[A-Za-z]*)=(.*)$', re.MULTILINE)
## apt config-tree keys whose LAST component is one of these run their value list
## via 'sh -c' (case-insensitive, as apt.conf names are).
_APT_HOOK_NAMES = frozenset(
    ("pre-invoke", "post-invoke", "pre-install-pkgs"))
CRON_ENV = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*[ \t]*=')


def _note(ctx, rule, message):
    return model.note(rule, message, ctx.path, 1)


class SystemdUnit(Rule):
    """R-191: a systemd unit must not embed a multi-statement shell script in an
    'Exec*=' directive (strict: ';', a pipe, '&&'/'||', a control keyword, or a
    directive spanning physical lines)."""

    id = "R-191"

    def detect(self, ctx):
        source = ctx.source
        path = ctx.path
        if path.endswith(".md") or not EXEC_DIRECTIVE.search(source) \
                or "Exec" not in source:
            return
        if ctx.has_config_waiver("allow-embedded-script"):
            yield _note(ctx, "R-191",
                        "R-191 skipped: 'style-ok: allow-embedded-script' "
                        "waiver in '%s'" % path)
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
            programs = list(h.shell_c_programs(vtree, value))
            if not programs:
                continue
            multi = spanned or any(
                h.embeds_multi_statement(h.unquote(program_text), strict=True)
                for _call, program_text, _lc in programs)
            if multi:
                yield model.fail(
                    "R-191",
                    "R-191 systemd unit embeds a multi-statement shell script "
                    "in %s; move the logic to a dedicated script (shebang) and "
                    "call it" % directive, path, start)


## POLICY: do NOT over-invest in apt.conf parsing. apt_pkg (apt's own parser) is
## the authority -- match its behaviour, do not hand-roll or re-model apt.conf
## grammar. Correctness here is BOUNDED and IMPERFECT-ON-PURPOSE: a novel grammar
## corner is delegated to apt_pkg, never chased with another regex/scanner rule.
## The hand-rolled scanner this replaced burned many review rounds on one edge at
## a time (no-space, comments, '::', concat, escapes, case, unquoted); that dead
## end is closed. Extend only if apt_pkg itself is wrong AND it matters.
def _apt_hook_commands(source):
    """Yield each command an apt hook would run (the 'sh -c' string), parsed with
    apt_pkg -- apt's OWN config parser -- so every quoting, comment, '::'-append,
    unquoted-value, and case rule is handled EXACTLY as apt does. A config apt
    itself rejects (a syntax error) runs no hooks, so it yields nothing. SOURCE is
    written to a private temp file because apt_pkg reads a path. Raises ImportError
    if python3-apt is absent (a required dependency, not a silent skip)."""
    import apt_pkg
    conf = apt_pkg.Configuration()
    handle = tempfile.NamedTemporaryFile(
        "w", prefix="dist-ai-apt-", suffix=".conf", delete=False)
    try:
        handle.write(source)
        handle.close()
        try:
            apt_pkg.read_config_file(conf, handle.name)
        except apt_pkg.Error:
            return
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
    for key in conf.keys():
        if key.rsplit("::", 1)[-1].lower() not in _APT_HOOK_NAMES:
            continue
        items = conf.value_list(key)
        if items:
            yield from items
        else:
            ## A hook written as a bare scalar ('Pre-Invoke "a; b";' with no list
            ## braces) has an empty value_list; fall back to its scalar so such a
            ## form is still checked (fail-safe -- a multi-statement one flags).
            scalar = conf.find(key)
            if scalar:
                yield scalar

class AptHook(Rule):
    """R-194: an apt hook ('Pre-Invoke'/'Post-Invoke'/'Pre-Install-Pkgs') runs
    each value in its list via 'sh -c'; a multi-statement command belongs in a
    script. The value is extracted with apt's own parser (apt_pkg), so quoted,
    unquoted, '::'-appended, commented and odd-case forms are all read the way apt
    runs them -- no hand-rolled grammar to keep chasing edges on."""

    id = "R-194"

    def detect(self, ctx):
        if not ctxmod.is_apt_conf(ctx.path) or ctx.source is None:
            return
        if ctx.has_config_waiver("allow-embedded-script", slashes=True):
            yield _note(ctx, "R-194",
                        "R-194 skipped: 'style-ok: allow-embedded-script' "
                        "waiver in '%s'" % ctx.path)
            return
        for command in _apt_hook_commands(ctx.source):
            if h.embeds_multi_statement(command, strict=False):
                yield model.fail(
                    "R-194",
                    "R-194 apt hook embeds a multi-statement shell command; "
                    "move the logic to a dedicated script (shebang) and "
                    "call it", ctx.path, 1)


class CronTable(Rule):
    """R-195: a cron entry's command field runs via 'sh -c'; a multi-statement
    command belongs in a script."""

    id = "R-195"

    def detect(self, ctx):
        if not ctxmod.is_cron_table(ctx.path):
            return
        if ctx.has_config_waiver("allow-embedded-script"):
            yield _note(ctx, "R-195",
                        "R-195 skipped: 'style-ok: allow-embedded-script' "
                        "waiver in '%s'" % ctx.path)
            return
        for number, line in enumerate(ctx.source.split("\n"), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") \
                    or CRON_ENV.match(stripped):
                continue
            ## A cron command ends at the first UNESCAPED '%'; the rest is stdin.
            command = re.split(r'(?<!\\)%', line, maxsplit=1)[0]
            if h.embeds_multi_statement(command, strict=False):
                yield model.fail(
                    "R-195",
                    "R-195 cron entry embeds a multi-statement shell command; "
                    "move the logic to a dedicated script (shebang) and call it",
                    ctx.path, number)


class WorkflowInlineShell(Rule):
    """R-100: a workflow 'run:' step must not embed a substantial inline shell
    SCRIPT (>5 top-level shell statements). The count comes from a real bash
    parse of the run: body, located via a real YAML parse."""

    id = "R-100"

    def detect(self, ctx):
        if not ctxmod.is_workflow_yaml(ctx.path):
            return
        if ctx.has_config_waiver("allow-inline-shell"):
            yield _note(ctx, "R-100",
                        "R-100 skipped: 'style-ok: allow-inline-shell' waiver "
                        "in '%s'" % ctx.path)
            return
        import yaml
        try:
            root = yaml.compose(ctx.source)
        except (yaml.YAMLError, RecursionError):
            ## PyYAML raises a bare RecursionError (not a YAMLError) on a deeply
            ## nested flow collection -- a crafted workflow must not crash the
            ## whole gate, just decline this rule.
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
                yield model.fail(
                    "R-100",
                    "R-100 workflow embeds an inline shell script (%d "
                    "statements) in a 'run:' step; extract it to a ci/ script "
                    "and call it" % count, ctx.path,
                    key_node.start_mark.line + 1)


def _yaml_run_scalars(node):
    """Yield (key_node, value_node) for every 'run:' mapping entry whose value
    is a scalar, anywhere in the composed YAML NODE."""
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


class PythonShebang(Rule):
    """R-180: a non-empty '.py' file must start with a shebang so it can be run
    directly when debugging (a file with NEITHER a shebang nor '+x' slips past
    both pre-commit-hooks executable checks). An empty file (a zero-byte
    '__init__.py' package marker) and an installed package module are exempt.
    A file-level rule -- it self-selects by path like the config rules and needs
    no shell parse, so it lives in this run-over-every-file bucket."""

    id = "R-180"

    def applies(self, ctx):
        return (super().applies(ctx) and ctx.path.endswith(".py")
                and PYTHON_MODULE_PATH.search(ctx.path) is None)

    def detect(self, ctx):
        if not ctx.source:  ## empty file: package marker, nothing to interpret
            return
        first = ctx.source.split("\n", 1)[0].rstrip("\r")
        if not first.startswith("#!"):
            yield model.fail(
                "R-180", "R-180 python file needs a shebang (and +x)",
                ctx.path, 1)


RULES = (
    SystemdUnit(),
    AptHook(),
    CronTable(),
    WorkflowInlineShell(),
    PythonShebang(),
)
