## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""External-tool check adapters -- rules whose verdict comes from RUNNING another
tool (bash -n, shellcheck) rather than from the shfmt AST. Check-only: an
external tool reports, it does not get a fix().

They run only in the human/check front (Engine's include_external pass), never
the US-delimited '--detect' channel, so a tool's multi-line output is carried in
the finding message without corrupting a machine record. bash -n runs even when
shfmt could not parse the file -- catching the syntax error is the whole point --
so these do not gate on ctx.tree the way the AST rules do."""

import os
import subprocess

from dist_ai import model
from dist_ai.model import ExternalRule


def _have(name):
    """True if NAME is an executable on PATH."""
    return any(
        os.access(os.path.join(directory, name), os.X_OK)
        for directory in os.environ.get("PATH", "").split(os.pathsep)
        if directory)


class BashParse(ExternalRule):
    """'bash -n': the shell must parse. A syntax error fails the gate. bash is
    always present (the strict-mode preamble needs 4.4+), so no skip path."""

    id = "bash-n"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.is_shell

    def detect(self, ctx):
        try:
            proc = subprocess.run(
                ["bash", "-n", "--", ctx.abspath],
                capture_output=True, text=True)
        except OSError:
            return
        if proc.returncode != 0:
            message = "bash -n: '%s' failed to parse" % ctx.path
            if proc.stderr.strip():
                message += "\n" + proc.stderr.rstrip("\n")
            yield model.fail("bash-n", message, ctx.path)


## Kept IDENTICAL to the set ai-review's static reviewer enables, so a file
## cannot be gate-green yet carry findings the reviewer reports.
SHELLCHECK_OPTIONAL = (
    "avoid-nullary-conditions,check-unassigned-uppercase,deprecate-which,"
    "quote-safe-variables,require-variable-braces")


class Shellcheck(ExternalRule):
    """'shellcheck --external-sources' with the ai-review-aligned optional
    checks. '--source-path=SCRIPTDIR' resolves a '# shellcheck source=' path
    relative to the SCRIPT's own directory (every such directive here is written
    script-relative). Fail-open when shellcheck is absent (a bare git-hook run
    without it installed must still commit)."""

    id = "shellcheck"

    def applies(self, ctx):
        return super().applies(ctx) and ctx.is_shell

    def detect(self, ctx):
        if not _have("shellcheck"):
            yield model.note(
                "shellcheck",
                "shellcheck not on PATH; skipping (apt-get install shellcheck)")
            return
        try:
            proc = subprocess.run(
                ["shellcheck", "--external-sources", "--source-path=SCRIPTDIR",
                 "--enable=" + SHELLCHECK_OPTIONAL, "--", ctx.abspath],
                capture_output=True, text=True)
        except OSError:
            return
        if proc.returncode != 0:
            message = "shellcheck: '%s'" % ctx.path
            if proc.stdout.strip():
                message += "\n" + proc.stdout.rstrip("\n")
            yield model.fail("shellcheck", message, ctx.path)


RULES = (BashParse(), Shellcheck())
