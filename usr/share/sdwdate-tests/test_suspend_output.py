#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression suite for the suspend-pre / suspend-post output helpers.

Drives the REAL shipped output_cmd_set / output_cmd_func by extracting them
from the installed (or SDWDATE_REPO) scripts and running them with systemd-cat
stubbed, so only the stdout copy is observed. No root, no side effects: the
helpers are exercised in isolation, never the top-level script body.

Locks in:
  * suspend-post prints the message on stdout in the normal case, and
    SUPPRESSES the stdout copy under xtrace (set -x already echoes it),
  * suspend-pre still prints after the vestigial output_cmd toggle was dropped.
"""

import os
import subprocess
import unittest


def _suspend_script(name: str) -> str:
    """SDWDATE_REPO -> that checkout's usr/libexec/sdwdate, else installed."""
    repo = os.environ.get("SDWDATE_REPO", "").strip()
    base = (
        os.path.join(repo, "usr", "libexec", "sdwdate")
        if repo
        else "/usr/libexec/sdwdate"
    )
    return os.path.join(base, name)


## Extract only the output helper definitions and drive output_cmd_func for
## real. 'set -x' is toggled BEFORE output_cmd_set so its '[ -o xtrace ]' probe
## sees the mode. systemd-cat is stubbed to a stdout-swallowing sink so the only
## thing left on stdout is the helper's own stdout copy.
_SNIPPET = r"""
set -o errexit
set -o nounset
eval "$(sed -n '/^date_cmd()/,/^}/p; /^output_cmd_set()/,/^}/p; /^output_cmd_func()/,/^}/p' -- "$1")"
systemd-cat() { cat >/dev/null; }
if [ "$3" = "xtrace" ]; then set -x; fi
if type output_cmd_set >/dev/null 2>&1; then output_cmd_set; fi
output_cmd_func "$2"
"""


def _run(name: str, message: str, mode: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", _SNIPPET, "bash", _suspend_script(name), message, mode],
        capture_output=True,
        text=True,
        check=False,
    )


class SuspendOutputTest(unittest.TestCase):
    def setUp(self) -> None:
        for name in ("suspend-pre", "suspend-post"):
            path = _suspend_script(name)
            if not os.path.exists(path):
                self.fail(
                    "%s not found -- install sdwdate or set SDWDATE_REPO" % path
                )

    def test_suspend_post_prints_normally(self) -> None:
        result = _run("suspend-post", "INFO - canary-post", "normal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INFO - canary-post", result.stdout)

    def test_suspend_post_suppresses_stdout_under_xtrace(self) -> None:
        result = _run("suspend-post", "INFO - canary-xtrace", "xtrace")
        self.assertEqual(result.returncode, 0, result.stderr)
        ## Under 'set -x' the helper must NOT print its own stdout copy (xtrace,
        ## on stderr, already shows it). Empty-stdout guard would pass even if
        ## the helper never ran, so require the message on stderr (the trace).
        self.assertNotIn("INFO - canary-xtrace", result.stdout)
        self.assertIn("canary-xtrace", result.stderr)

    def test_suspend_pre_prints_after_toggle_dropped(self) -> None:
        result = _run("suspend-pre", "INFO - canary-pre", "normal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INFO - canary-pre", result.stdout)

    def test_no_echo_output_command_remains(self) -> None:
        ## Guards a revert of the printf fix: neither script may reintroduce the
        ## echo-based output dispatch.
        for name in ("suspend-pre", "suspend-post"):
            with open(_suspend_script(name), encoding="utf-8") as handle:
                text = handle.read()
            self.assertNotIn('="echo"', text, name)
            self.assertNotIn("${output_cmd}", text, name)


if __name__ == "__main__":
    unittest.main()
