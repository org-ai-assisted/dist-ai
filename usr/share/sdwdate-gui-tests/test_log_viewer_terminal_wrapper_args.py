#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression test for usr/libexec/sdwdate-gui/log-viewer.

Bug: the "Open sdwdate's log" tray action runs
    terminal-wrapper "leaprun sdwdate-log-viewer"
i.e. it passes the whole command as ONE quoted string. terminal-wrapper
forwards its arguments verbatim to the terminal's '--execute' ("$@"), so a
single multi-word string is treated as one program name -- the terminal tries
to exec a file literally called 'leaprun sdwdate-log-viewer' (with a space),
which does not exist, and the log window never opens. Every other
terminal-wrapper caller passes the program and its arguments as SEPARATE
tokens; log-viewer must too:
    terminal-wrapper leaprun sdwdate-log-viewer

Guards that the terminal-wrapper invocation passes separate arguments.
"""

import os
import shlex
import unittest


def _locate_log_viewer() -> str:
    """Resolve usr/libexec/sdwdate-gui/log-viewer from an explicit repo
    override, then from the importable sdwdate_gui module's checkout, then the
    installed path."""
    rel = 'usr/libexec/sdwdate-gui/log-viewer'

    repo = os.environ.get('SDWDATE_GUI_REPO', '').strip()
    if repo:
        return os.path.join(repo, rel)

    try:
        from sdwdate_gui import sdwdate_gui_client as client
        directory = os.path.dirname(os.path.realpath(client.__file__))
        while directory != '/':
            candidate = os.path.join(directory, rel)
            if os.path.isfile(candidate):
                return candidate
            directory = os.path.dirname(directory)
    except ModuleNotFoundError:
        pass

    return '/' + rel


class TestLogViewerTerminalWrapperArgs(unittest.TestCase):
    def test_terminal_wrapper_gets_separate_arguments(self) -> None:
        path = _locate_log_viewer()
        if not os.path.isfile(path):
            self.fail(
                f"log-viewer not found at {path!r}; set SDWDATE_GUI_REPO to a "
                "sdwdate-gui checkout or install the package"
            )

        with open(path, encoding='utf-8') as handle:
            lines = handle.read().splitlines()

        invocations = [
            line for line in lines
            if 'terminal-wrapper' in line and not line.lstrip().startswith('#')
        ]
        self.assertTrue(
            invocations,
            "no terminal-wrapper invocation found in log-viewer",
        )

        for line in invocations:
            tokens = shlex.split(line)
            idx = next(
                i for i, tok in enumerate(tokens)
                if tok.endswith('terminal-wrapper')
            )
            rest = tokens[idx + 1:]
            self.assertGreaterEqual(
                len(rest), 2,
                f"terminal-wrapper must receive the program and its arguments "
                f"as separate tokens, got {rest!r} -- a single multi-word "
                f"string is exec'd as one bogus program name",
            )
            for tok in rest:
                self.assertNotIn(
                    ' ', tok,
                    f"terminal-wrapper argument {tok!r} is a multi-word string; "
                    "pass separate arguments",
                )
            self.assertEqual(
                rest[:2], ['leaprun', 'sdwdate-log-viewer'],
                f"expected 'leaprun sdwdate-log-viewer' as separate args, got {rest!r}",
            )


if __name__ == '__main__':
    unittest.main()
