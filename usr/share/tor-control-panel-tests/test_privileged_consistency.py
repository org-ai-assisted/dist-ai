#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Consistency checks between tor_control_panel_lib's privileged-task map and the
shipped privleap config / libexec helpers. A drift here means the GUI asks for a
privileged action that privleap will not grant, or a pkexec fallback that points
at a missing helper -- a runtime failure that unit tests of the pure logic would
otherwise miss.
"""

import os
import re
import unittest
from pathlib import Path

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()


def _repo_root() -> Path:
    ## TCP_REPO points at the checkout under test; unset means the installed
    ## package, whose conf / helpers live at the same paths under '/'. The
    ## dist-ai runner always sets TCP_REPO, so the checkout is the normal case.
    repo = os.environ.get('TCP_REPO', '').strip()
    if repo:
        return Path(repo)
    return Path('/')


def _privleap_actions() -> set:
    conf = _repo_root() / 'usr/lib/privleap/conf.d/tor-control-panel.conf'
    assert conf.is_file(), f"required privleap conf not found at {conf}"
    actions = set()
    for line in conf.read_text(encoding='utf-8').splitlines():
        match = re.match(r'\[action:(.+)\]', line.strip())
        if match:
            actions.add(match.group(1))
    return actions


class TestPrivilegedMapConsistency(unittest.TestCase):
    def test_every_leaprun_task_is_a_privleap_action(self):
        actions = _privleap_actions()
        leaprun_map = tcpl.tcpl_priv_executor_map['/usr/bin/leaprun']
        for task_name, argv in leaprun_map.items():
            self.assertEqual(
                len(argv), 1,
                f"leaprun task '{task_name}' must be a single action name",
            )
            self.assertIn(
                argv[0], actions,
                f"leaprun action '{argv[0]}' (task '{task_name}') is not "
                f"declared in the privleap conf",
            )

    def test_leaprun_and_pkexec_cover_the_same_tasks(self):
        leaprun_tasks = set(tcpl.tcpl_priv_executor_map['/usr/bin/leaprun'])
        pkexec_tasks = set(tcpl.tcpl_priv_executor_map['/usr/bin/pkexec'])
        self.assertEqual(leaprun_tasks, pkexec_tasks)

    def test_pkexec_repo_helpers_exist_and_are_executable(self):
        root = _repo_root()
        pkexec_map = tcpl.tcpl_priv_executor_map['/usr/bin/pkexec']
        for task_name, argv in pkexec_map.items():
            target = argv[0]
            if not target.startswith('/usr/libexec/tor-control-panel/'):
                continue
            rel = target.lstrip('/')
            helper = root / rel
            self.assertTrue(
                helper.is_file(),
                f"pkexec task '{task_name}' points at missing helper {target}",
            )
            self.assertTrue(
                os.access(helper, os.X_OK),
                f"helper {target} for task '{task_name}' is not executable",
            )


if __name__ == '__main__':
    unittest.main()
