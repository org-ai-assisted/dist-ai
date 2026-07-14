#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Bubblewrap-isolated scenario tests for the systemcheck Tor checks:
check_tor_config, check_tor_running, check_tor_enabled.

All three are gated on absolute-path files: they only run on a Whonix-Gateway
(the /usr/share/anon-gw-base-files/gateway marker) and skip inside a Qubes
TemplateVM (the /run/qubes/this-is-templatevm marker). Those paths cannot be
steered from the environment, so each scenario runs inside a bubblewrap mount
namespace via run_check_scenario_isolated:

  * place the gateway marker PRESENT so the Whonix-Gateway branch runs,
  * hide /run/qubes so the TemplateVM guard is ABSENT,
  * stub leaprun per scenario to drive the Tor state under test.

External commands the harness does NOT provide (leaprun, br_add, cleanup, and
check_tor_enabled_do, which lives in the tor_enabled_check helper) are stubbed;
sanitize-string is a real installed binary and runs for real.

These SkipTest when bubblewrap / user namespaces are unavailable.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario_isolated,
)

## Make the Whonix-Gateway guard file PRESENT.
GATEWAY = ("/usr/share/anon-gw-base-files/gateway", "", False)
## Make the Qubes TemplateVM marker PRESENT (used by the skip test).
TEMPLATEVM = ("/run/qubes/this-is-templatevm", "", False)
## Keep the TemplateVM marker ABSENT (empty /run/qubes) and empty /usr/share so
## bubblewrap can create the gateway marker's parent dir on hosts that lack
## /usr/share/anon-gw-base-files (a tmpfs mountpoint under a read-only /usr
## cannot be created without emptying an existing ancestor first).
HIDE_QUBES = ["/run/qubes", "/usr/share"]
## The gateway marker's parent tmpfs needs this ancestor emptied even when the
## TemplateVM marker is being PLACED (the skip tests) rather than hidden.
HIDE_USR_SHARE = ["/usr/share"]

## br_add (adds <br> to newlines) and cleanup are not among the preparation.bsh
## helpers the harness extracts, so stub them; a passthrough br_add preserves the
## text the assertions look for.
BR_ADD = "br_add() { printf '%s' \"$1\"; }"
CLEANUP = "cleanup() { :; }"


class TestTorConfigIsolatedScenarios(ScenarioTestBase):
    FILE = "check_tor_config.bsh"
    ENV = ('verbose=1\n'
           'start_menu_instructions_system_first_part="Start Menu"')

    def test_valid_config_ok_info(self) -> None:
        ## leaprun tor-verify-config exits 0 -> OK / info, EXIT_CODE stays 0.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_config", env_setup=self.ENV,
            stubs="leaprun() { echo 'configuration was valid'; return 0; }\n"
                  + BR_ADD + "\n" + CLEANUP,
            hide_dirs=HIDE_QUBES, place=[GATEWAY])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("error"))
        self.assertIn("Tor Config Check Result", r.joined())
        self.assertEqual(r.exit_code, "0")

    def test_invalid_config_errors_and_fails(self) -> None:
        ## leaprun tor-verify-config exits nonzero -> error, EXIT_CODE 1.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_config", env_setup=self.ENV,
            stubs="leaprun() { echo '[warn] bad line'; return 1; }\n"
                  + BR_ADD + "\n" + CLEANUP,
            hide_dirs=HIDE_QUBES, place=[GATEWAY])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("error"))
        self.assertIn("at least one error", r.joined())
        self.assertEqual(r.exit_code, "1")


class TestTorRunningIsolatedScenarios(ScenarioTestBase):
    FILE = "check_tor_running.bsh"
    ENV = ('verbose=1\n'
           'start_menu_instructions_system_first_part="Start Menu"')

    def test_running_info(self) -> None:
        ## leaprun check-tor-running exits 0 -> Tor running, info, EXIT_CODE 0.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_running", env_setup=self.ENV,
            stubs="leaprun() { echo 'Tor is running.'; return 0; }\n" + BR_ADD,
            hide_dirs=HIDE_QUBES, place=[GATEWAY])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("error"))
        self.assertIn("Tor Running Check Result", r.joined())
        self.assertEqual(r.exit_code, "0")

    def test_not_running_errors_and_fails(self) -> None:
        ## leaprun check-tor-running exits nonzero -> error (code emits
        ## `emit_message error`), EXIT_CODE 1.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_running", env_setup=self.ENV,
            stubs="leaprun() { echo 'no tor process'; return 1; }\n" + BR_ADD,
            hide_dirs=HIDE_QUBES, place=[GATEWAY])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("error"))
        self.assertFalse(r.has_severity("info"))
        self.assertIn("Tor is not running", r.joined())
        self.assertEqual(r.exit_code, "1")

    def test_skipped_in_templatevm(self) -> None:
        ## TemplateVM marker present -> the check returns early; the only
        ## emission is the verbose-gated OK info, so verbose=0 yields no records.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_running", env_setup="verbose=0",
            stubs=BR_ADD, hide_dirs=HIDE_USR_SHARE, place=[GATEWAY, TEMPLATEVM])
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, "0")


class TestTorEnabledIsolatedScenarios(ScenarioTestBase):
    FILE = "check_tor_enabled.bsh"
    ENV = ('verbose=1\n'
           'start_menu_instructions_system_first_part="Start Menu"')

    def test_enabled_info(self) -> None:
        ## TOR_ENABLED=1 on a Whonix-Gateway -> "DisableNetwork 1" not active,
        ## info, EXIT_CODE 0.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_enabled", env_setup=self.ENV,
            stubs="check_tor_enabled_do() { TOR_ENABLED=1; }\n" + CLEANUP,
            hide_dirs=HIDE_QUBES, place=[GATEWAY])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("warning"))
        self.assertIn("not active", r.joined())
        self.assertEqual(r.exit_code, "0")

    def test_disabled_warns_and_fails(self) -> None:
        ## TOR_ENABLED=0 -> DisableNetwork not found -> warning, EXIT_CODE 1.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_enabled", env_setup=self.ENV,
            stubs="check_tor_enabled_do() { TOR_ENABLED=0; }\n" + CLEANUP,
            hide_dirs=HIDE_QUBES, place=[GATEWAY])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("warning"))
        self.assertFalse(r.has_severity("info"))
        self.assertIn("Tor is disabled", r.joined())
        self.assertEqual(r.exit_code, "1")

    def test_skipped_in_templatevm(self) -> None:
        ## TemplateVM marker present -> early skip; the only emission is the
        ## verbose-gated info, so verbose=0 yields no records.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_tor_enabled", env_setup="verbose=0",
            stubs="check_tor_enabled_do() { TOR_ENABLED=1; }\n" + CLEANUP,
            hide_dirs=HIDE_USR_SHARE, place=[GATEWAY, TEMPLATEVM])
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, "0")


if __name__ == "__main__":
    unittest.main()
