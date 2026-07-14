#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Bubblewrap-isolated scenario tests for the Qubes check functions in
check_qubes.bsh.

check_qubes_network_interface and check_qubes_vm_type are gated on absolute-path
marker files under /run/qubes (and /var/run/qubes, which is the same directory
because /var/run is a symlink to /run) and call the bare binary qubesdb-read.
They therefore cannot be steered by environment alone; every scenario runs
inside a bubblewrap mount namespace via run_check_scenario_isolated so the
markers can be made present (place=) or absent (hide_dirs=/place tmpfs) and
qubesdb-read / cleanup can be stubbed.

Each test asserts the actual severity and a content substring of the real
message the branch emits, plus $EXIT_CODE. Tests SkipTest automatically when
bubblewrap / unprivileged user namespaces are unavailable.
"""

import unittest

from systemcheck_testlib import (
    ScenarioTestBase,
    run_check_scenario_isolated,
)


class TestQubesNetworkInterfaceIsolatedScenarios(ScenarioTestBase):
    FILE = "check_qubes.bsh"
    ## Empty /run/qubes so the templatevm/netvm/proxyvm markers are all absent
    ## unless a scenario explicitly places one. /var/run is a symlink to /run,
    ## so this also empties /var/run/qubes.
    HIDE = ["/run/qubes"]

    def test_valid_ip_connection_succeeded_and_netvm_ok(self) -> None:
        ## qubesdb-read returns a valid IPv4 and exits 0; GATEWAY_IP is a real
        ## address (not the qubesdb_read_failed sentinel) -> the "Connection ...
        ## succeeded" info fires and the follow-on netvm check falls through to
        ## the final OK info, with no warning/error.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_network_interface",
            env_setup=("verbose=1\nvm_lower_case_short=workstation\n"
                       "GATEWAY_IP=10.152.152.10\nqubes_vm_type=AppVM"),
            stubs='qubesdb-read() { echo "10.152.152.10"; }',
            hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("warning"))
        self.assertFalse(r.has_severity("error"))
        self.assertIn("succeeded", r.joined())
        self.assertIn("OK.", r.joined())
        self.assertEqual(r.exit_code, "0")

    def test_daemon_read_failed_errors(self) -> None:
        ## qubesdb-read prints the daemon-down message -> "qubes-db read failed"
        ## error; the branch calls cleanup "1", which must be stubbed.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_network_interface",
            env_setup="verbose=1\nvm_lower_case_short=workstation",
            stubs=('qubesdb-read() { echo "Failed connect to local daemon"; }\n'
                   "cleanup() { :; }"),
            hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("error"))
        self.assertIn("qubes-db read failed", r.joined())
        self.assertEqual(r.exit_code, "1")

    def test_non_ipv4_garbage_invalid_data_error(self) -> None:
        ## qubesdb-read returns data that is neither the daemon-down message nor
        ## an IPv4 address -> invalid-data error. This branch does NOT call
        ## cleanup.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_network_interface",
            env_setup="verbose=1\nvm_lower_case_short=workstation",
            stubs='qubesdb-read() { echo "not-an-ip-address"; }',
            hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("error"))
        self.assertIn("invalid data", r.joined())
        self.assertEqual(r.exit_code, "1")

    def test_netvm_not_set_warns(self) -> None:
        ## Valid IPv4 passes the format check, but GATEWAY_IP is the
        ## qubesdb_read_failed sentinel -> networking-misconfiguration warning
        ## (workstation -> suggests sys-whonix). cleanup is deliberately NOT
        ## called here (the Qube may lack Internet on purpose).
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_network_interface",
            env_setup=("verbose=1\nvm_lower_case_short=workstation\n"
                       "GATEWAY_IP=qubesdb_read_failed\n"
                       "qubes_name_of_vm=anon-whonix\nqubes_vm_type=AppVM"),
            stubs='qubesdb-read() { echo "10.152.152.10"; }',
            hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("warning"))
        self.assertIn("Networking will probably not work", r.joined())
        self.assertEqual(r.exit_code, "1")

    def test_machine_netvm_marker_present_is_ok(self) -> None:
        ## A netvm (sys-net): GATEWAY_IP is the failed sentinel, but the
        ## this-is-netvm marker is present, so the read failure is expected and
        ## the function returns OK without a warning. Only the verbose
        ## "succeeded" info is emitted. The check reads /var/run/qubes/... but
        ## /var/run is a symlink to /run, so the marker is placed under /run
        ## (bubblewrap cannot mkdir a mount point through the symlink).
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_network_interface",
            env_setup=("verbose=1\nvm_lower_case_short=machine\n"
                       "GATEWAY_IP=qubesdb_read_failed\nqubes_vm_type=NetVM"),
            stubs='qubesdb-read() { echo "10.152.152.10"; }',
            place=[("/run/qubes/this-is-netvm", "", False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("warning"))
        self.assertEqual(r.exit_code, "0")

    def test_skipped_in_templatevm(self) -> None:
        ## The /run/qubes/this-is-templatevm marker short-circuits the whole
        ## check with return 0 before qubesdb-read is ever run: no records.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_network_interface",
            env_setup="verbose=1\nvm_lower_case_short=workstation",
            place=[("/run/qubes/this-is-templatevm", "", False)])
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, "0")


class TestQubesVmTypeIsolatedScenarios(ScenarioTestBase):
    FILE = "check_qubes.bsh"
    HIDE = ["/run/qubes"]

    def test_gateway_netvm_marker_ok_info(self) -> None:
        ## Gateway with the this-is-netvm marker present -> OK info.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_vm_type",
            env_setup="verbose=1\nvm_lower_case_short=gateway\nqubes_vm_type=NetVM",
            place=[("/run/qubes/this-is-netvm", "", False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("warning"))
        self.assertIn("qubes_vm_type is", r.joined())
        self.assertEqual(r.exit_code, "0")

    def test_gateway_templatevm_marker_ok_info(self) -> None:
        ## Gateway with the this-is-templatevm marker present is also accepted
        ## -> OK info (TemplateVM is one of the expected gateway types).
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_vm_type",
            env_setup=("verbose=1\nvm_lower_case_short=gateway\n"
                       "qubes_vm_type=TemplateVM"),
            place=[("/run/qubes/this-is-templatevm", "", False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("warning"))
        self.assertEqual(r.exit_code, "0")

    def test_gateway_wrong_type_warns(self) -> None:
        ## Gateway but none of the netvm/proxyvm/templatevm markers present ->
        ## warning; the branch calls cleanup "1", stubbed here.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_vm_type",
            env_setup="verbose=1\nvm_lower_case_short=gateway\nqubes_vm_type=AppVM",
            stubs="cleanup() { :; }", hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("warning"))
        self.assertIn("NetVM, ProxyVM or TemplateVM is expected", r.joined())
        self.assertEqual(r.exit_code, "1")

    def test_workstation_appvm_marker_ok_info(self) -> None:
        ## Workstation with the this-is-appvm marker present -> OK info.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_vm_type",
            env_setup=("verbose=1\nvm_lower_case_short=workstation\n"
                       "qubes_vm_type=AppVM"),
            place=[("/run/qubes/this-is-appvm", "", False)])
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("info"))
        self.assertFalse(r.has_severity("warning"))
        self.assertIn("qubes_vm_type is", r.joined())
        self.assertEqual(r.exit_code, "0")

    def test_workstation_wrong_type_warns(self) -> None:
        ## Workstation but neither appvm nor templatevm marker present ->
        ## warning; cleanup "1" stubbed.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_vm_type",
            env_setup=("verbose=1\nvm_lower_case_short=workstation\n"
                       "qubes_vm_type=NetVM"),
            stubs="cleanup() { :; }", hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertTrue(r.has_severity("warning"))
        self.assertIn("AppVM or TemplateVM is expected", r.joined())
        self.assertEqual(r.exit_code, "1")

    def test_other_vm_type_emits_nothing(self) -> None:
        ## vm_lower_case_short neither gateway nor workstation (e.g. a plain
        ## machine): the function matches neither block and emits nothing.
        r = run_check_scenario_isolated(
            self.check(self.FILE), "check_qubes_vm_type",
            env_setup="verbose=1\nvm_lower_case_short=machine\nqubes_vm_type=AppVM",
            hide_dirs=self.HIDE)
        self.assertCleanRun(r)
        self.assertEqual(r.records, [])
        self.assertEqual(r.exit_code, "0")


if __name__ == "__main__":
    unittest.main()
