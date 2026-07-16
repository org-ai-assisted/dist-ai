#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Boot a built derivative-maker ISO headless and run systemcheck leak tests in
both the sysmaint and the user session.

Sequence (each session is a fresh qemu boot; dm-qemu passes -no-reboot, so a
guest reboot simply exits qemu and we boot the next session ourselves):

  1. boot the SYSMAINT session -> log in -> `systemcheck --leak-tests --verbose`
     -> reboot
  2. boot the USER session     -> log in -> `systemcheck --leak-tests --verbose`
     -> poweroff

"more tests later": extra scripted commands are appended to a scenario's
``commands`` list (see SCENARIOS below) -- add a command string and, optionally,
a regex its output must / must not match. New sessions are new SCENARIOS entries.

Exit status:
  0  all scenarios passed
  1  at least one scenario failed
  77 skipped (no ISO given / ISO unreadable) -- the dist-ai convention for
     "target absent", so dist-ai-tests-all reports SKIP rather than FAIL.

This test runs on the BUILD HOST (it needs qemu + the ISO), not inside the guest.
It is slow: without KVM (/dev/kvm), a full leak-test boot can take tens of
minutes per session; pass --fast on a pure-TCG host to append mitigations=off.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iso_boot_lib import SerialBootSession, SerialBootError  # noqa: E402


## Each scenario is one full boot. ``commands`` is a list of (command, must_pass)
## tuples run in order after login; must_pass=True fails the scenario on a
## non-zero exit code. ``final`` is how to end the boot (poweroff|reboot).
def _scenarios(leaktest_cmd):
    return [
        {
            "name": "sysmaint-session",
            "entry": "sysmaint",
            "commands": [
                (leaktest_cmd, True),
            ],
            "final": "reboot",
        },
        {
            "name": "user-session",
            "entry": "user",
            "commands": [
                (leaktest_cmd, True),
            ],
            "final": "poweroff",
        },
    ]


def run_scenario(scenario, args):
    name = scenario["name"]
    print("=== scenario: %s (entry=%s) ===" % (name, scenario["entry"]), flush=True)
    try:
        with SerialBootSession(
            iso=args.iso,
            entry=scenario["entry"],
            dm_qemu=args.dm_qemu,
            username=None,          ## fixed by the session: sysmaint->sysmaint, user->user
            password=args.password,
            arch=args.arch,
            fast=args.fast,
            memory=args.memory,
            smp=args.smp,
            extra_append=args.extra_append,
            logfile=sys.stdout.buffer if args.serial_echo else None,
            use_qmp=not args.no_qmp,
        ) as sess:
            print("[%s] QMP: %s" % (name, "connected" if sess.qmp else "unavailable (serial-only)"), flush=True)
            print("[%s] waiting for login prompt ..." % name, flush=True)
            sess.wait_for_login(timeout=args.boot_timeout)
            print("[%s] logging in as %s ..." % (name, sess.username), flush=True)
            sess.login()
            for command, must_pass in scenario["commands"]:
                print("[%s] run: %s" % (name, command), flush=True)
                output, rc = sess.run(command, timeout=args.command_timeout)
                print("[%s] rc=%s; output:\n%s" % (name, rc, output), flush=True)
                if must_pass and rc != 0:
                    print("[%s] FAIL: '%s' exited %s" % (name, command, rc), flush=True)
                    return False
            print("[%s] %s ..." % (name, scenario["final"]), flush=True)
            reason = getattr(sess, scenario["final"])()
            print("[%s] shutdown reason (QMP): %s" % (name, reason or "n/a"), flush=True)
    except SerialBootError as exc:
        print("[%s] FAIL: %s" % (name, exc), flush=True)
        return False
    print("[%s] PASS" % name, flush=True)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Boot a built ISO and run systemcheck leak tests in the "
                    "sysmaint and user sessions."
    )
    parser.add_argument("--iso", help="path to the built ISO to boot")
    parser.add_argument("--dm-qemu", dest="dm_qemu", default=None,
                        help="path to derivative-maker help-steps/dm-qemu "
                             "(default: $DERIVATIVE_MAKER_DIR or ~/derivative-maker)")
    parser.add_argument("--leaktest-command", default="systemcheck --leak-tests --verbose",
                        help="the leak-test command to run in each session")
    parser.add_argument("--arch", default=None,
                        help="guest architecture (amd64/x86_64, arm64/aarch64); "
                             "default: the host arch. Passed through to dm-qemu.")
    ## The login account is fixed by the boot-role session (sysmaint->sysmaint,
    ## user->user), so there is no --username knob. Only the shared password is
    ## configurable (default: the live 'changeme').
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--fast", action="store_true",
                        help="append mitigations=off (pure-TCG speed; NOT a fidelity test)")
    parser.add_argument("--extra-append", dest="extra_append", default=None,
                        help="extra kernel cmdline passed through to dm-qemu (e.g. 'fstab=0' to "
                             "ignore a seeded /etc/fstab)")
    parser.add_argument("--memory", type=int, default=None, help="guest RAM in MB")
    parser.add_argument("--smp", type=int, default=None, help="guest vCPUs")
    parser.add_argument("--boot-timeout", type=int, default=2400,
                        help="seconds to wait for the login prompt (default 2400)")
    parser.add_argument("--command-timeout", type=int, default=2400,
                        help="seconds to wait for each command (default 2400)")
    parser.add_argument("--serial-echo", action="store_true",
                        help="mirror the raw serial transcript to stdout (debugging)")
    parser.add_argument("--no-qmp", action="store_true",
                        help="disable the QMP control channel (serial-only power control)")
    args = parser.parse_args()

    ## SKIP (77) when there is nothing to boot -- the dist-ai "target absent"
    ## convention, so dist-ai-tests-all reports SKIP instead of FAIL.
    if not args.iso:
        print("SKIP: no --iso given (nothing to boot)", flush=True)
        return 77
    if not os.access(args.iso, os.R_OK):
        print("SKIP: ISO not readable: %s" % args.iso, flush=True)
        return 77

    results = []
    for scenario in _scenarios(args.leaktest_command):
        results.append((scenario["name"], run_scenario(scenario, args)))

    print("\n=== summary ===", flush=True)
    failed = 0
    for name, ok in results:
        print("  %-20s %s" % (name, "PASS" if ok else "FAIL"), flush=True)
        if not ok:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
