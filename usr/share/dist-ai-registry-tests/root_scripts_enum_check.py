#!/usr/bin/python3 -Bsu

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_scripts_enum_test.sh.

Standalone (R-193: not read from stdin) and eval-free. Takes the tool's JSON
report plus the two run exit codes the shell captured, checks every category
and every build-time sudo-reader pin, prints PASS/FAIL per case, and exits
non-zero if any failed.

Usage: root_scripts_enum_check.py <report.json> <populated_rc> <empty_rc>
"""

import json
import sys


def main(argv):
    report_path, populated_rc, empty_rc = argv[1], int(argv[2]), int(argv[3])
    report = json.load(open(report_path, encoding="utf-8"))
    entries = report["entries"]

    def cat(name):
        return [e for e in entries if e["category"] == name]

    def one(name, needle):
        matches = [e for e in cat(name) if needle in e["path"]]
        return matches[0] if matches else None

    def sudo_lines(entry):
        return {s["line"]: s for s in entry["sudo_invocations"]}

    build = one("build-time", "help-steps/buildscript")
    lines = sudo_lines(build) if build else {}

    checks = [
        ("a populated tree exits 0",
         populated_rc == 0),
        ("an empty tree fails loudly instead of reporting clean",
         empty_rc != 0),

        ## maintainer scripts
        ("maintainer script is enumerated",
         one("maintainer-script", "debian/foo.postinst") is not None),
        ("maintainer script attributes to the submodule component",
         one("maintainer-script", "debian/foo.postinst") is not None
         and one("maintainer-script", "debian/foo.postinst")["component"] == "foo"),
        ("a non-debian .config file is NOT a maintainer script",
         one("maintainer-script", "etc/skel/.config") is None),

        ## systemd units
        ("root system unit is enumerated with its exec target",
         one("systemd-unit", "rootsvc.service") is not None
         and "/usr/bin/rootprog" in one("systemd-unit", "rootsvc.service")["exec"]),
        ("a user-scope unit is excluded (runs as the user, not root)",
         one("systemd-unit", "usersvc.service") is None),
        ("a unit pinned to a non-root User= is excluded",
         one("systemd-unit", "nonrootsvc.service") is None),

        ## sudoers
        ("an active NOPASSWD sudoers rule is captured",
         one("sudoers", "active-sudo") is not None
         and one("sudoers", "active-sudo")["grants_root"]
         and one("sudoers", "active-sudo")["nopasswd"]
         and "/usr/bin/foo" in one("sudoers", "active-sudo")["commands"]),
        ("an all-commented sudoers file grants nothing",
         one("sudoers", "commented-sudo") is not None
         and one("sudoers", "commented-sudo")["grants_root"] is False),

        ## polkit
        ("a polkit action id is enumerated",
         one("polkit", "com.example.test") is not None
         and "com.example.test.do" in one("polkit", "com.example.test")["actions"]),

        ## build-time sudo reader -- the parser-creep pins
        ("a plain sudo invocation captures the program",
         2 in lines and lines[2]["command"] == "apt-get"),
        ("sudo -u root chown resolves to chown, not the -u argument",
         3 in lines and lines[3]["command"] == "chown"),
        ("sudo inside prose is not treated as an invocation",
         4 not in lines),
        ("sudo as a bare argument is not an invocation",
         5 not in lines),
        ("a program hidden in a variable is reported notify, never guessed",
         6 in lines and lines[6]["command"] is None
         and lines[6].get("note") == "notify"),

        ## build-time -- chroot flag, data-file exclusion, component
        ("a chroot helper is flagged runs_in_chroot_as_root",
         one("build-time", "foo-chroot-raw") is not None
         and one("build-time", "foo-chroot-raw")["runs_in_chroot_as_root"] is True),
        ("a data file that merely mentions sudo is not build orchestration",
         one("build-time", "changelog.upstream") is None),
        ("dm build script attributes to derivative-maker",
         build is not None and build["component"] == "derivative-maker"),

        ## summary + examined sanity
        ("the report carries examined counts and a category summary",
         report["examined"]["files"] > 0
         and report["summary"].get("maintainer-script", 0) >= 1
         and report["summary"].get("systemd-unit", 0) >= 1),
    ]

    passed = 0
    failed = 0
    for description, ok in checks:
        if ok:
            passed += 1
            print(f"PASS: {description}")
        else:
            failed += 1
            print(f"FAIL: {description}")

    print("")
    print(f"root-scripts-enum: {passed} pass, {failed} fail")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
