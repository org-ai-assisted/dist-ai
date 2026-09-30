#!/usr/bin/python3 -Bsu

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_scripts_enum_test.sh.

Standalone (R-193: not read from stdin) and eval-free. Takes the tool's JSON
report, the two run exit codes, and an INDEPENDENT maintainer-script count the
shell derived by a different method (the recount sanity), checks every category
and every sudo-reader pin, prints PASS/FAIL per case, and exits non-zero if any
failed.

Usage: root_scripts_enum_check.py <report.json> <populated_rc> <empty_rc> <maint_count>
"""

import json
import sys


def main(argv):
    report_path = argv[1]
    populated_rc = int(argv[2])
    empty_rc = int(argv[3])
    independent_maint = int(argv[4])
    report = json.load(open(report_path, encoding="utf-8"))
    entries = report["entries"]

    def cat(name):
        return [e for e in entries if e["category"] == name]

    def one(name, needle):
        matches = [e for e in cat(name) if needle in e["path"]]
        return matches[0] if matches else None

    def sudo_at(needle, line):
        for e in cat("sudo-call"):
            if needle in e["path"] and e.get("line") == line:
                return e
        return None

    def sudo_lines(needle):
        return {e["line"] for e in cat("sudo-call") if needle in e["path"]}

    helper = "usr/libexec/foo/helper"
    priv = one("privleap-action", "conf.d/foo.conf")
    priv_actions = {a["action"]: a for a in priv["actions"]} if priv else {}

    checks = [
        ("a populated tree exits 0", populated_rc == 0),
        ("an empty tree fails loudly instead of reporting clean", empty_rc != 0),

        ## maintainer scripts (caught regardless of the +x bit) + recount
        ("a non-executable maintainer script is enumerated",
         one("maintainer-script", "debian/foo.postinst") is not None),
        ("a bare-name maintainer script (debian/preinst) is enumerated",
         one("maintainer-script", "debian/preinst") is not None),
        ("a non-debian .config file is NOT a maintainer script",
         one("maintainer-script", "etc/skel/.config") is None),
        ("maintainer count matches the independent recount",
         report["summary"].get("maintainer-script", 0) == independent_maint
         and independent_maint >= 2),

        ## systemd units
        ("root system unit is enumerated with its exec target",
         one("systemd-unit", "rootsvc.service") is not None
         and "/usr/bin/rootprog" in one("systemd-unit", "rootsvc.service")["exec"]),
        ("a user-scope unit is excluded", one("systemd-unit", "usersvc.service") is None),
        ("a non-root User= unit is excluded",
         one("systemd-unit", "nonrootsvc.service") is None),

        ## privleap
        ("a root privleap action is enumerated with its command",
         "root-action" in priv_actions
         and priv_actions["root-action"]["command"] == "/usr/bin/rootcmd --flag"),
        ("a privleap action with a non-root TargetUser is excluded",
         "tor-action" not in priv_actions),
        ("the privleap [persistent-users] section is not an action",
         "persistent-users" not in priv_actions and None not in priv_actions),

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

        ## sudo-call: all components (a SUBMODULE runtime script, not just dm)
        ("a sudo call in a submodule script is enumerated",
         sudo_at(helper, 2) is not None
         and sudo_at(helper, 2)["command"] == "apt-get"
         and sudo_at(helper, 2)["component"] == "foo"),
        ("sudo -u <nonroot> records the run-as target",
         sudo_at(helper, 3) is not None and sudo_at(helper, 3)["runs_as"] == "nobody"),
        ("sudo VAR=val prog skips the env setting and reports the program",
         sudo_at(helper, 4) is not None and sudo_at(helper, 4)["command"] == "realprog"),
        ("sudo inside prose is not an invocation (AST)", 5 not in sudo_lines(helper)),
        ("sudo as a bare argument is not an invocation (AST)", 6 not in sudo_lines(helper)),
        ("a sudo program hidden in a variable is notify, never guessed",
         sudo_at(helper, 7) is not None and sudo_at(helper, 7)["command"] is None
         and sudo_at(helper, 7).get("note") == "notify"),
        ("sudo in a NON-shell file is not scanned",
         one("sudo-call", "etc/foo.conf") is None),
        ("a dm build-script sudo call is enumerated under derivative-maker",
         one("sudo-call", "help-steps/buildscript") is not None
         and one("sudo-call", "help-steps/buildscript")["component"] == "derivative-maker"),

        ## build-chroot
        ("a chroot helper is enumerated as build-chroot",
         one("build-chroot", "foo-chroot-raw") is not None
         and one("build-chroot", "foo-chroot-raw")["runs_in_chroot_as_root"] is True),

        ## summary + parse sanity
        ("shfmt parsed the shell with no errors", report["parse_errors"] == []),
        ("the report carries examined counts and a category summary",
         report["examined"]["files"] > 0 and report["examined"]["shell_files"] > 0
         and report["summary"].get("sudo-call", 0) >= 1),
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
