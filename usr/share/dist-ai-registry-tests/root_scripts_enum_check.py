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

    def _polkit_default(entry, action_id, key):
        for action in entry["actions"]:
            if action["id"] == action_id:
                return action["defaults"].get(key)
        return None

    helper = "usr/libexec/foo/helper"
    probe = "usr/libexec/foo/optprobe"
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
        ("a DynamicUser=yes unit is excluded (dynamic non-root UID)",
         one("systemd-unit", "dynuser.service") is None),
        ("a debhelper .user.service source is excluded",
         one("systemd-unit", "foo.user.service") is None),
        ("ExecCondition and ExecStopPost root programs are captured",
         one("systemd-unit", "execkeys.service") is not None
         and "/usr/bin/root-cond" in one("systemd-unit", "execkeys.service")["exec"]
         and "/usr/bin/root-cleanup" in one("systemd-unit", "execkeys.service")["exec"]),
        ("a bare ExecStartPre= reset clears only that key",
         one("systemd-unit", "execkeys.service") is not None
         and "/usr/bin/root-pre" not in one("systemd-unit", "execkeys.service")["exec"]
         and "/usr/bin/root-main" in one("systemd-unit", "execkeys.service")["exec"]),

        ## systemd drop-ins
        ("a service.d drop-in that adds Exec programs is enumerated",
         one("systemd-dropin", "svc.service.d/30_override.conf") is not None
         and one("systemd-dropin", "svc.service.d/30_override.conf")["base_unit"]
         == "svc.service"
         and "/usr/lib/svc" in one("systemd-dropin", "svc.service.d/30_override.conf")["exec"]),
        ("a '+'-prefixed drop-in Exec is captured as forced-root",
         one("systemd-dropin", "svc.service.d/30_override.conf") is not None
         and "/usr/lib/root-merger"
         in one("systemd-dropin", "svc.service.d/30_override.conf")["root_forced_exec"]),
        ("a user-scope drop-in is excluded",
         one("systemd-dropin", "u.service.d/30_x.conf") is None),

        ## privleap
        ("a root privleap action is enumerated with its command",
         "root-action" in priv_actions
         and priv_actions["root-action"]["command"] == "/usr/bin/rootcmd --flag"),
        ("a privleap action with a non-root TargetUser is excluded",
         "tor-action" not in priv_actions),
        ("the privleap [persistent-users] section is not an action",
         "persistent-users" not in priv_actions and None not in priv_actions),

        ## sudoers
        ("an active NOPASSWD root sudoers rule is captured, args stripped",
         one("sudoers", "active-sudo") is not None
         and one("sudoers", "active-sudo")["grants_root"]
         and one("sudoers", "active-sudo")["nopasswd"]
         and one("sudoers", "active-sudo")["commands"] == ["/usr/bin/foo"]),
        ("a sudoers rule granting only a non-root runas does not grant root",
         one("sudoers", "nonroot-sudo") is not None
         and one("sudoers", "nonroot-sudo")["grants_root"] is False),
        ("an all-commented sudoers file grants nothing",
         one("sudoers", "commented-sudo") is not None
         and one("sudoers", "commented-sudo")["grants_root"] is False),

        ## polkit -- per-action defaults, single- or double-quoted ids
        ("both polkit actions are enumerated with their own defaults",
         one("polkit", "com.example.test") is not None
         and _polkit_default(one("polkit", "com.example.test"),
                             "com.example.test.do", "allow_active") == "yes"
         and _polkit_default(one("polkit", "com.example.test"),
                             "com.example.test.other", "allow_active") == "no"),

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

        ## sudo getopt semantics (optprobe)
        ("an abbreviated --us=nobody resolves the run-as target",
         sudo_at(probe, 2) is not None and sudo_at(probe, 2)["runs_as"] == "nobody"),
        ("a value-taking -p cluster is not misread as -u",
         sudo_at(probe, 3) is not None and sudo_at(probe, 3)["command"] == "/usr/bin/b"
         and sudo_at(probe, 3)["runs_as"] == "root"),
        ("an attached -u expansion target is unresolved (?)",
         sudo_at(probe, 4) is not None and sudo_at(probe, 4)["runs_as"] == "?"),
        ("a sudo env setting with an expansion value still finds the program",
         sudo_at(probe, 5) is not None and sudo_at(probe, 5)["command"] == "/usr/bin/realp"),
        ("a non-executing sudo -l is noted, not a plain root exec",
         sudo_at(probe, 6) is not None and sudo_at(probe, 6).get("note") == "sudo-l"),
        ("sudo behind an exec wrapper is enumerated",
         sudo_at(probe, 7) is not None and sudo_at(probe, 7)["command"] == "/usr/bin/f"),
        ("a script defining a sudo function reports no sudo calls",
         not any("sudofn" in e["path"] for e in cat("sudo-call"))),
        ("an extensionless shebang-less build-step file is scanned",
         one("sudo-call", "help-steps/nosheb") is not None
         and one("sudo-call", "help-steps/nosheb")["command"] == "apt-get"),
        ("a privleap TargetUser=00 (numeric UID 0) is a root action",
         "numeric-root-action" in priv_actions),
        ("a dm build-script sudo call is enumerated under derivative-maker",
         one("sudo-call", "help-steps/buildscript") is not None
         and one("sudo-call", "help-steps/buildscript")["component"] == "derivative-maker"),

        ## build-chroot
        ("a chroot helper is enumerated as build-chroot",
         one("build-chroot", "foo-chroot-raw") is not None
         and one("build-chroot", "foo-chroot-raw")["runs_in_chroot_as_root"] is True),

        ## summary + parse sanity
        ("shfmt parsed the shell with no errors", report["parse_errors"] == []),
        ("the walk reported no unreadable directories", report["walk_errors"] == []),
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
