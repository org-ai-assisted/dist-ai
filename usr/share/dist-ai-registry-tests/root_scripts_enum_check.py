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
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
    entries = report["entries"]

    def cat(name):
        return [e for e in entries if e["category"] == name]

    def one(name, needle):
        matches = [e for e in cat(name) if needle in e["path"]]
        return matches[0] if matches else None

    def sudo_at(needle, line):
        for e in cat("privileged-call"):
            if needle in e["path"] and e.get("line") == line:
                return e
        return None

    def sudo_lines(needle):
        return {e["line"] for e in cat("privileged-call") if needle in e["path"]}

    def _polkit_default(entry, action_id, key):
        for action in entry["actions"]:
            if action["id"] == action_id:
                return action["defaults"].get(key)
        return None

    def _polkit_exec(entry, action_id):
        for action in entry["actions"]:
            if action["id"] == action_id:
                return action.get("exec_path")
        return None

    def esc(line):
        return sudo_at("usr/libexec/foo/escprobe", line)

    def wrap(line):
        return sudo_at("usr/libexec/foo/wrapprobe", line)

    def optesc(line):
        return sudo_at("usr/libexec/foo/optesc", line)

    def besc(line):
        return sudo_at("help-steps/build-escalate", line)

    def lp(line):
        return sudo_at("usr/libexec/foo/leapprobe", line)

    helper = "usr/libexec/foo/helper"
    probe = "usr/libexec/foo/optprobe"
    sep = "usr/libexec/foo/sepprobe"
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

        ## systemd activation units (.socket/.timer)
        ("a .socket unit is enumerated with its Exec and activated service",
         one("systemd-activation", "foo.socket") is not None
         and one("systemd-activation", "foo.socket")["unit_type"] == "socket"
         and "/usr/bin/socket-root-pre" in one("systemd-activation", "foo.socket")["exec"]
         and "/usr/bin/socket-root-stop" in one("systemd-activation", "foo.socket")["exec"]
         and one("systemd-activation", "foo.socket")["activates"] == "foo-worker.service"),
        ("a .timer unit records the service it activates",
         one("systemd-activation", "foo.timer") is not None
         and one("systemd-activation", "foo.timer")["activates"] == "foo-daily.service"),
        ("a '+'-prefixed socket Exec runs as root -> root_forced_exec, not exec; a bare Exec= reset clears a prior '+'",
         one("systemd-activation", "forced.socket") is not None
         and "/usr/bin/socket-forced-root"
             in one("systemd-activation", "forced.socket")["root_forced_exec"]
         and "/usr/bin/socket-obsolete-root"
             not in one("systemd-activation", "forced.socket")["root_forced_exec"]
         and "/usr/bin/socket-forced-root"
             not in one("systemd-activation", "forced.socket")["exec"]
         and "/usr/bin/socket-userdrop"
             in one("systemd-activation", "forced.socket")["exec"]),
        ("an Accept=yes template socket keeps a single '@' in its service",
         one("systemd-activation", "tmpl@.socket") is not None
         and one("systemd-activation", "tmpl@.socket")["activates"] == "tmpl@.service"),
        ("a .mount does not claim to activate a same-named service",
         one("systemd-activation", "data.mount") is not None
         and one("systemd-activation", "data.mount")["activates"] is None),
        ("a debhelper .user.timer source is excluded",
         one("systemd-activation", "foo.user.timer") is None),

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
         one("privileged-call", "etc/foo.conf") is None),

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
        ("a real /usr/bin/sudo call is not dropped by a sudo function shadow",
         one("privileged-call", "usr/libexec/foo/sudofn") is not None
         and one("privileged-call", "usr/libexec/foo/sudofn")["command"] == "/usr/bin/real-root"),
        ("an extensionless shebang-less build-step file is scanned",
         one("privileged-call", "help-steps/nosheb") is not None
         and one("privileged-call", "help-steps/nosheb")["command"] == "apt-get"),
        ("a privleap TargetUser=00 (numeric UID 0) is a root action",
         "numeric-root-action" in priv_actions),

        ## separate-word sudo value options (regression: value != program)
        ("sudo -p PROMPT does not mistake the prompt for the program",
         sudo_at(sep, 2) is not None and sudo_at(sep, 2)["command"] == "apt-get"),
        ("sudo -g group keeps the real program",
         sudo_at(sep, 3) is not None and sudo_at(sep, 3)["command"] == "/usr/bin/b"),
        ("sudo -g grp -u user still sees the later -u target",
         sudo_at(sep, 4) is not None and sudo_at(sep, 4)["command"] == "/usr/bin/c"
         and sudo_at(sep, 4)["runs_as"] == "nobody"),

        ## genmkfile '#pkg' install suffix must not hide a category
        ("a .service with a #pkg install suffix is still enumerated",
         one("systemd-unit", "suffixed.service#foo-shared") is not None
         and "/usr/bin/suffixed-root"
         in one("systemd-unit", "suffixed.service#foo-shared")["exec"]),

        ## other privilege escalators (escprobe)
        ("pkexec is enumerated as a privileged call",
         esc(2) is not None and esc(2)["tool"] == "pkexec"
         and esc(2)["command"] == "/usr/bin/pk" and esc(2)["runs_as"] == "root"),
        ("pkexec --user sets the run-as target",
         esc(3) is not None and esc(3)["runs_as"] == "nobody"),
        ("su - user -c cmd records the user and command",
         esc(4) is not None and esc(4)["tool"] == "su"
         and esc(4)["runs_as"] == "postgres" and esc(4)["command"] == "psql"),
        ("leaprun records the privleap action name",
         esc(5) is not None and esc(5)["tool"] == "leaprun"
         and esc(5)["command"] == "grub-password-status-check"),
        ("a polkit action's pkexec exec.path (root helper) is captured",
         _polkit_exec(one("polkit", "com.example.test"), "com.example.test.do")
         == "/usr/libexec/foo/pkexec-helper"),

        ## wrapper + non-shell escalation
        ("timeout is peeled to reach the sudo behind it",
         wrap(2) is not None and wrap(2)["tool"] == "sudo"
         and wrap(2)["command"] == "/usr/bin/tprog"),
        ("a root_cmd helper call is enumerated as escalation",
         wrap(3) is not None and wrap(3)["tool"] == "root_cmd"
         and wrap(3)["command"] == "/usr/bin/rprog"),
        ("a root_cmd behind a timeout wrapper is still enumerated",
         wrap(4) is not None and wrap(4)["tool"] == "root_cmd"
         and wrap(4)["command"] == "/usr/bin/wrapped-root"),
        ("a Python subprocess escalator call is flagged (advisory)",
         one("nonshell-escalation", "foo/esc.py") is not None
         and {"leaprun", "su"} <=
         {c["tool"] for c in one("nonshell-escalation", "foo/esc.py")["calls"]}),

        ## escalator option edge cases (optesc)
        ("runuser --user=VALUE resolves the target",
         optesc(2) is not None and optesc(2)["runs_as"] == "nobody"
         and optesc(2)["command"] == "/usr/bin/ru"),
        ("su user -c cmd: a trailing argv0 does not overwrite the user",
         optesc(3) is not None and optesc(3)["runs_as"] == "postgres"
         and optesc(3)["command"] == "id"),
        ("leaprun --check is noted as a non-executing check",
         optesc(4) is not None
         and optesc(4).get("note") == "leaprun-privleap-check"),
        ("leaprun run-as is left unresolved, not falsely root",
         optesc(4) is not None and optesc(4)["runs_as"] == "?"),
        ("pkexec --help is a non-executing mode, not a notify",
         optesc(5) is not None and optesc(5).get("note") == "pkexec-help"),
        ("udev PROGRAM and a := final assignment are enumerated",
         one("udev-rule", "90-foo.rules") is not None
         and "/usr/bin/udev-probe" in one("udev-rule", "90-foo.rules")["programs"]
         and "/usr/bin/udev-final" in one("udev-rule", "90-foo.rules")["programs"]),
        ("a single-quoted polkit exec.path key is captured",
         _polkit_exec(one("polkit", "com.example.test"), "com.example.test.do")
         == "/usr/libexec/foo/pkexec-helper"),
        ("a dm build-script sudo call is enumerated under derivative-maker",
         one("privileged-call", "help-steps/buildscript") is not None
         and one("privileged-call", "help-steps/buildscript")["component"] == "derivative-maker"),

        ## build-chroot
        ("a chroot helper is enumerated as build-chroot",
         one("build-chroot", "foo-chroot-raw") is not None
         and one("build-chroot", "foo-chroot-raw")["runs_in_chroot_as_root"] is True),

        ## a '+'-prefixed Exec under a non-root User runs as root (forced)
        ("a forced-root (+) Exec under a non-root User is captured",
         one("systemd-unit", "forced.service") is not None
         and "/usr/bin/forced-root"
         in one("systemd-unit", "forced.service")["root_forced_exec"]),
        ("a bare Exec reset clears only that key's forced-root list",
         one("systemd-unit", "forced-reset.service") is not None
         and "/usr/bin/forced-pre"
         not in one("systemd-unit", "forced-reset.service")["root_forced_exec"]
         and "/usr/bin/forced-main"
         in one("systemd-unit", "forced-reset.service")["root_forced_exec"]),
        ("a '+' combined with another prefix (-+, @+) is still forced-root",
         one("systemd-unit", "forced-combo.service") is not None
         and "/usr/bin/forced-combo-pre"
         in one("systemd-unit", "forced-combo.service")["root_forced_exec"]
         and "/usr/bin/forced-combo-main"
         in one("systemd-unit", "forced-combo.service")["root_forced_exec"]),

        ## leaprun --test executes; --check is auth-only; attached -gusers
        ("leaprun --test executes the action (not a check)",
         lp(2) is not None and lp(2)["note"] == "leaprun-privleap"),
        ("leaprun --check is the auth-only check",
         lp(3) is not None and lp(3)["note"] == "leaprun-privleap-check"),
        ("an attached -gusers cluster does not read 'u' as -u",
         lp(4) is not None and lp(4)["command"] == "/usr/bin/gcmd"
         and lp(4)["runs_as"] == "root"),

        ## build escalation without the word 'sudo' (build-escalate)
        ("a ${SUDO_TO_ROOT} call is enumerated as a sudo escalation",
         besc(2) is not None and besc(2)["tool"] == "sudo"
         and besc(2)["command"] == "losetup"),
        ("a chroot_run helper call is enumerated",
         besc(3) is not None and besc(3)["tool"] == "chroot_run"
         and besc(3)["command"] == "apt-get"),
        ("a run-parts chroot-scripts-post.d script is build-chroot",
         one("build-chroot", "chroot-scripts-post.d/80_cleanup") is not None),

        ## config-file root hooks
        ("a modprobe install directive command is enumerated",
         one("modprobe-hook", "30_foo.conf") is not None
         and "/usr/bin/disabled-firewire-by-foo"
         in one("modprobe-hook", "30_foo.conf")["programs"]),
        ("a backslash-continued modprobe install command is joined",
         one("modprobe-hook", "30_foo.conf") is not None
         and "/usr/bin/disabled-thunderbolt-by-foo"
         in one("modprobe-hook", "30_foo.conf")["programs"]),
        ("an asyncio.create_subprocess_exec escalator call is flagged",
         one("nonshell-escalation", "foo/esc.py") is not None
         and "pkexec" in {c["tool"]
                          for c in one("nonshell-escalation", "foo/esc.py")["calls"]}),
        ("a Qubes post-install hook is enumerated",
         one("qubes-hook", "post-install.d/30-foo.sh") is not None),
        ("a Qubes suspend hook is enumerated",
         one("qubes-hook", "suspend-pre.d/30-foo.sh") is not None),
        ("an update-motd.d script is enumerated",
         one("update-motd", "update-motd.d/30-foo") is not None),

        ## debian/*.links-relocated root surfaces + default/grub.d + calamares
        ("a grub.d script installed via debian/*.links is attributed to its dest",
         one("grub-script", "conf/grub.d_10_linked") is not None
         and one("grub-script", "conf/grub.d_10_linked")["installs_to"]
         == "/etc/grub.d/10_linked"),
        ("a qubes hook installed via debian/*.links is enumerated",
         one("qubes-hook", "conf/qubes_post-install.d_50-foo.sh") is not None),
        ("an /etc/default/grub.d/*.cfg sourced-as-root file is enumerated",
         one("grub-default-config", "default/grub.d/50_foo.cfg") is not None),
        ("a Calamares shellprocess script program is enumerated, blank line ok",
         one("calamares-job", "shellprocess_foo.conf") is not None
         and "/usr/libexec/foo/cala-script"
         in one("calamares-job", "shellprocess_foo.conf")["programs"]
         and "/usr/libexec/foo/cala-script2"
         in one("calamares-job", "shellprocess_foo.conf")["programs"]),
        ("a Calamares process-job command is enumerated",
         one("calamares-job", "foo-job/module.desc") is not None
         and "/usr/share/calamares/helpers/foo-helper"
         in one("calamares-job", "foo-job/module.desc")["programs"]),
        ("a non-process Calamares module.desc is excluded",
         one("calamares-job", "qml-job/module.desc") is None),

        ## Python advisory precision + coverage
        ("a Python allow-list literal is NOT flagged (precision)",
         one("nonshell-escalation", "foo/data.py") is None),
        ("an os.system(f\"sudo ...\") f-string call is flagged",
         one("nonshell-escalation", "foo/esc.py") is not None
         and "sudo" in {c["tool"]
                        for c in one("nonshell-escalation", "foo/esc.py")["calls"]}),

        ## config-file root hooks
        ("a udev RUN+= program is enumerated",
         one("udev-rule", "90-foo.rules") is not None
         and "/usr/bin/udev-root-prog --flag"
         in one("udev-rule", "90-foo.rules")["programs"]),
        ("a PAM pam_exec program is enumerated",
         one("pam-exec", "pam-configs/foo") is not None
         and "/usr/libexec/foo/pam-root-prog"
         in one("pam-exec", "pam-configs/foo")["programs"]),
        ("an /etc/grub.d script is enumerated",
         one("grub-script", "etc/grub.d/10_foo") is not None),
        ("a /etc/default/grub.d config snippet is NOT a grub script",
         one("grub-script", "default/grub.d/foo.cfg") is None),
        ("a qubes-rpc handler is enumerated",
         one("qubes-rpc", "etc/qubes-rpc/qubes.Foo") is not None),
        ("a policy-rc.d is enumerated",
         one("policy-rc-d", "foo/policy-rc.d") is not None),
        ("a kernel postinst.d hook is enumerated",
         one("initramfs-kernel-hook", "etc/kernel/postinst.d/10_foo") is not None),
        ("an initramfs-tools hook is enumerated",
         one("initramfs-kernel-hook", "initramfs-tools/hooks/foo") is not None),

        ## summary + parse sanity
        ("shfmt parsed the shell with no errors", report["parse_errors"] == []),
        ("the walk reported no unreadable directories", report["walk_errors"] == []),
        ("the report carries examined counts and a category summary",
         report["examined"]["files"] > 0 and report["examined"]["shell_files"] > 0
         and report["summary"].get("privileged-call", 0) >= 1),
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
