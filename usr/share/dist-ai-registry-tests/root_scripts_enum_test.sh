#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-root-scripts-enum: every root-privileged category is enumerated across
## derivative-maker + ALL submodules, and -- the part that must never regress --
## sudo detection is done by a REAL bash parser (shfmt AST), never a hand-rolled
## match. The AST handles, structurally and for free:
##
##   - 'sudo' as an ARGUMENT (adduser user sudo) is not an invocation.
##   - 'sudo' inside prose ("... run as root (sudo)") is not an invocation.
##   - a program hidden in a variable is not guessed -> note=notify.
##   - 'sudo VAR=val prog' skips sudo's env setting; 'sudo -u <user>' records
##     the run-as target.
##
## Also pinned: sudo calls are found in ALL components (a submodule runtime
## script, not just dm's build), NON-shell files are not scanned, the
## exclusions (user-scope/non-root systemd, non-root privleap TargetUser,
## all-commented sudoers, non-debian .config), maintainer scripts are caught
## regardless of the +x bit with an independent recount, and the empty tree
## fails loudly.
##
## This builds a fixture TREE (controlled input for the enumerator, like the
## sibling stripped_setx_audit_test.sh) and drives the REAL tool from the
## checkout; the per-entry assertions live in the standalone checker beside it.
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v DIST_AI_REPO ] || DIST_AI_REPO=""

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dist-ai-tests-all" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -x "${repo}/usr/bin/dm-root-scripts-enum" ]; then
   printf '%s\n' 'FATAL: dist-ai-registry-tests: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

subject="${repo}/usr/bin/dm-root-scripts-enum"
checker="${script_dir}/root_scripts_enum_check.py"

if [ ! -f "${checker}" ]; then
   printf '%s\n' "FATAL: missing assertion checker '${checker}'." >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/root-scripts-enum-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

write() {
   ## write <relative-path> ; body on stdin
   local rel dir
   rel="$1"
   dir="$(dirname -- "${work_dir}/${rel}")"
   mkdir --parents -- "${dir}"
   cat > "${work_dir}/${rel}"
}

## --- fixture: a miniature derivative-maker tree -----------------------------

## Submodule map so packages/kicksecure/foo attributes to component 'foo'.
write '.gitmodules' <<'EOF'
[submodule "foo"]
	path = packages/kicksecure/foo
	url = https://example.invalid/foo.git
EOF

## maintainer script (root via dpkg), NON-executable -- caught by path+name,
## not the +x bit. write() leaves it non-executable, which is the point.
write 'packages/kicksecure/foo/debian/foo.postinst' <<'EOF'
#!/bin/bash
true
EOF

## a bare-name maintainer script (no '<pkg>.' prefix) -- also caught.
write 'packages/kicksecure/foo/debian/preinst' <<'EOF'
#!/bin/bash
true
EOF

## a .config that is NOT a maintainer script -- MUST be excluded.
write 'packages/kicksecure/foo/etc/skel/.config' <<'EOF'
not a maintainer script
EOF

## privleap actions. Root by default; a non-root TargetUser is excluded, and
## [persistent-users] is not an action.
write 'packages/kicksecure/foo/usr/lib/privleap/conf.d/foo.conf' <<'EOF'
[persistent-users]
User=foo

[action:root-action]
Command=/usr/bin/rootcmd --flag
AuthorizedGroups=sudo,privleap
AuthorizedUsers=user

[action:tor-action]
Command=/usr/bin/torcmd
AuthorizedUsers=user
TargetUser=debian-tor

[action:numeric-root-action]
Command=/usr/bin/numroot
AuthorizedUsers=user
TargetUser=00
EOF

## a SUBMODULE runtime shell script (not dm's build) that calls sudo -- proves
## all-components coverage. Line numbers are asserted:
##   2 plain    -> apt-get, root
##   3 -u user  -> id, runs_as nobody
##   4 VAR=val  -> realprog (env setting skipped)
##   5 prose    -> not an invocation
##   6 argument -> not an invocation
##   7 variable -> notify
write 'packages/kicksecure/foo/usr/libexec/foo/helper' <<'EOF'
#!/bin/bash
sudo apt-get update
sudo -u nobody id
sudo FOO=bar realprog
echo "this must run as root (sudo)"
adduser tempuser sudo
sudo "${opts[@]}" test -d /usr
EOF

## a NON-shell file that mentions sudo -- MUST NOT be scanned as a sudo call.
write 'packages/kicksecure/foo/etc/foo.conf' <<'EOF'
# config mentioning sudo foo in prose
sudo foo
EOF

## sudo getopt-semantics probe (shfmt AST + sudo option rules). Lines:
##   2 --us=nobody   -> abbreviated --user, runs_as nobody
##   3 -puser        -> -p takes 'user', so cmd is /usr/bin/b, runs_as root
##   4 -u"$x"        -> attached expansion target -> runs_as ?
##   5 FOO="$y" prog -> env setting with an expansion -> cmd is the program
##   6 -l cmd        -> non-executing list mode -> note sudo-l
##   7 exec sudo ... -> wrapper peeled -> cmd /usr/bin/f
write 'packages/kicksecure/foo/usr/libexec/foo/optprobe' <<'EOF'
#!/bin/bash
sudo --us=nobody /usr/bin/a
sudo -puser /usr/bin/b
sudo -u"$x" /usr/bin/c
sudo FOO="$y" /usr/bin/realp
sudo -l /usr/bin/e
exec sudo /usr/bin/f
EOF

## a script defining a 'sudo' function AND calling the real /usr/bin/sudo -- the
## real call must NOT be dropped (a security inventory over-reports, not under).
write 'packages/kicksecure/foo/usr/libexec/foo/sudofn' <<'EOF'
#!/bin/bash
sudo() { return 0; }
/usr/bin/sudo /usr/bin/real-root
EOF

## separate-word value options: the value must NOT be mistaken for the program.
##   2 -p PROMPT   -> cmd apt-get
##   3 -g group    -> cmd /usr/bin/b
##   4 -g grp -u u -> sees -u after -g's value: cmd /usr/bin/c, runs_as nobody
write 'packages/kicksecure/foo/usr/libexec/foo/sepprobe' <<'EOF'
#!/bin/bash
sudo -p "Enter password: " apt-get update
sudo -g mygroup /usr/bin/b
sudo -g wheel -u nobody /usr/bin/c
EOF

## a systemd unit whose SOURCE name carries a genmkfile '#pkg' install suffix
## -> must still be matched as a .service (else real root units are missed).
write 'packages/kicksecure/foo/usr/lib/systemd/system/suffixed.service#foo-shared' <<'EOF'
[Service]
ExecStart=/usr/bin/suffixed-root
EOF

## an extensionless, shebang-less build-step file -> still scanned (dm build).
write 'help-steps/nosheb' <<'EOF'
sudo apt-get update
EOF

## wrapper-invoked escalation: timeout peels to the sudo; root_cmd escalates.
write 'packages/kicksecure/foo/usr/libexec/foo/wrapprobe' <<'EOF'
#!/bin/bash
timeout --kill-after 5 5 sudo -- /usr/bin/tprog
root_cmd /usr/bin/rprog
timeout 5 root_cmd /usr/bin/wrapped-root
EOF

## escalator option edge cases.
##   2 runuser --user=u -- prog -> runs_as nobody, command /usr/bin/ru
##   3 su user -c cmd argv       -> runs_as postgres (argv does not overwrite)
##   4 leaprun --check action    -> note leaprun-privleap-check
##   5 pkexec --help             -> note pkexec-help (non-executing)
write 'packages/kicksecure/foo/usr/libexec/foo/optesc' <<'EOF'
#!/bin/bash
runuser --user=nobody -- /usr/bin/ru
su postgres -c id extra-argv0
leaprun --check some-check-action
pkexec --help
EOF

## a Python file invoking an escalator via subprocess -> nonshell-escalation.
write 'packages/kicksecure/foo/usr/lib/python3/dist-packages/foo/esc.py' <<'EOF'
import os, subprocess
subprocess.run(["/usr/bin/leaprun", "some-action"])
subprocess.call(["su", "root", "-c", "id"])
os.system(f"sudo id")
asyncio.create_subprocess_exec("pkexec", "id")
EOF

## system-scope service, no User= -> root. MUST be found with its exec target.
write 'packages/kicksecure/foo/usr/lib/systemd/system/rootsvc.service' <<'EOF'
[Service]
Type=oneshot
ExecStart=/usr/bin/rootprog --flag
EOF

## user-scope unit runs as the user, never root -> MUST be excluded.
write 'packages/kicksecure/foo/usr/lib/systemd/user/usersvc.service' <<'EOF'
[Service]
ExecStart=/usr/bin/userprog
EOF

## non-root User= -> MUST be excluded.
write 'packages/kicksecure/foo/usr/lib/systemd/system/nonrootsvc.service' <<'EOF'
[Service]
User=someuser
ExecStart=/usr/bin/x
EOF

## a non-root unit with a '+'-prefixed Exec (runs as root despite User=)
## -> the forced-root command MUST be captured.
write 'packages/kicksecure/foo/usr/lib/systemd/system/forced.service' <<'EOF'
[Service]
User=nobody
ExecStartPre=+/usr/bin/forced-root
ExecStart=/usr/bin/nonroot-worker
EOF

## a bare Exec* reset clears ONLY that key's forced-root list: forced-pre is
## cleared by the empty ExecStartPre=; forced-main on ExecStart survives.
write 'packages/kicksecure/foo/usr/lib/systemd/system/forced-reset.service' <<'EOF'
[Service]
User=nobody
ExecStartPre=+/usr/bin/forced-pre
ExecStartPre=
ExecStart=+/usr/bin/forced-main
EOF

## DynamicUser=yes runs under a dynamic non-root UID -> MUST be excluded.
write 'packages/kicksecure/foo/usr/lib/systemd/system/dynuser.service' <<'EOF'
[Service]
DynamicUser=yes
ExecStart=/usr/bin/dynprog
EOF

## debhelper user-unit SOURCE name -> a user unit -> MUST be excluded.
write 'packages/kicksecure/foo/debian/foo.user.service' <<'EOF'
[Service]
ExecStart=/usr/bin/foouser
EOF

## every Exec* directive that runs as root is captured; a bare ExecStartPre=
## resets ONLY that key (root-pre must NOT survive; cond + cleanup MUST).
write 'packages/kicksecure/foo/usr/lib/systemd/system/execkeys.service' <<'EOF'
[Service]
ExecStartPre=/usr/bin/root-pre
ExecStartPre=
ExecCondition=/usr/bin/root-cond
ExecStart=/usr/bin/root-main
ExecStopPost=/usr/bin/root-cleanup
EOF

## a systemd drop-in that adds Exec programs, with a '+'-prefixed (forced-root)
## ExecStartPre and an ExecStart reset -> enumerated as systemd-dropin.
write 'packages/kicksecure/foo/usr/lib/systemd/system/svc.service.d/30_override.conf' <<'EOF'
[Service]
ExecStartPre=+/usr/lib/root-merger
ExecStart=
ExecStart=/usr/lib/svc --opt
EOF

## a USER-scope drop-in -> excluded.
write 'packages/kicksecure/foo/usr/lib/systemd/user/u.service.d/30_x.conf' <<'EOF'
[Service]
ExecStart=/usr/bin/userdrop
EOF

## a .socket with its own root ExecStartPre + a .timer -> systemd-activation.
write 'packages/kicksecure/foo/usr/lib/systemd/system/foo.socket' <<'EOF'
[Socket]
ListenStream=/run/foo.sock
ExecStartPre=/usr/bin/socket-root-pre
ExecStopPre=/usr/bin/socket-root-stop
Service=foo-worker.service
EOF
write 'packages/kicksecure/foo/usr/lib/systemd/system/foo.timer' <<'EOF'
[Timer]
OnCalendar=daily
Unit=foo-daily.service
EOF

## a template Accept=yes socket -> instantiates <stem>.service (single '@').
write 'packages/kicksecure/foo/usr/lib/systemd/system/tmpl@.socket' <<'EOF'
[Socket]
ListenStream=1234
Accept=yes
EOF

## a .mount does not implicitly activate a same-named service.
write 'packages/kicksecure/foo/usr/lib/systemd/system/data.mount' <<'EOF'
[Mount]
What=/dev/sda1
Where=/data
EOF

## a debhelper .user.timer source name -> user scope -> excluded.
write 'packages/kicksecure/foo/debian/foo.user.timer' <<'EOF'
[Timer]
OnCalendar=daily
EOF

## sudoers: ACTIVE NOPASSWD root rule; commands exclude the arguments.
write 'packages/kicksecure/foo/etc/sudoers.d/active-sudo' <<'EOF'
%sudo ALL=NOPASSWD: /usr/bin/foo --flag /etc/target
EOF

## sudoers granting only a NON-root runas -> grants_root false.
write 'packages/kicksecure/foo/etc/sudoers.d/nonroot-sudo' <<'EOF'
user ALL=(debian-tor) NOPASSWD: /usr/bin/tor --verify-config
EOF

## sudoers whose only directive is commented out -> grants nothing.
write 'packages/kicksecure/foo/etc/sudoers.d/commented-sudo' <<'EOF'
## disabled on purpose
#Defaults env_keep += "X"
EOF

## polkit: TWO actions with DIFFERENT defaults (must not collapse), one id
## single-quoted (valid XML), the first annotating a pkexec helper (exec.path)
## -> both parsed with their own defaults; the root helper path is captured.
write 'packages/kicksecure/foo/usr/share/polkit-1/actions/com.example.test.policy' <<'EOF'
<?xml version="1.0"?>
<policyconfig>
  <action id="com.example.test.do">
    <defaults><allow_active>yes</allow_active></defaults>
    <annotate key='org.freedesktop.policykit.exec.path'>/usr/libexec/foo/pkexec-helper</annotate>
  </action>
  <action id='com.example.test.other'>
    <defaults><allow_active>no</allow_active></defaults>
  </action>
</policyconfig>
EOF

## privilege escalators OTHER than sudo, as shell command words. Lines:
##   2 pkexec prog        -> tool pkexec, root
##   3 pkexec --user u    -> runs_as nobody
##   4 su - user -c cmd   -> tool su, runs_as postgres, command psql
##   5 leaprun action     -> tool leaprun, command is the action name
write 'packages/kicksecure/foo/usr/libexec/foo/escprobe' <<'EOF'
#!/bin/bash
pkexec /usr/bin/pk
pkexec --user nobody /usr/bin/pk2
su - postgres -c "psql"
leaprun grub-password-status-check
EOF

## dm's OWN build script that calls sudo -> a sudo-call under derivative-maker.
write 'help-steps/buildscript' <<'EOF'
#!/bin/bash
sudo apt-get update
EOF

## a chroot helper -> enumerated as build-chroot.
write 'help-steps/foo-chroot-raw' <<'EOF'
#!/bin/bash
sudo mount --bind /a /b
EOF

## config-file root hooks (run as root at their trigger).
write 'packages/kicksecure/foo/usr/lib/udev/rules.d/90-foo.rules' <<'EOF'
ACTION=="add", SUBSYSTEM=="input", RUN+="/usr/bin/udev-root-prog --flag"
ACTION=="add", PROGRAM=="/usr/bin/udev-probe", RUN:="/usr/bin/udev-final"
EOF
write 'packages/kicksecure/foo/usr/share/pam-configs/foo' <<'EOF'
Name: foo
Auth-Type: Primary
Auth: requisite pam_exec.so seteuid quiet_log /usr/libexec/foo/pam-root-prog
EOF
write 'packages/kicksecure/foo/etc/grub.d/10_foo' <<'EOF'
#!/bin/sh
echo menuentry
EOF
## a default/grub.d SNIPPET is config, not a run-as-root script -> excluded.
write 'packages/kicksecure/foo/etc/default/grub.d/foo.cfg' <<'EOF'
GRUB_CMDLINE_LINUX="quiet"
EOF
write 'packages/kicksecure/foo/etc/qubes-rpc/qubes.Foo' <<'EOF'
#!/bin/bash
true
EOF
write 'packages/kicksecure/foo/usr/libexec/foo/policy-rc.d' <<'EOF'
#!/bin/sh
exit 101
EOF
write 'packages/kicksecure/foo/etc/kernel/postinst.d/10_foo' <<'EOF'
#!/bin/sh
true
EOF
write 'packages/kicksecure/foo/usr/share/initramfs-tools/hooks/foo' <<'EOF'
#!/bin/sh
true
EOF

## leaprun --test EXECUTES (not a check); --check is auth-only; and an
## attached short cluster -gusers must not read 'u' as the -u flag.
##   2 --test  -> note leaprun-privleap (executes)
##   3 --check -> note leaprun-privleap-check
##   4 -gusers -> cmd /usr/bin/gcmd, runs_as root (g consumes 'users')
write 'packages/kicksecure/foo/usr/libexec/foo/leapprobe' <<'EOF'
#!/bin/bash
leaprun --test act-test
leaprun --check act-check
sudo -gusers /usr/bin/gcmd
EOF

## a Python allow-list literal (no subprocess call) -> MUST NOT be flagged.
write 'packages/kicksecure/foo/usr/lib/python3/dist-packages/foo/data.py' <<'EOF'
ALLOWED = ["sudo", "doas", "pkexec"]
def ok(name):
    return name in ALLOWED
EOF

## modprobe.d install directive -> runs a command as root on module load.
write 'packages/kicksecure/foo/etc/modprobe.d/30_foo.conf' <<'EOF'
install firewire-core /usr/bin/disabled-firewire-by-foo
install thunderbolt \
  /usr/bin/disabled-thunderbolt-by-foo
blacklist pcspkr
EOF

## Qubes post-install + suspend hooks (run as root by qrexec).
write 'packages/kicksecure/foo/etc/qubes/post-install.d/30-foo.sh' <<'EOF'
#!/bin/bash
qvm-features-request foo
EOF
write 'packages/kicksecure/foo/etc/qubes/suspend-pre.d/30-foo.sh' <<'EOF'
#!/bin/bash
/usr/libexec/foo/suspend-pre
EOF

## /etc/update-motd.d script (run as root at every console login via pam_motd).
write 'packages/kicksecure/foo/etc/update-motd.d/30-foo' <<'EOF'
#!/bin/bash
echo motd
EOF

## a run-parts chroot-scripts-post.d script (run as root in the build chroot).
write 'packages/kicksecure/foo/usr/libexec/foo/chroot-scripts-post.d/80_cleanup' <<'EOF'
#!/bin/bash
apt-get clean
EOF

## build escalation without the word 'sudo': ${SUDO_TO_ROOT} + chroot_run.
write 'help-steps/build-escalate' <<'EOF'
#!/bin/bash
${SUDO_TO_ROOT} losetup --detach /dev/loop0
chroot_run apt-get update
EOF

## a grub.d script SHIPPED from a renamed source and installed via debian/*.links
## into /etc/grub.d/ -> attributed to its install destination.
write 'packages/kicksecure/foo/debian/foo.links' <<'EOF'
/usr/share/foo/conf/grub.d_10_linked /etc/grub.d/10_linked
/usr/share/foo/conf/qubes_post-install.d_50-foo.sh /etc/qubes/post-install.d/50-foo.sh
EOF
write 'packages/kicksecure/foo/usr/share/foo/conf/grub.d_10_linked' <<'EOF'
#!/bin/bash
echo menuentry
EOF
write 'packages/kicksecure/foo/usr/share/foo/conf/qubes_post-install.d_50-foo.sh' <<'EOF'
#!/bin/bash
qvm-features-request foo
EOF

## /etc/default/grub.d/*.cfg -> sourced as root by update-grub.
write 'packages/kicksecure/foo/etc/default/grub.d/50_foo.cfg' <<'EOF'
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX rd.emergency=halt"
EOF

## Calamares installer jobs run as root: a shellprocess script + a process job.
write 'packages/kicksecure/foo/etc/calamares/modules/shellprocess_foo.conf' <<'EOF'
---
dontChroot: true
script:
    - /usr/libexec/foo/cala-script ${ROOT}

    - /usr/libexec/foo/cala-script2
EOF
write 'packages/kicksecure/foo/calamares-modules/foo-job/module.desc' <<'EOF'
---
type: "job"
name: "foo-job"
interface: "process"
command: "/usr/share/calamares/helpers/foo-helper"
EOF
## a module.desc that is NOT a process job -> excluded.
write 'packages/kicksecure/foo/calamares-modules/qml-job/module.desc' <<'EOF'
---
type: "view"
interface: "qtplugin"
EOF

## a data file that merely MENTIONS sudo in prose -> not shell, not scanned.
write 'changelog.upstream' <<'EOF'
* some entry describing how the build must run as root (sudo).
EOF

## --- run + delegate assertions ----------------------------------------------

json="${work_dir}/out.json"
populated_rc=0
"${subject}" "${work_dir}" > "${json}" 2>"${work_dir}/err" || populated_rc=$?

mkdir --parents -- "${work_dir}/empty"
empty_rc=0
"${subject}" "${work_dir}/empty" >/dev/null 2>&1 || empty_rc=$?

if [ "${populated_rc}" -ne 0 ]; then
   printf '%s\n' "note: tool exited ${populated_rc} on the populated tree; stderr:" >&2
   cat -- "${work_dir}/err" >&2 || true
fi

## Independent maintainer recount: enumerate the fixture's debian maintainer
## scripts by a DIFFERENT method (find over debian/ dirs) so a drift in the
## tool's matcher is caught, not masked by re-using the tool's own logic.
maint_count="$(find "${work_dir}" -type f -path '*/debian/*' \
   \( -name '*.preinst' -o -name '*.postinst' -o -name '*.prerm' \
      -o -name '*.postrm' -o -name '*.config' \
      -o -name preinst -o -name postinst -o -name prerm \
      -o -name postrm -o -name config \) | wc -l)"

"${checker}" "${json}" "${populated_rc}" "${empty_rc}" "${maint_count}"
