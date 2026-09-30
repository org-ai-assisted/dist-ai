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

## sudoers with an ACTIVE NOPASSWD rule -> grants_root true.
write 'packages/kicksecure/foo/etc/sudoers.d/active-sudo' <<'EOF'
%sudo ALL=NOPASSWD: /usr/bin/foo
EOF

## sudoers whose only directive is commented out -> grants nothing.
write 'packages/kicksecure/foo/etc/sudoers.d/commented-sudo' <<'EOF'
## disabled on purpose
#Defaults env_keep += "X"
EOF

## polkit action definition -> found.
write 'packages/kicksecure/foo/usr/share/polkit-1/actions/com.example.test.policy' <<'EOF'
<?xml version="1.0"?>
<policyconfig>
  <action id="com.example.test.do">
    <defaults><allow_active>yes</allow_active></defaults>
  </action>
</policyconfig>
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
