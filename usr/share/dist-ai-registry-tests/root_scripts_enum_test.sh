#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-root-scripts-enum: the four root-privileged categories are enumerated
## correctly, and -- the part that must never regress -- the build-time sudo
## reader stays a SIMPLE match, not a bash parser:
##
##   - 'sudo' as an ARGUMENT (adduser user sudo) is not an invocation.
##   - 'sudo' inside prose ("... run as root (sudo)!") is not an invocation.
##   - 'sudo -u root cmd' resolves to cmd, not to the -u argument 'root'.
##   - a program hidden in a variable/subshell/continuation is NOT guessed;
##     it is reported as note=notify for a human.
##
## A refactor that "improves" the reader into parsing quoted strings would flip
## these, so they are pinned. Also pinned: the exclusions (user-scope and
## non-root systemd units, non-debian .config files, all-commented sudoers) and
## the empty-tree-fails-loudly property every audit in this repo carries.
##
## This builds a fixture TREE (controlled input for the enumerator, like the
## sibling stripped_setx_audit_test.sh) and drives the REAL tool from the
## checkout; the per-entry assertions live in the standalone checker beside it.
## No git, no root, no network.

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

## maintainer script (root via dpkg) -- MUST be found.
write 'packages/kicksecure/foo/debian/foo.postinst' <<'EOF'
#!/bin/bash
true
EOF

## a .config that is NOT a maintainer script -- MUST be excluded.
write 'packages/kicksecure/foo/etc/skel/.config' <<'EOF'
not a maintainer script
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

## dm's OWN build script -- the sudo-reader torture test. Line numbers matter:
##   2 real     -> apt-get
##   3 -u root  -> chown (not 'root')
##   4 prose    -> dropped
##   5 argument -> dropped
##   6 variable -> notify
write 'help-steps/buildscript' <<'EOF'
#!/bin/bash
sudo apt-get update
sudo -u root chown root:root /some/path
true "This must run as root (sudo)!"
adduser tempuser sudo
sudo "${opts[@]}" test -d /usr
EOF

## a chroot helper -> flagged runs_in_chroot_as_root.
write 'help-steps/foo-chroot-raw' <<'EOF'
#!/bin/bash
sudo mount --bind /a /b
EOF

## a big data file that merely MENTIONS sudo in prose -> never build orchestration.
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

"${checker}" "${json}" "${populated_rc}" "${empty_rc}"
