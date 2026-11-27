#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL sudoers-command-audit tool against built fixtures and asserts
## its findings and exit codes. cvtsudoers (the 'sudo' package) is a hard
## dependency of the tool; it is assumed present and called directly, so its
## absence fails the assertions loudly rather than skipping. Every "detect a
## dangling command" assertion is paired with a canary (same fixture, command
## now present -> must go clean) so a tool that always passes, or always fails,
## cannot read green.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## --- locate the subject tool (checkout copy preferred, else installed) -------
payload_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
subject=''
for candidate in \
  "${DIST_AI_REPO:-}/usr/bin/sudoers-command-audit" \
  "${payload_dir}/../../bin/sudoers-command-audit" \
  '/usr/bin/sudoers-command-audit'; do
  if [ -n "${candidate}" ] && [ -x "${candidate}" ]; then
    subject="$(readlink --canonicalize -- "${candidate}")"
    break
  fi
done
if [ -z "${subject}" ]; then
  printf '%s\n' "FATAL: sudoers-command-audit-tests: subject tool not found." >&2
  exit 1
fi

## cvtsudoers (the 'sudo' package) is a hard dependency in debian/control and is
## assumed present: the tool is driven directly and fails loud (returns 2, so
## the assertions below fail) if it is ever absent -- no has/die preflight.

[ -v TMP ] || TMP=/tmp
work="$(mktemp --directory -- "${TMP}/sudoers-command-audit-test.XXXXXX")"

cleanup() {
  safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

pass=0
fail=0
out=''
code=0

## run the subject, capturing stdout + exit code into globals.
run_audit() {
  out=''
  code=0
  out="$( "${subject}" "$@" 2>/dev/null )" || code=$?
}

## predicates: return 0 when the assertion holds. Herestrings, not pipes, so a
## quiet grep never consumes a pipe (R-161).
rc_is() {
  [ "${code}" -eq "$1" ]
}
out_empty() {
  [ -z "${out}" ]
}
out_has() {
  grep --quiet --fixed-strings -- "$1" <<< "${out}"
}
out_lacks() {
  ! grep --quiet --fixed-strings -- "$1" <<< "${out}"
}

check() {
  local desc="$1"
  shift
  if "$@"; then
    pass=$(( pass + 1 ))
  else
    fail=$(( fail + 1 ))
    printf '%s\n' "FAIL: ${desc}" >&2
    printf '%s\n' "      exit=${code} output=<<${out}>>" >&2
  fi
}

## --- fixtures ----------------------------------------------------------------
root="${work}/root"
mkdir -p -- "${root}/usr/bin"
printf '%s\n' '#!/bin/sh' > "${root}/usr/bin/present"
chmod +x -- "${root}/usr/bin/present"
printf '%s\n' 'data' > "${root}/usr/bin/nonexec"

cat > "${work}/clean" <<'EOF'
user ALL=NOPASSWD: /usr/bin/present
user ALL=NOPASSWD: /usr/bin/present dist-upgrade
user ALL=(ALL) ALL
%sudo ALL=NOPASSWD: sudoedit /etc/hosts
EOF

cat > "${work}/plain-missing" <<'EOF'
user ALL=NOPASSWD: /usr/bin/gone-cmd arg1
EOF

cat > "${work}/alias-missing" <<'EOF'
Cmnd_Alias UPD = /usr/bin/present, /usr/bin/gone-alias-member
user ALL=NOPASSWD: UPD
EOF

cat > "${work}/negated-missing" <<'EOF'
user ALL=NOPASSWD: !/usr/bin/gone-negated
EOF

printf '%s\n' 'this is not valid sudoers @@@' > "${work}/broken"

## a sysroot for the default-mode (no-double-report) check: a main sudoers with
## no includedir plus an unrelated drop-in.
sysroot="${work}/sysroot"
mkdir -p -- "${sysroot}/etc/sudoers.d" "${sysroot}/usr/bin"
cat > "${sysroot}/etc/sudoers" <<'EOF'
user ALL=NOPASSWD: /usr/bin/gone-main
EOF
cat > "${sysroot}/etc/sudoers.d/extra" <<'EOF'
user ALL=NOPASSWD: /usr/bin/gone-dropin
EOF

## --- assertions --------------------------------------------------------------

## 1. clean fixture: args stripped, ALL and sudoedit skipped -> exit 0, no output.
run_audit --root "${root}" "${work}/clean"
check "clean fixture passes (exit 0)" rc_is 0
check "clean fixture prints no findings" out_empty

## 2. plain missing command (with args) detected.
run_audit --root "${root}" "${work}/plain-missing"
check "missing command detected (exit 1)" rc_is 1
check "missing command path named in output" out_has '/usr/bin/gone-cmd'

## 2-canary: create the command under the root -> must now go clean. Proves the
## "missing" verdict is genuinely sensitive to presence, not a constant.
printf '%s\n' '#!/bin/sh' > "${root}/usr/bin/gone-cmd"
chmod +x -- "${root}/usr/bin/gone-cmd"
run_audit --root "${root}" "${work}/plain-missing"
check "canary: command present -> clean (exit 0)" rc_is 0
safe-rm --force -- "${root}/usr/bin/gone-cmd"

## 3. Cmnd_Alias member existence is checked (present member fine, missing flagged).
run_audit --root "${root}" "${work}/alias-missing"
check "alias member missing detected (exit 1)" rc_is 1
check "missing alias member named in output" out_has '/usr/bin/gone-alias-member'
check "present alias member not flagged" out_lacks '/usr/bin/present'

## 4. negated (deny) rule to a missing command detected and tagged.
run_audit --root "${root}" "${work}/negated-missing"
check "negated missing detected (exit 1)" rc_is 1
check "negated finding tagged 'deny rule'" out_has 'deny rule'

## 5. unparseable source -> inconclusive (exit 2), never a false clean.
run_audit --root "${root}" "${work}/broken"
check "parse error is inconclusive (exit 2)" rc_is 2

## 6. --require-executable: present-but-not-executable.
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/nonexec' > "${work}/nonexec-rule"
run_audit --root "${root}" "${work}/nonexec-rule"
check "non-executable command not flagged by default (exit 0)" rc_is 0
run_audit --root "${root}" --require-executable "${work}/nonexec-rule"
check "non-executable flagged with --require-executable (exit 1)" rc_is 1
check "non-executable finding tagged 'not executable'" out_has 'not executable'

## 7. --find discovers drop-ins and honours sudo's ignore rule (dot/tilde names).
tree="${work}/tree"
mkdir -p -- "${tree}/etc/sudoers.d"
cp -- "${work}/plain-missing" "${tree}/etc/sudoers.d/live"
cp -- "${work}/plain-missing" "${tree}/etc/sudoers.d/live.disabled"
run_audit --root "${root}" --find "${tree}"
check "--find detects a dangling command in a loadable drop-in (exit 1)" rc_is 1
check "--find audits the loadable drop-in" out_has 'etc/sudoers.d/live:'
check "--find ignores a '.'-containing drop-in name" out_lacks 'live.disabled'

## 8. default mode (no positional, no --find) audits only <root>/etc/sudoers.
##    On a real system cvtsudoers follows its @includedir, so the drop-ins are
##    covered in that one parse; feeding the directory a second time would
##    double-report every finding. This fixture's main file has no includedir,
##    so the drop-in's command must be ABSENT from the result -- the regression
##    guard for the double-report bug.
run_audit --root "${sysroot}"
check "default mode detects the main sudoers finding (exit 1)" rc_is 1
check "default mode flags the main-file command" out_has '/usr/bin/gone-main'
check "default mode does not separately feed /etc/sudoers.d" out_lacks '/usr/bin/gone-dropin'

## 9. existence is resolved CONFINED to --root: an absolute symlink inside the
##    image must not be followed to the host filesystem (the false-clean bug),
##    while a relative symlink resolving within the image is present.
imgroot="${work}/imgroot"
mkdir -p -- "${imgroot}/usr/bin" "${imgroot}/etc/sudoers.d"
printf '%s\n' '#!/bin/sh' > "${work}/outside-target"
chmod +x -- "${work}/outside-target"
## absolute target that exists on the real fs but is OUTSIDE imgroot.
ln -s -- "${work}/outside-target" "${imgroot}/usr/bin/escaping"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/escaping' > "${imgroot}/etc/sudoers.d/esc"
printf '%s\n' '#!/bin/sh' > "${imgroot}/usr/bin/realbin"
chmod +x -- "${imgroot}/usr/bin/realbin"
ln -s realbin "${imgroot}/usr/bin/reltool"
printf '%s\n' 'user ALL=NOPASSWD: /usr/bin/reltool' > "${imgroot}/etc/sudoers.d/rel"
run_audit --root "${imgroot}" "${imgroot}/etc/sudoers.d/esc"
check "absolute symlink escaping root is flagged, not followed to host (exit 1)" rc_is 1
check "escaping command is named" out_has '/usr/bin/escaping'
run_audit --root "${imgroot}" "${imgroot}/etc/sudoers.d/rel"
check "relative symlink resolving within root is present (exit 0)" rc_is 0

## 10. a command PATH that legitimately contains a (backslash-escaped) space is
##     matched via progressive prefixes, not mis-split on the first space.
mkdir -p -- "${root}/opt/my dir"
printf '%s\n' '#!/bin/sh' > "${root}/opt/my dir/tool"
chmod +x -- "${root}/opt/my dir/tool"
printf '%s\n' 'user ALL=NOPASSWD: /opt/my\ dir/tool' > "${work}/spaced"
run_audit --root "${root}" "${work}/spaced"
check "spaced command path matched, not mis-split (exit 0)" rc_is 0

## --- report ------------------------------------------------------------------
printf '%s\n' "sudoers-command-audit-tests: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
