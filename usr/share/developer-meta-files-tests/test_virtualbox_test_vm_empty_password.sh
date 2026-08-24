#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-virtualbox-test-vm': the guest
## account is passwordless (helper-scripts user_create.bsh 'passwd --delete'), so
## guest LOGIN auth is an EMPTY password.
##
## THE BUG IT GUARDS: the sudo wrapper was a word-split STRING with an unquoted
## '--password ${password}'. With an empty password the token collapses and the
## NEXT flag ('--wait-stdout') is read as the password value -- so the login is
## wrong AND '--wait-stdout' is silently consumed. The fix makes the wrapper an
## ARRAY, where '--password ""' survives as a distinct empty argument.
##
## Drives the REAL variables() (extracted from the shipped script) and inspects
## the argv it hands to VBoxManage via a stub -- no real VM needed. (End-to-end
## guestcontrol login still needs a running VM; that is out of scope here.)
##
## Self-contained; detects nothing external, so no has()/command -v needed.
## Needs no root, no network, no VM.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}

rel='usr/bin/dm-virtualbox-test-vm'
candidates=()
[ -z "${DM_VIRTUALBOX_TEST_VM:-}" ] || candidates+=( "${DM_VIRTUALBOX_TEST_VM}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-virtualbox-test-vm not found (set DM_VIRTUALBOX_TEST_VM)." >&2
   exit 1
fi

## Extract the REAL variables() function (its closing brace is the first
## line-initial '}' after the definition).
func_src="$(sed -n '/^variables()/,/^}/p' -- "${subject}")"
if [ -z "${func_src}" ]; then
   printf '%s\n' "FATAL: could not extract variables() from ${subject}." >&2
   exit 1
fi

## --- STRUCTURAL --------------------------------------------------------------
if grep --quiet --fixed-strings -- 'password=""' <<< "${func_src}"; then
   pass "structural: guest login password is empty (passwordless account)"
else
   fail "structural: password is not empty; the passwordless guest login needs password=\"\""
fi
if grep --quiet --fixed-strings -- 'password="changeme"' <<< "${func_src}"; then
   fail "structural: password is still 'changeme'; the guest account is passwordless now"
else
   pass "structural: the old 'changeme' password is gone"
fi
if grep --quiet --extended-regexp -- 'vboxmanage_sudo_wrapper=\(' <<< "${func_src}"; then
   pass "structural: the sudo wrapper is an array (empty --password survives word-splitting)"
else
   fail "structural: the sudo wrapper is not an array; an empty --password would collapse"
fi

## --- BEHAVIOURAL: the argv actually carries an empty password ----------------
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## Stub VBoxManage: print each argv element wrapped in [] (so an empty one shows
## as '[]') on its own line, then succeed.
stub_bin="${workdir}/bin"
mkdir --parents -- "${stub_bin}"
cat > "${stub_bin}/VBoxManage" <<'STUB'
#!/bin/bash
for stub_arg in "$@"; do
   printf '%s\n' "[${stub_arg}]"
done
STUB
chmod 0755 -- "${stub_bin}/VBoxManage"

## Source the extracted function, call it, then invoke the wrapper array against
## the stub and capture the argv it received.
argv_file="${workdir}/argv.txt"
func_file="${workdir}/variables.bsh"
printf '%s\n' "${func_src}" > "${func_file}"
(
   PATH="${stub_bin}:${PATH}"
   # shellcheck disable=SC1090 # path resolved at runtime
   source "${func_file}"
   variables
   "${vboxmanage_sudo_wrapper[@]}" MARKER-COMMAND
) > "${argv_file}"

## The token immediately after [--password] must be [] (empty), NOT [--wait-stdout].
mapfile -t argv_lines < "${argv_file}"
password_index=-1
for line_index in "${!argv_lines[@]}"; do
   if [ "${argv_lines[line_index]}" = '[--password]' ]; then
      password_index="${line_index}"
      break
   fi
done
if [ "${password_index}" -lt 0 ]; then
   fail "behavioural: no --password flag reached VBoxManage argv"
else
   next_index=$(( password_index + 1 ))
   next_token="${argv_lines[next_index]:-<none>}"
   if [ "${next_token}" = '[]' ]; then
      pass "behavioural: --password is followed by a distinct EMPTY argument"
   else
      fail "behavioural: --password is followed by '${next_token}', not an empty argument (it collapsed)"
   fi
fi
## And the flag after the empty password must still be --wait-stdout (not eaten).
if grep --quiet --fixed-strings -- '[--wait-stdout]' <<< "${argv_lines[@]}"; then
   pass "behavioural: --wait-stdout survived (not consumed as the password value)"
else
   fail "behavioural: --wait-stdout is missing from argv; it was eaten as the password"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-virtualbox-test-vm passwordless guest login (${pass_count} assertions)."
