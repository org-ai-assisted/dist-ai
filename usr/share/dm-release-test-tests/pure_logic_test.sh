#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests dm-release-test's pure-logic helpers by sourcing the REAL script
## (its main() is guarded, so sourcing defines the functions without running).
## Canary-oriented: each case fails on a no-op/loosened implementation (e.g. a
## version token that kept its dots would break the account-name charset).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf 'FATAL: dm-release-test not found at %s\n' "${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

failures=0

## Assert a function prints exactly the expected value and exits 0.
assert_out() {
   local label expected out rc
   label="$1"
   expected="$2"
   shift 2
   rc=0
   out="$("$@")" || rc=$?
   if [ "${rc}" -ne 0 ]; then
      printf 'FAIL: %s: rc=%s (expected output %s)\n' "${label}" "${rc}" "${expected}" >&2
      failures=$((failures + 1))
      return
   fi
   if [ "${out}" != "${expected}" ]; then
      printf 'FAIL: %s: got %s, expected %s\n' "${label}" "'${out}'" "'${expected}'" >&2
      failures=$((failures + 1))
      return
   fi
   printf 'ok: %s\n' "${label}"
}

## Assert a function exits non-zero (rejects bad input).
assert_reject() {
   local label rc
   label="$1"
   shift
   rc=0
   "$@" >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -eq 0 ]; then
      printf 'FAIL: %s: expected non-zero rc, got 0\n' "${label}" >&2
      failures=$((failures + 1))
      return
   fi
   printf 'ok: %s (rejected, rc=%s)\n' "${label}" "${rc}"
}

## guest validation
assert_out "guest kicksecure valid" "" rt_guest_valid kicksecure
assert_out "guest whonix valid" "" rt_guest_valid whonix
assert_reject "guest debian rejected" rt_guest_valid debian
assert_reject "guest empty rejected" rt_guest_valid ""

## interface -> published desktop token
assert_out "desktop lxqt" "LXQt" rt_desktop_token lxqt
assert_out "desktop xfce" "Xfce" rt_desktop_token xfce
assert_out "desktop cli" "CLI" rt_desktop_token cli
assert_reject "desktop gnome rejected" rt_desktop_token gnome

## version -> username token (dots become dashes; canary: a no-op keeps dots)
assert_out "version token dotted" "18-2-3-5" rt_version_token 18.2.3.5
assert_out "version token short" "18-2" rt_version_token 18.2
assert_reject "version with letter rejected" rt_version_token 1.2a
assert_reject "version empty rejected" rt_version_token ""
## length bound (the leak/blessed lanes skip the account-name ceiling): 33 chars reject
assert_reject "version token over 32 chars" rt_version_token 123456789012345678901234567890123

## ephemeral account name
assert_out "eph account kicksecure" "eph-run-kicksecure-18-2-3-5" rt_eph_account kicksecure 18-2-3-5
assert_out "eph account whonix" "eph-run-whonix-18-2-3-5" rt_eph_account whonix 18-2-3-5
assert_reject "eph account bad charset" rt_eph_account kicksecure "18_2"
## 32-char ceiling: eph-run-kicksecure- is 19 chars, so a 14+ char token overflows.
assert_reject "eph account over 32 chars" rt_eph_account kicksecure "1-2-3-4-5-6-7-8"

## bless-state
assert_out "bless equal" "blessed" rt_bless_state 18.2.3.5 18.2.3.5
assert_out "bless differ" "prebless" rt_bless_state 18.2.3.5 18.2.3.3

## account selection by bless-state
assert_out "select blessed golden" "persist-stable-kicksecure" rt_select_account kicksecure blessed 18-2-3-5
assert_out "select prebless eph" "eph-run-whonix-18-2-3-5" rt_select_account whonix prebless 18-2-3-5
assert_reject "select unknown state" rt_select_account kicksecure bogus 18-2-3-5

## leak-lane + leak-account predicates: the whonix lane IS the leak test and ALWAYS
## uses the dedicated, persistent persist-leak- account, never a shared namespace.
## rt_account_is_leak must REJECT the golden persist-stable- and the install eph-run-
## accounts, so the leak lane can never be handed a potentially-contaminated account.
assert_out "whonix is leak lane" "" rt_lane_is_leak whonix
assert_reject "kicksecure not leak lane" rt_lane_is_leak kicksecure
assert_out "persist-leak- is a leak account" "" rt_account_is_leak persist-leak-whonix
assert_reject "persist-stable- not a leak account" rt_account_is_leak persist-stable-whonix
assert_reject "eph-run- not a leak account" rt_account_is_leak eph-run-whonix-18-2-3-5

## host-privilege gate: uid != 0, PRIMARY group == the account's own private group, and
## every group is that private group or vboxusers. Canaries: a group denylist would pass
## docker/disk; blind-trusting the primary would pass a privileged primary; and a SHARED
## primary (users/vboxusers, group-writable files) would break isolation -- all rejected.
assert_out "unpriv: private primary + vboxusers" "" rt_account_unprivileged persist-leak-whonix 5001 persist-leak-whonix "persist-leak-whonix vboxusers"
assert_out "unpriv: private primary alone" "" rt_account_unprivileged u 5001 u "u"
assert_reject "unpriv: shared vboxusers primary rejected" rt_account_unprivileged u 5001 vboxusers "vboxusers"
assert_reject "unpriv: shared users primary rejected" rt_account_unprivileged u 5001 users "users vboxusers"
assert_reject "unpriv: docker supplementary rejected" rt_account_unprivileged u 5001 u "u docker vboxusers"
assert_reject "unpriv: disk supplementary rejected" rt_account_unprivileged u 5001 u "u disk vboxusers"
assert_reject "unpriv: sudo supplementary rejected" rt_account_unprivileged u 5001 u "u sudo"
assert_reject "unpriv: privileged primary root rejected" rt_account_unprivileged u 5001 root "root vboxusers"
assert_reject "unpriv: privileged primary docker rejected" rt_account_unprivileged u 5001 docker "docker vboxusers"
assert_reject "unpriv: uid 0 rejected" rt_account_unprivileged u 0 u "u vboxusers"

## rt_account_can_sudo reports the EXERCISED sudo's rc (0 => passwordless root granted),
## NOT a listing (`sudo -l` exits 0 for everyone). Real passwordless-root semantics are
## verified live in the sandbox; here a runuser+sudo PATH stub pins the rc wiring.
cansudo_stub="$(mktemp --directory)"
printf '%s\n' '#!/bin/bash' 'shift 2' 'exec "$@"' > "${cansudo_stub}/runuser"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${cansudo_stub}/sudo"
chmod +x -- "${cansudo_stub}/runuser" "${cansudo_stub}/sudo"
if PATH="${cansudo_stub}:${PATH}" rt_account_can_sudo acct; then
   printf 'ok: rt_account_can_sudo true when the exercised sudo succeeds\n'
else
   printf 'FAIL: rt_account_can_sudo false though sudo exited 0\n' >&2; failures=$((failures + 1))
fi
printf '%s\n' '#!/bin/bash' 'exit 1' > "${cansudo_stub}/sudo"
if PATH="${cansudo_stub}:${PATH}" rt_account_can_sudo acct; then
   printf 'FAIL: rt_account_can_sudo true though sudo exited 1\n' >&2; failures=$((failures + 1))
else
   printf 'ok: rt_account_can_sudo false when the exercised sudo fails\n'
fi
safe-rm --recursive --force -- "${cansudo_stub}"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall pure-logic assertions passed\n'
