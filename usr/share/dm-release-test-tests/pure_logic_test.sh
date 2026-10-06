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

## pair-version marker parse: VBoxManage prints "Value: <v>" for a set key and
## "No value set!" for an unset one. Canary: a naive impl that echoed the whole line
## would pass "No value set!" through as a value instead of rejecting it.
assert_out "parse extradata value" "18.2.3.5" rt_parse_extradata "Value: 18.2.3.5"
assert_reject "parse extradata unset" rt_parse_extradata "No value set!"
assert_reject "parse extradata empty" rt_parse_extradata ""

## pair-version gate: both VMs must carry the REQUESTED version. Canaries: an impl that
## checked only the GW would pass a stale WS; one that skipped the empty-requested guard
## would pass a markerless pair ("" == "" == "").
assert_out "pair version both match" "" rt_pair_version_ok 18.2.3.5 18.2.3.5 18.2.3.5
assert_reject "pair version gw mismatch" rt_pair_version_ok 18.2.3.5 18.2.3.3 18.2.3.5
assert_reject "pair version ws mismatch" rt_pair_version_ok 18.2.3.5 18.2.3.5 18.2.3.3
assert_reject "pair version gw unset" rt_pair_version_ok 18.2.3.5 "" 18.2.3.5
assert_reject "pair version requested empty" rt_pair_version_ok "" "" ""

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
## fail-CLOSED on empty groups: `id -nG` failure (NSS/initgroups) yields "" -> must REJECT,
## not vacuously accept. Canary: the old loop-only body skipped the loop and returned 0.
assert_reject "unpriv: empty group list fails closed" rt_account_unprivileged u 5001 u ""

## rt_account_can_sudo reports the EXERCISED sudo's rc (0 => passwordless root granted),
## NOT a listing (`sudo -l` exits 0 for everyone). Real passwordless-root semantics are
## verified live in the sandbox; here a runuser+sudo PATH stub pins the rc wiring + the
## fail-CLOSED behaviour. Subshell PATH overrides (a `VAR=val funcname` prefix persists
## in bash, which would leak the stub PATH into later assertions).
cansudo_stub="$(mktemp --directory)"
printf '%s\n' '#!/bin/bash' 'shift 2' 'exec "$@"' > "${cansudo_stub}/runuser"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${cansudo_stub}/sudo"
chmod +x -- "${cansudo_stub}/runuser" "${cansudo_stub}/sudo"
## Probe rt_account_can_sudo with a chosen PATH in a subshell -- overriding PATH is the
## point (command resolution), and the subshell keeps it from leaking into later tests.
## Capture the real PATH under another name so the call sites never read PATH directly.
cansudo_origpath="${PATH}"
# shellcheck disable=SC2030,SC2031,SC2123
cansudo_probe() { ( PATH="$1"; rt_account_can_sudo acct ); }
if cansudo_probe "${cansudo_stub}:${cansudo_origpath}"; then
   printf 'ok: rt_account_can_sudo true when the exercised sudo succeeds\n'
else
   printf 'FAIL: rt_account_can_sudo false though sudo exited 0\n' >&2; failures=$((failures + 1))
fi
printf '%s\n' '#!/bin/bash' 'exit 1' > "${cansudo_stub}/sudo"
if cansudo_probe "${cansudo_stub}:${cansudo_origpath}"; then
   printf 'FAIL: rt_account_can_sudo true though sudo exited 1\n' >&2; failures=$((failures + 1))
else
   printf 'ok: rt_account_can_sudo false when the exercised sudo fails\n'
fi
## fail-CLOSED: probe tools absent => report "can sudo" so the caller REJECTS (a missing
## runuser must never read as "account is clean"). Canary: the old no-guard body exited
## 127 -> `! rt_account_can_sudo` true -> a privileged account wrongly accepted.
if cansudo_probe "${cansudo_stub}/none"; then
   printf 'ok: rt_account_can_sudo fails closed when probe tools are absent\n'
else
   printf 'FAIL: rt_account_can_sudo failed OPEN with runuser/sudo absent\n' >&2; failures=$((failures + 1))
fi
safe-rm --recursive --force -- "${cansudo_stub}"

## rt_require_account_unprivileged: the single fail-closed privilege gate every test
## account passes through. Stub id + rt_account_can_sudo in a subshell so the real die's
## exit is CONTAINED, then assert the exit status (SETUP_RC on refusal, 0 on a clean
## account). $1=uid $2=primary-group $3=`id -nG` groups $4=can_sudo rc.
gate_probe() {
   ## SETUP_RC feeds the real gate's `die "${SETUP_RC}"`; id/rt_account_can_sudo/die are
   ## stubs the SOURCED gate calls indirectly -- invisible to shellcheck, hence the disables.
   # shellcheck disable=SC2034,SC2317
   (
      SETUP_RC=2
      _u="$1"; _p="$2"; _g="$3"; _cs="$4"
      id() { case "$1" in -u) printf '%s\n' "${_u}";; -gn) printf '%s\n' "${_p}";; -nG) printf '%s\n' "${_g}";; esac; }
      rt_account_can_sudo() { return "${_cs}"; }
      die() { exit "$1"; }
      rt_require_account_unprivileged acct blessed
   )
}
gate_rc=0; gate_probe 1000 acct "acct vboxusers" 1 || gate_rc=$?
if [ "${gate_rc}" -eq 0 ]; then
   printf 'ok: gate passes a clean unprivileged account\n'
else
   printf 'FAIL: gate rejected a clean account (rc=%s)\n' "${gate_rc}" >&2; failures=$((failures + 1))
fi
gate_rc=0; gate_probe 1000 acct "acct vboxusers" 0 || gate_rc=$?
if [ "${gate_rc}" -eq 2 ]; then
   printf 'ok: gate refuses a passwordless-sudo account (SETUP_RC)\n'
else
   printf 'FAIL: gate did not refuse a sudo-capable account (rc=%s, want 2)\n' "${gate_rc}" >&2; failures=$((failures + 1))
fi
gate_rc=0; gate_probe 0 acct "acct vboxusers" 1 || gate_rc=$?
if [ "${gate_rc}" -eq 2 ]; then
   printf 'ok: gate refuses a uid-0 account (SETUP_RC)\n'
else
   printf 'FAIL: gate did not refuse uid 0 (rc=%s, want 2)\n' "${gate_rc}" >&2; failures=$((failures + 1))
fi
gate_rc=0; gate_probe 1000 acct "acct sudo" 1 || gate_rc=$?
if [ "${gate_rc}" -eq 2 ]; then
   printf 'ok: gate refuses a privileged-group account (SETUP_RC)\n'
else
   printf 'FAIL: gate did not refuse a privileged group (rc=%s, want 2)\n' "${gate_rc}" >&2; failures=$((failures + 1))
fi

## Call-site canary: EVERY account kind -- ephemeral (test), leak, AND blessed -- must be
## wired through the gate. The blessed wiring is the regression: before it, a privileged
## persist-stable- account ran a test unchecked (isolation-boundary gap). Fails on the old
## code, where the 'blessed' call was absent.
for role in test leak blessed; do
   if grep --quiet --fixed-strings "rt_require_account_unprivileged \"\${account}\" ${role}" "${subject}"; then
      printf 'ok: %s account wired through the privilege gate\n' "${role}"
   else
      printf 'FAIL: %s account not routed through rt_require_account_unprivileged\n' "${role}" >&2; failures=$((failures + 1))
   fi
done

if [ "${failures}" -ne 0 ]; then
   printf '\n%s assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall pure-logic assertions passed\n'
