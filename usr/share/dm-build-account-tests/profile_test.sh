#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-build-account provisions the PRIVILEGED build account persist-bild-<guest> -- the
## inverse of dm-release-test's unprivileged, leak-dropped install accounts. Drive the
## REAL script under a stub PATH (no root, no system mutation) and assert the build
## profile: private primary group, sysmaint (sudo-exec on the hardened host), passwordless
## sudo, and -- the load-bearing safety properties -- NO vboxusers and a name OUTSIDE the
## host nftables leak-drop patterns. Canary: dropping sysmaint, adding vboxusers, or a
## non-NOPASSWD sudoers each fail a distinct assertion below.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_BUILD_ACCOUNT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-build-account" ]; then
      subject="${test_dir}/../../bin/dm-build-account"
   else
      subject='/usr/bin/dm-build-account'
   fi
fi
[ -r "${subject}" ] || { printf 'FATAL: dm-build-account not found at %s\n' "${subject}" >&2; exit 1; }

failures=0
ok()  { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }

work="$(mktemp --directory)"
## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
test_cleanup_handler() {
   safe-rm --recursive --force -- "${work}" || true
}
trap test_cleanup_handler EXIT

stub_bin="${work}/bin"
calls="${work}/calls.log"
sudoers_d="${work}/sudoers.d"
mkdir --parents -- "${stub_bin}" "${sudoers_d}"

## Stubs: record argv, and return the status the real flow expects. getent reports the
## account ABSENT (exit 1) so the useradd branch runs; id -u is root and the account has
## its private primary group plus sysmaint; visudo/runuser/useradd/usermod succeed.
## STUB_* env knobs force the other branches. chmod/mktemp/mv are the real binaries.
make_stub() {
   local name="$1" body="$2"
   {
      printf '#!/bin/bash\n'
      printf 'printf "%%s %%s\\n" "%s" "$*" >> "%s"\n' "${name}" "${calls}"
      printf '%s\n' "${body}"
   } > "${stub_bin}/${name}"
   chmod +x "${stub_bin}/${name}"
}
## The single-quoted bodies expand in the STUB, not here.
# shellcheck disable=SC2016
make_stub id '
case "$1" in
   -u) printf "0\n" ;;
   --group) printf "%s\n" "${STUB_PRIMARY_GROUP:-${!#}}" ;;
   --groups) printf "%s\n" "${STUB_GROUPS:-${!#} sysmaint}" ;;
esac'
# shellcheck disable=SC2016
make_stub getent   'exit "${STUB_GETENT_RC:-1}"'
make_stub useradd  'exit 0'
make_stub usermod  'exit 0'
# shellcheck disable=SC2016
make_stub visudo   'exit "${STUB_VISUDO_RC:-0}"'
make_stub runuser  'exit 0'
true >| "${calls}"

run_subject() {
   PATH="${stub_bin}:${PATH}" \
   DM_BUILD_ACCOUNT_SUDOERS_DIR="${sudoers_d}" \
      bash "${subject}" "$@"
}

## 1. happy path: kicksecure
true >| "${calls}"
safe-rm --force -- "${sudoers_d}"/* 2>/dev/null || true
if out="$(run_subject kicksecure 2>&1)"; then
   ok 'dm-build-account kicksecure exits 0'
else
   bad "dm-build-account kicksecure exited non-zero: ${out}"
fi

## 2. final line is the account name (callers capture it)
if [ "$(printf '%s\n' "${out}" | tail -1)" = 'persist-bild-kicksecure' ]; then
   ok 'prints persist-bild-kicksecure as the last line'
else
   bad "last line not the account name: $(printf '%s\n' "${out}" | tail -1)"
fi

## 3. private primary group (no shared-group privilege bleed)
if grep --quiet --extended-regexp '^useradd .*--user-group' "${calls}"; then
   ok 'useradd uses --user-group (private primary)'
else
   bad 'useradd missing --user-group'
fi

## 4. sysmaint granted (needed to EXECUTE the 4750 root:sysmaint sudo)
if grep --quiet --extended-regexp '^usermod .*--groups sysmaint' "${calls}"; then
   ok 'usermod grants sysmaint'
else
   bad 'usermod does not grant sysmaint'
fi

## 5. SAFETY: never vboxusers (a build drives no VirtualBox)
if grep --quiet --ignore-case --extended-regexp 'vboxusers' "${calls}"; then
   bad 'build account was granted vboxusers (must not be)'
else
   ok 'no vboxusers grant'
fi

## 6. passwordless sudo written + validated
sudoers_file="${sudoers_d}/persist-bild-kicksecure"
if [ -f "${sudoers_file}" ] && grep --quiet --extended-regexp 'NOPASSWD:ALL' "${sudoers_file}"; then
   ok 'NOPASSWD sudoers entry written'
else
   bad 'NOPASSWD sudoers entry missing'
fi
if grep --quiet --extended-regexp '^visudo .*--check' "${calls}"; then
   ok 'sudoers validated with visudo --check'
else
   bad 'sudoers not validated with visudo --check'
fi

## 7. SAFETY: name is OUTSIDE the host leak-drop patterns, so the build keeps network
## and an install account can never collide with it.
account='persist-bild-kicksecure'
leak_dropped='false'
case "${account}" in
   persist-inst-* | eph-inst-* | persist-leak-* | eph-leak-*)
      leak_dropped='true'
      ;;
esac
if [ "${leak_dropped}" = 'false' ]; then
   ok 'account name is outside the nftables leak-drop patterns (networked)'
else
   bad 'account name matches a leak-drop pattern (would lose network)'
fi

## 8. whonix variant
true >| "${calls}"
if out2="$(run_subject whonix 2>&1)" \
   && [ "$(printf '%s\n' "${out2}" | tail -1)" = 'persist-bild-whonix' ]; then
   ok 'whonix variant -> persist-bild-whonix'
else
   bad "whonix variant wrong: ${out2}"
fi

## 9. rejects an unknown guest (exit 2), does not provision
true >| "${calls}"
rc=0
run_subject bogus >/dev/null 2>&1 || rc=$?
if [ "${rc}" = '2' ] && ! grep --quiet --extended-regexp '^useradd' "${calls}"; then
   ok 'unknown guest rejected (exit 2), no useradd'
else
   bad "unknown guest not rejected cleanly (rc=${rc})"
fi

## 10. an EXISTING account in vboxusers is refused, not reported ready, and gets no
## sudoers rule.
true >| "${calls}"
safe-rm --force -- "${sudoers_d}"/* 2>/dev/null || true
rc=0
out3="$(STUB_GETENT_RC=0 STUB_GROUPS='persist-bild-kicksecure sysmaint vboxusers' \
   run_subject kicksecure 2>&1)" || rc=$?
if [ "${rc}" -ne 0 ] && ! grep --quiet 'ready:' <<< "${out3}" \
   && [ ! -e "${sudoers_d}/persist-bild-kicksecure" ]; then
   ok 'existing account in vboxusers refused, no sudoers rule'
else
   bad "existing vboxusers account not refused (rc=${rc}): ${out3}"
fi

## 11. an EXISTING account without its private primary group is refused.
safe-rm --force -- "${sudoers_d}"/* 2>/dev/null || true
rc=0
out4="$(STUB_GETENT_RC=0 STUB_PRIMARY_GROUP='users' run_subject kicksecure 2>&1)" || rc=$?
if [ "${rc}" -ne 0 ] && ! grep --quiet 'ready:' <<< "${out4}"; then
   ok 'existing account with shared primary group refused'
else
   bad "existing shared-primary-group account not refused (rc=${rc}): ${out4}"
fi

## 12. a sudoers rule visudo rejects never becomes live: the existing rule is left
## byte-identical and no temp file is left in the include dir.
safe-rm --force -- "${sudoers_d}"/* "${sudoers_d}"/.[!.]* 2>/dev/null || true
printf '%s\n' 'previous-good-rule' > "${sudoers_d}/persist-bild-kicksecure"
rc=0
STUB_VISUDO_RC=1 run_subject kicksecure >/dev/null 2>&1 || rc=$?
leftover="$(find "${sudoers_d}" -mindepth 1 ! -name persist-bild-kicksecure)"
if [ "${rc}" -ne 0 ] \
   && [ "$(cat -- "${sudoers_d}/persist-bild-kicksecure")" = 'previous-good-rule' ] \
   && [ -z "${leftover}" ]; then
   ok 'rejected sudoers rule not installed, existing rule unchanged, no temp left'
else
   bad "rejected sudoers rule handling wrong (rc=${rc}, leftover='${leftover}'): $(cat -- "${sudoers_d}/persist-bild-kicksecure")"
fi

if [ "${failures}" -eq 0 ]; then
   printf '%s: all checks passed\n' "${0##*/}"
   exit 0
fi
printf '%s: %s check(s) FAILED\n' "${0##*/}" "${failures}" >&2
exit 1
