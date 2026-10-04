#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the Whonix leak lane's pair-version gate and the leak-pair
## provisioner. Canary targets:
##   - rt_lane_whonix must REFUSE (SETUP_RC, never reach dm-whonix-pair) when the imported
##     pair's version marker is absent or differs from the requested version -- else a
##     stale/wrong-version pair mislabels the leak verdict. A reverted gate reaches the
##     dm-whonix-pair recorder, so the "not invoked" assertion is a real canary.
##   - rt_provision_leak must import via dist-installer-cli with the pinned version and set
##     the marker on BOTH VMs -- the counterpart the run-time gate reads.
## Stubs isolate the unit: no VM, no account mutation, no root.

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
work="$(mktemp --directory --tmpdir dm-release-test-whonix.XXXXXX)"

whonix_lane_test_cleanup() {
   [ -n "${work}" ] || return 0
   safe-rm --recursive --force -- "${work}"
}
trap whonix_lane_test_cleanup EXIT

stubbin="${work}/bin"
mkdir --parents -- "${stubbin}"

## Files the stubs read/write at runtime (exported so the stub bodies stay expansion-free).
export MARKER_RESPONSE_FILE="${work}/marker.response"
export SETEXTRA_LOG="${work}/setextradata.log"
export PAIR_ARGV="${work}/dm-whonix-pair.argv"
export DIST_ARGV="${work}/dist-installer-cli.argv"

## sudo: `--non-interactive <cmd>` (the rt_account_can_sudo probe) exits 1 => "account is
## clean". Otherwise drop `-u <user>` and a leading `--` and run the rest as this user, so
## the lane's per-account VBoxManage / dm-whonix-pair steps work without root.
cat > "${stubbin}/sudo" <<'EOF'
#!/bin/bash
if [ "$1" = "--non-interactive" ]; then exit 1; fi
args=()
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-u" ]; then shift 2; continue; fi
  if [ "$1" = "--" ]; then shift; break; fi
  args+=("$1"); shift
done
exec "${args[@]}" "$@"
EOF

## runuser -u <acct> -- <cmd...>: drop the account + separator, run the rest (so the
## rt_account_can_sudo probe reaches the sudo stub above and reads "clean").
cat > "${stubbin}/runuser" <<'EOF'
#!/bin/bash
shift 2
[ "$1" = "--" ] && shift
exec "$@"
EOF

## VBoxManage: getextradata echoes the controlled marker response; setextradata records.
cat > "${stubbin}/VBoxManage" <<'EOF'
#!/bin/bash
case "$1" in
  getextradata) cat -- "${MARKER_RESPONSE_FILE}";;
  setextradata) printf '%s %s %s\n' "$2" "$3" "$4" >> "${SETEXTRA_LOG}";;
esac
exit 0
EOF

## dm-whonix-pair + dist-installer-cli recorders.
cat > "${stubbin}/dm-whonix-pair" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${PAIR_ARGV}"
exit 0
EOF
cat > "${stubbin}/dist-installer-cli" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${DIST_ARGV}"
exit 0
EOF

## Account-lifecycle stubs: the account "exists" (skip useradd), is unprivileged (uid!=0,
## private primary, only vboxusers), and vboxusers "exists". No real account is touched.
cat > "${stubbin}/id" <<'EOF'
#!/bin/bash
case "$1" in
  -u) printf '5001\n';;
  -gn) printf '%s\n' "$2";;
  -nG) printf '%s %s\n' "$2" "vboxusers";;
  *) exit 0;;
esac
EOF
cat > "${stubbin}/getent" <<'EOF'
#!/bin/bash
exit 0
EOF
cat > "${stubbin}/usermod" <<'EOF'
#!/bin/bash
exit 0
EOF

chmod 0770 -- "${stubbin}"/*

## Resolve the results owner with the REAL id, BEFORE the stub id shadows PATH.
export RESULTS_OWNER
RESULTS_OWNER="$(id --user --name)"

export PATH="${stubbin}:${PATH}"
export VBOXMANAGE="${stubbin}/VBoxManage"
export DM_WHONIX_PAIR="${stubbin}/dm-whonix-pair"
export DIST_INSTALLER_CLI="${stubbin}/dist-installer-cli"
## NFT fleet tool absent => rt_refresh_fleet only NOTEs (no fail).
export NFT_FLEET_TOOL="${stubbin}/nft-fleet-absent"
## Lock dir this user can write (root uses /run/lock in production).
export DM_RELEASE_TEST_LOCK_DIR="${work}"
export interface='cli'
export desktop='CLI'
export RESULTS_ROOT="${work}/results"

check() {
   local label cond
   label="$1"
   cond="$2"
   if [ "${cond}" = 'true' ]; then
      printf 'ok: %s\n' "${label}"
   else
      printf 'FAIL: %s\n' "${label}" >&2
      failures=$((failures + 1))
   fi
}

run_lane() {
   ## Run the lane in a subshell so a `die` (exit) is captured, not fatal to the test.
   local rc=0
   ( rt_lane_whonix persist-leak-whonix 18.2.3.5 ) >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## Case A: marker matches -> lane proceeds to dm-whonix-pair and publishes.
printf '%s\n' 'Value: 18.2.3.5' > "${MARKER_RESPONSE_FILE}"
printf "" > "${PAIR_ARGV}"
rc_a="$(run_lane)"
check "match: lane returns 0" "$([ "${rc_a}" = '0' ] && printf true || printf false)"
check "match: dm-whonix-pair invoked" "$([ -s "${PAIR_ARGV}" ] && printf true || printf false)"

## Case B: marker differs -> SETUP_RC, dm-whonix-pair NEVER reached (no verdict mislabel).
printf '%s\n' 'Value: 18.2.3.3' > "${MARKER_RESPONSE_FILE}"
printf "" > "${PAIR_ARGV}"
rc_b="$(run_lane)"
check "mismatch: lane fails SETUP_RC(2)" "$([ "${rc_b}" = '2' ] && printf true || printf false)"
check "mismatch: dm-whonix-pair NOT invoked" "$([ ! -s "${PAIR_ARGV}" ] && printf true || printf false)"

## Case C: marker unset -> SETUP_RC, dm-whonix-pair NEVER reached.
printf '%s\n' 'No value set!' > "${MARKER_RESPONSE_FILE}"
printf "" > "${PAIR_ARGV}"
rc_c="$(run_lane)"
check "unset: lane fails SETUP_RC(2)" "$([ "${rc_c}" = '2' ] && printf true || printf false)"
check "unset: dm-whonix-pair NOT invoked" "$([ ! -s "${PAIR_ARGV}" ] && printf true || printf false)"

## Case D: provisioner imports with the pinned version and marks BOTH VMs.
printf "" > "${DIST_ARGV}"
printf "" > "${SETEXTRA_LOG}"
rc_d=0
( rt_provision_leak persist-leak-whonix 18.2.3.5 ) >/dev/null 2>&1 || rc_d=$?
check "provision: returns 0" "$([ "${rc_d}" = '0' ] && printf true || printf false)"
check "provision: dist-installer-cli got --guest=whonix" \
   "$(grep --quiet -- '--guest=whonix' "${DIST_ARGV}" && printf true || printf false)"
check "provision: dist-installer-cli got the pinned version" \
   "$(grep --quiet -- '--guest-version=18.2.3.5' "${DIST_ARGV}" && printf true || printf false)"
check "provision: dist-installer-cli got the leak account" \
   "$(grep --quiet -- '--user=persist-leak-whonix' "${DIST_ARGV}" && printf true || printf false)"
check "provision: dist-installer-cli imports both VMs" \
   "$(grep --quiet -- '--import-only=both' "${DIST_ARGV}" && printf true || printf false)"
check "provision: GW marker set to the version" \
   "$(grep --quiet -- 'Whonix-Gateway-CLI leaktest/pair-version 18.2.3.5' "${SETEXTRA_LOG}" && printf true || printf false)"
check "provision: WS marker set to the version" \
   "$(grep --quiet -- 'Whonix-Workstation-CLI leaktest/pair-version 18.2.3.5' "${SETEXTRA_LOG}" && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s whonix-lane assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall whonix-lane assertions passed\n'
