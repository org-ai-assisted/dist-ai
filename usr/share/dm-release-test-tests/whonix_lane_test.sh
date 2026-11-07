#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the Whonix lanes' pair-version gate, the --mode each lane passes to
## dm-whonix-pair, and the pair provisioner. Canary targets:
##   - rt_lane_whonix_leak / rt_lane_whonix_inst must REFUSE (SETUP_RC, never reach
##     dm-whonix-pair) when the imported pair's version marker is absent or differs from the
##     requested version -- else a stale/wrong-version pair mislabels the verdict. A reverted
##     gate reaches the dm-whonix-pair recorder, so the "not invoked" assertion is a real canary.
##   - the leak lane must pass --mode leak and the inst lane --mode functional (a swapped mode
##     would run the wrong battery on the wrong account).
##   - rt_provision_pair must import via dist-installer-cli (--source official) with the pinned
##     version and set the marker on BOTH VMs -- the counterpart the run-time gate reads.
##   - for a --source built pair (rt_origin=built) rt_provision_pair must import the local OVAs
##     DIRECTLY via VBoxManage and NOT call dist-installer-cli (no download, no wrong subject).
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
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }
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
export SUDO_LOG="${work}/sudo.log"
export VBOX_LOG="${work}/vboxmanage.log"

## sudo: `--non-interactive <cmd>` (the rt_account_can_sudo probe) exits 1 => "account is
## clean". Otherwise drop `-u <user>` and a leading `--` and run the rest as this user, so
## the lane's per-account VBoxManage / dm-whonix-pair steps work without root.
cat > "${stubbin}/sudo" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${SUDO_LOG}"
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

## VBoxManage: getextradata echoes the controlled marker response; setextradata records; the
## built-pair import path's controlvm/unregistervm/import calls record to VBOX_LOG.
cat > "${stubbin}/VBoxManage" <<'EOF'
#!/bin/bash
case "$1" in
  getextradata) cat -- "${MARKER_RESPONSE_FILE}";;
  setextradata) printf '%s %s %s\n' "$2" "$3" "$4" >> "${SETEXTRA_LOG}";;
  import|controlvm|unregistervm|modifyvm|modifynvram) printf '%s\n' "$*" >> "${VBOX_LOG}";;
esac
exit 0
EOF

## dm-smbios-reader-vbox: emit-argv --op import --ova <ova> --vm <vm> prints the canonical
## import argv one token per line (mirrors build_import_argv), the single source rt_import_one_ova
## reuses. imp[0] is the literal 'VBoxManage', which rt_import_one_ova replaces with VBOXMANAGE.
cat > "${stubbin}/dm-smbios-reader-vbox" <<'EOF'
#!/bin/bash
ova=""
vm=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --ova) ova="$2"; shift 2;;
    --vm) vm="$2"; shift 2;;
    *) shift;;
  esac
done
printf '%s\n' VBoxManage import "${ova}" --vsys 0 --vmname "${vm}"
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
# group lookups: succeed (vboxusers exists). passwd lookups: synthesize a home so
# rt_provision_pair can derive --directory-prefix for the target account.
case "$1" in
  passwd) printf '%s:x:5001:5001::/home/%s:/bin/bash\n' "$2" "$2";;
  *) exit 0;;
esac
EOF
cat > "${stubbin}/usermod" <<'EOF'
#!/bin/bash
exit 0
EOF

## Fleet tool stub: logs each call; --assert-fleet-member fails when the account is
## listed in NFT_UNCOVERED_FILE (an account the host leak-drop does not cover).
export NFT_FLEET_LOG="${work}/nft-fleet.log"
export NFT_UNCOVERED_FILE="${work}/nft-uncovered"
true >| "${NFT_UNCOVERED_FILE}"
cat > "${stubbin}/nft-fleet" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${NFT_FLEET_LOG}"
if [ "${1:-}" = '--assert-fleet-member' ] && grep --quiet --line-regexp --fixed-strings -- "${2:-}" "${NFT_UNCOVERED_FILE}"; then
   exit 1
fi
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
export DM_SMBIOS_READER_VBOX="${stubbin}/dm-smbios-reader-vbox"
export NFT_FLEET_TOOL="${stubbin}/nft-fleet"
## Lock dir this user can write (root uses a 0700 dir under /run in production).
## Pre-create it world-writable so the chmod-to-0700 hardening is a real canary.
export DM_RELEASE_TEST_LOCK_DIR="${work}/lock"
install -d -m 0777 -- "${DM_RELEASE_TEST_LOCK_DIR}"
export interface='cli'
export desktop='CLI'
## whonix is BIOS-only (main forces it; the test calls rt_provision_pair directly, so set it here).
# shellcheck disable=SC2034  ## read by the sourced rt_provision_pair
firmware='bios'
## rt_provision_pair shells out to dm-vbox-firmware (sudo -u account); point it at the checkout
## copy, which runs the VBoxManage stub (on PATH) and records modifyvm to VBOX_LOG.
if [ -x "${test_dir}/../../bin/dm-vbox-firmware" ]; then
   DM_VBOX_FIRMWARE="$(readlink --canonicalize -- "${test_dir}/../../bin/dm-vbox-firmware")"
else
   DM_VBOX_FIRMWARE='/usr/bin/dm-vbox-firmware'
fi
export DM_VBOX_FIRMWARE
export RESULTS_ROOT="${work}/results"

check() {
   local label cond
   label="$1"
   cond="$2"
   if [ "${cond}" = 'true' ]; then
      printf '%s\n' "ok: ${label}"
   else
      printf '%s\n' "FAIL: ${label}" >&2
      failures=$((failures + 1))
   fi
}

run_lane() {
   ## Run a lane fn in a subshell so a `die` (exit) is captured, not fatal to the test.
   ## $1=lane fn, $2=account.
   local rc=0
   ( "$1" "$2" 18.2.3.5 ) >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## Case A (leak lane): marker matches -> lane proceeds to dm-whonix-pair with --mode leak
## and publishes.
printf '%s\n' 'Value: 18.2.3.5' > "${MARKER_RESPONSE_FILE}"
printf '%s' "" > "${PAIR_ARGV}"
rc_a="$(run_lane rt_lane_whonix_leak persist-leak-whonix)"
check "leak match: lane returns 0" "$([ "${rc_a}" = '0' ] && printf '%s' "true" || printf '%s' "false")"
check "leak match: dm-whonix-pair invoked" "$([ -s "${PAIR_ARGV}" ] && printf '%s' "true" || printf '%s' "false")"
check "leak match: passed --mode leak" \
   "$(grep --quiet -- '--mode leak' "${PAIR_ARGV}" && printf '%s' "true" || printf '%s' "false")"
## leak lane must hand dm-whonix-pair a --shot-dir (the account-owned leak "story" sink), so the
## run publishes the ordered milestone sequence. A revert to the old storyless call fails this.
check "leak match: passed --shot-dir" \
   "$(grep --quiet -- '--shot-dir ' "${PAIR_ARGV}" && printf '%s' "true" || printf '%s' "false")"

## Case A-inst (inst lane): marker matches -> lane proceeds to dm-whonix-pair with --mode
## functional. A swapped mode (functional vs leak) is a real canary.
printf '%s\n' 'Value: 18.2.3.5' > "${MARKER_RESPONSE_FILE}"
printf '%s' "" > "${PAIR_ARGV}"
rc_ai="$(run_lane rt_lane_whonix_inst persist-inst-whonix)"
check "inst match: lane returns 0" "$([ "${rc_ai}" = '0' ] && printf '%s' "true" || printf '%s' "false")"
check "inst match: passed --mode functional" \
   "$(grep --quiet -- '--mode functional' "${PAIR_ARGV}" && printf '%s' "true" || printf '%s' "false")"
check "inst match: did NOT pass --mode leak" \
   "$(grep --quiet -- '--mode leak' "${PAIR_ARGV}" && printf '%s' "false" || printf '%s' "true")"

## Case B (both lanes): marker differs -> SETUP_RC, dm-whonix-pair NEVER reached (no verdict
## mislabel). Checked on BOTH lanes since they share rt_whonix_pair_require.
for pair in "rt_lane_whonix_leak persist-leak-whonix" "rt_lane_whonix_inst persist-inst-whonix"; do
   # shellcheck disable=SC2086
   set -- ${pair}
   printf '%s\n' 'Value: 18.2.3.3' > "${MARKER_RESPONSE_FILE}"
   printf '%s' "" > "${PAIR_ARGV}"
   rc_b="$(run_lane "$1" "$2")"
   check "mismatch ($1): fails SETUP_RC(2)" "$([ "${rc_b}" = '2' ] && printf '%s' "true" || printf '%s' "false")"
   check "mismatch ($1): dm-whonix-pair NOT invoked" "$([ ! -s "${PAIR_ARGV}" ] && printf '%s' "true" || printf '%s' "false")"
done

## Case C (leak lane): marker unset -> SETUP_RC, dm-whonix-pair NEVER reached.
printf '%s\n' 'No value set!' > "${MARKER_RESPONSE_FILE}"
printf '%s' "" > "${PAIR_ARGV}"
rc_c="$(run_lane rt_lane_whonix_leak persist-leak-whonix)"
check "unset: lane fails SETUP_RC(2)" "$([ "${rc_c}" = '2' ] && printf '%s' "true" || printf '%s' "false")"
check "unset: dm-whonix-pair NOT invoked" "$([ ! -s "${PAIR_ARGV}" ] && printf '%s' "true" || printf '%s' "false")"

## Case E: the leak account is NOT covered by the host leak-drop -> provisioning fails
## SETUP_RC before any import (fail-closed; a fail-open refresh would proceed).
printf '%s\n' 'persist-leak-whonix' > "${NFT_UNCOVERED_FILE}"
printf '%s' "" > "${DIST_ARGV}"
rc_e=0
( rt_provision_pair persist-leak-whonix 18.2.3.5 ) >/dev/null 2>&1 || rc_e=$?
check "uncovered: provision fails SETUP_RC(2)" "$([ "${rc_e}" = '2' ] && printf '%s' "true" || printf '%s' "false")"
check "uncovered: dist-installer-cli NOT invoked" "$([ ! -s "${DIST_ARGV}" ] && printf '%s' "true" || printf '%s' "false")"
true >| "${NFT_UNCOVERED_FILE}"

## Case D: provisioner imports with the pinned version and marks BOTH VMs.
printf '%s' "" > "${DIST_ARGV}"
printf '%s' "" > "${SETEXTRA_LOG}"
printf '%s' "" > "${SUDO_LOG}"
rc_d=0
( rt_provision_pair persist-leak-whonix 18.2.3.5 ) >/dev/null 2>&1 || rc_d=$?
check "provision: returns 0" "$([ "${rc_d}" = '0' ] && printf '%s' "true" || printf '%s' "false")"
check "provision: dist-installer-cli got --guest=whonix" \
   "$(grep --quiet -- '--guest=whonix' "${DIST_ARGV}" && printf '%s' "true" || printf '%s' "false")"
check "provision: dist-installer-cli got the pinned version" \
   "$(grep --quiet -- '--guest-version=18.2.3.5' "${DIST_ARGV}" && printf '%s' "true" || printf '%s' "false")"
check "provision: dist-installer-cli got the leak account" \
   "$(grep --quiet -- '--user=persist-leak-whonix' "${DIST_ARGV}" && printf '%s' "true" || printf '%s' "false")"
check "provision: dist-installer-cli imports both VMs" \
   "$(grep --quiet -- '--import-only=both' "${DIST_ARGV}" && printf '%s' "true" || printf '%s' "false")"
## download/import run AS the target, so the staging dir must be the target's own home,
## not the invoker's. Canary: a revert to no/invoker-home prefix fails this.
check "provision: directory-prefix is the target account home" \
   "$(grep --quiet -- '--directory-prefix=/home/persist-leak-whonix/dist-installer-cli-download' "${DIST_ARGV}" && printf '%s' "true" || printf '%s' "false")"
## skip the installer's apt-upgrade gate (irrelevant to an OVA re-import on a host with
## VirtualBox already installed).
check "provision: skips the OS-upgrade gate" \
   "$(grep --quiet -- '--noupgrade' "${DIST_ARGV}" && printf '%s' "true" || printf '%s' "false")"
check "provision: GW marker set to the version" \
   "$(grep --quiet -- 'Whonix-Gateway-CLI leaktest/pair-version 18.2.3.5' "${SETEXTRA_LOG}" && printf '%s' "true" || printf '%s' "false")"
check "provision: WS marker set to the version" \
   "$(grep --quiet -- 'Whonix-Workstation-CLI leaktest/pair-version 18.2.3.5' "${SETEXTRA_LOG}" && printf '%s' "true" || printf '%s' "false")"
## dist-installer-cli REFUSES root, so it must be invoked via sudo -u <invoker>, NOT directly
## by the root dm-release-test process. Canary: a revert to a direct call leaves no sudo-drop
## of dist-installer-cli in the sudo log.
check "provision: dist-installer-cli invoked via sudo -u (not as root)" \
   "$(grep --quiet --extended-regexp -- '-u .*dist-installer-cli' "${SUDO_LOG}" && printf '%s' "true" || printf '%s' "false")"

## Case H (built pair): rt_origin=built provisions by importing the LOCAL OVAs DIRECTLY via
## VBoxManage (reusing dm-smbios-reader-vbox's build_import_argv shape), never dist-installer-cli
## -- no download, no wrong-subject risk. Both VMs are imported + version-pinned with the build
## label. Canary: a revert to the dist-installer-cli path leaves VBOX_LOG without the imports (and
## DIST_ARGV non-empty).
## rt_origin + ova_gw/ova_ws are globals the sourced rt_provision_pair reads; export so a
## standalone shellcheck of this file sees them used (SC2034), matching interface/desktop above.
export rt_origin='built'
export ova_gw="${work}/Whonix-Gateway-CLI-build.ova"
export ova_ws="${work}/Whonix-Workstation-CLI-build.ova"
## The ovas must EXIST + be readable: rt_import_built_pair prechecks `sudo -u account test -r`
## on both before importing either (so an unreadable ova never destroys the existing pair).
touch -- "${ova_gw}" "${ova_ws}"
printf '%s' "" > "${DIST_ARGV}"
printf '%s' "" > "${SETEXTRA_LOG}"
printf '%s' "" > "${VBOX_LOG}"
rc_h=0
( rt_provision_pair persist-inst-whonix 18.2.3.0-g9999 ) >/dev/null 2>&1 || rc_h=$?
export rt_origin='downloaded'
check "built provision: returns 0" "$([ "${rc_h}" = '0' ] && printf '%s' "true" || printf '%s' "false")"
check "built provision: dist-installer-cli NOT invoked (no download)" \
   "$([ ! -s "${DIST_ARGV}" ] && printf '%s' "true" || printf '%s' "false")"
check "built provision: imported the GW ova via VBoxManage" \
   "$(grep --quiet --fixed-strings -- "import ${ova_gw} --vsys 0 --vmname Whonix-Gateway-CLI" "${VBOX_LOG}" && printf '%s' "true" || printf '%s' "false")"
check "built provision: imported the WS ova via VBoxManage" \
   "$(grep --quiet --fixed-strings -- "import ${ova_ws} --vsys 0 --vmname Whonix-Workstation-CLI" "${VBOX_LOG}" && printf '%s' "true" || printf '%s' "false")"
check "built provision: GW marker set to the build label" \
   "$(grep --quiet -- 'Whonix-Gateway-CLI leaktest/pair-version 18.2.3.0-g9999' "${SETEXTRA_LOG}" && printf '%s' "true" || printf '%s' "false")"
check "built provision: WS marker set to the build label" \
   "$(grep --quiet -- 'Whonix-Workstation-CLI leaktest/pair-version 18.2.3.0-g9999' "${SETEXTRA_LOG}" && printf '%s' "true" || printf '%s' "false")"
## #28: rt_provision_pair applies the requested firmware to BOTH imported VMs (powered off,
## before the clean-live snapshot). firmware defaults to efi-secureboot here -> modifyvm
## --firmware efi on each pair VM via the per-account runner. Canary: the pre-fix provisioner
## applied NO firmware, so VBOX_LOG carried no modifyvm --firmware line for either VM. whonix is
## BIOS-only, so the applied firmware is bios (via the extracted dm-vbox-firmware, run sudo -u).
check "built provision: BIOS firmware applied to the GW VM" \
   "$(grep --quiet -- 'modifyvm Whonix-Gateway-CLI --firmware bios' "${VBOX_LOG}" && printf '%s' "true" || printf '%s' "false")"
check "built provision: BIOS firmware applied to the WS VM" \
   "$(grep --quiet -- 'modifyvm Whonix-Workstation-CLI --firmware bios' "${VBOX_LOG}" && printf '%s' "true" || printf '%s' "false")"
## BIOS-only means no NVRAM ops for whonix -- the F1 inituefivarstore wipe can never run here.
check "built provision: no NVRAM ops on a BIOS whonix pair" \
   "$(grep --quiet -- 'modifynvram' "${VBOX_LOG}" && printf '%s' "false" || printf '%s' "true")"
## whonix is BIOS-only: an EXPLICIT non-bios --firmware is rejected (SETUP_RC=2) early in main,
## before any account/VBox work -- black-box the real binary (dies at the guard, needs no stubs).
## Canary: pre-pivot code accepted efi-secureboot for whonix and attempted the NVRAM-wiping apply.
fwrej_rc=0
"${subject}" whonix lxqt --source official --firmware efi-secureboot --version 18.2.3.5 >/dev/null 2>&1 || fwrej_rc=$?
check "whonix rejects an explicit non-bios --firmware (SETUP_RC)" \
   "$([ "${fwrej_rc}" = '2' ] && printf '%s' "true" || printf '%s' "false")"

## Case H2 (built pair, unreadable ova): the account-readability precheck must abort SETUP_RC
## BEFORE any destructive unregister/import, so an unreadable ova never destroys the existing
## pair. Point --ova-gw at a MISSING path so the stubbed `sudo -u account test -r` fails.
export rt_origin='built'
export ova_gw="${work}/missing-gw.ova"
printf '%s' "" > "${VBOX_LOG}"
rc_h2=0
( rt_provision_pair persist-inst-whonix 18.2.3.0-g9999 ) >/dev/null 2>&1 || rc_h2=$?
export rt_origin='downloaded'
check "built provision unreadable ova: aborts SETUP_RC(2)" \
   "$([ "${rc_h2}" = '2' ] && printf '%s' "true" || printf '%s' "false")"
check "built provision unreadable ova: no destructive VBoxManage op before abort" \
   "$([ ! -s "${VBOX_LOG}" ] && printf '%s' "true" || printf '%s' "false")"

## Lock dir hardened to 0700 (a world-writable lock dir lets any local user hold the
## lock and wedge every run). Canary: pre-created 0777 above; the chmod must tighten it.
check "lock dir hardened to 0700" \
   "$([ "$(stat --format='%a' -- "${DM_RELEASE_TEST_LOCK_DIR}")" = '700' ] && printf '%s' "true" || printf '%s' "false")"

## Case F (inst lane): a failed account-owned mktemp (the check-log sink) must abort the lane
## INCONCLUSIVE (SETUP_RC) BEFORE dm-whonix-pair -- errexit is off in the lane, so an unchecked
## mktemp would yield check_log="" and run the battery with `--check-log ""`. Canary: pre-fix
## code reaches dm-whonix-pair (PAIR_ARGV non-empty).
printf '%s\n' 'Value: 18.2.3.5' > "${MARKER_RESPONSE_FILE}"
printf '%s' "" > "${PAIR_ARGV}"
cat > "${stubbin}/mktemp" <<'EOF'
#!/bin/bash
exit 1
EOF
chmod 0770 -- "${stubbin}/mktemp"
rc_f="$(run_lane rt_lane_whonix_inst persist-inst-whonix)"
check "mktemp-fail (inst): lane aborts SETUP_RC(2)" "$([ "${rc_f}" = '2' ] && printf '%s' "true" || printf '%s' "false")"
check "mktemp-fail (inst): dm-whonix-pair NOT invoked" "$([ ! -s "${PAIR_ARGV}" ] && printf '%s' "true" || printf '%s' "false")"

## Case G (leak lane): a failed account-owned mktemp (the --shot-dir story sink) must abort the
## lane INCONCLUSIVE (SETUP_RC) BEFORE dm-whonix-pair -- errexit is off in the lane, so an
## unchecked mktemp would yield shot_dir="" and run with `--shot-dir ""` (a storyless pass that
## hides a provisioning gap). Canary: pre-fix code reaches dm-whonix-pair (PAIR_ARGV non-empty).
printf '%s\n' 'Value: 18.2.3.5' > "${MARKER_RESPONSE_FILE}"
printf '%s' "" > "${PAIR_ARGV}"
rc_g="$(run_lane rt_lane_whonix_leak persist-leak-whonix)"
check "mktemp-fail (leak): lane aborts SETUP_RC(2)" "$([ "${rc_g}" = '2' ] && printf '%s' "true" || printf '%s' "false")"
check "mktemp-fail (leak): dm-whonix-pair NOT invoked" "$([ ! -s "${PAIR_ARGV}" ] && printf '%s' "true" || printf '%s' "false")"
safe-rm --force -- "${stubbin}/mktemp"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "" "${failures} whonix-lane assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' "" "all whonix-lane assertions passed"
