#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## persistence-setup drives persistence-boot-sync in PROVISIONING mode right after
## formatting the boot partition, before any overlay is active, and uses its exit
## status as the ONLY check that the boot area was populated. This exercises the
## REAL persistence-boot-sync control flow (executed end-to-end) while stubbing its
## helper lib persistent-boot.sh to force the branches a headless host cannot reach
## (no persistbootx device, no kernels, no grub). The real persistent-boot.sh is
## covered by helper-scripts' persistent_boot_test.sh. Regressions covered
## (org-ai-assisted/live-config-dist#3):
##   * h8h: provisioning must bypass the active-overlay gate (there is no overlay
##     yet) -- an ordinary hook call still exits 0 early when no overlay is active.
##   * h8c: in provisioning a missing helper lib, or any sync failure, must exit
##     non-zero (a best-effort hook call stays exit 0).
##   * h8l: a failed GRUB config build or write must fail the sync (was swallowed by
##     '|| true'); a freshly-formatted boot area has no fallback config.
## No root, no device, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/bin/persistence-boot-sync"
else
   subject='/usr/bin/persistence-boot-sync'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not found: ${subject}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

work="$(mktemp --directory --tmpdir persistence-boot-sync.XXXXXX)"
# shellcheck disable=SC2317  ## EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Stub helper tree: a persistent-boot.sh defining only the functions
## persistence-boot-sync calls, each driven by a STUB_* env var so a case forces a
## branch (missing boot dev, install failure, cmdline failure, grub-write failure).
helpers="${work}/helpers/usr/libexec/helper-scripts"
mkdir --parents -- "${helpers}"
stub_lib="${helpers}/persistent-boot.sh"
## STUB_* placeholders are literal in the emitted lib, expanded when it runs
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'persistent_boot_device() { printf "%s\n" "${STUB_BOOT_DEV-/dev/fake-boot}"; }'
   printf '%s\n' 'persistent_boot_luks_uuid() { printf "%s\n" "${STUB_LUKS_UUID:-}"; return "${STUB_LUKS_RC:-0}"; }'
   printf '%s\n' 'persistent_boot_safe_boot_dir() { mkdir --parents -- "$1/boot"; printf "%s\n" "$1/boot"; }'
   printf '%s\n' 'persistent_boot_prune() { return 0; }'
   printf '%s\n' 'persistent_boot_install() { [ -n "${STUB_MARKER:-}" ] && : > "${STUB_MARKER}"; return "${STUB_INSTALL_RC:-0}"; }'
   printf '%s\n' 'persistent_boot_cmdline() { printf "%s\n" "${STUB_CMDLINE-root=live rd.live.overlay=LABEL=persistence}"; return "${STUB_CMDLINE_RC:-0}"; }'
   printf '%s\n' 'persistent_boot_write_grub_cfg() { return "${STUB_WRITE_RC:-0}"; }'
} > "${stub_lib}"

## PATH stubs for the root-only commands (the sync never touches a real device).
shimdir="${work}/bin"
mkdir --parents -- "${shimdir}"
seed="${work}/seed"
mkdir --parents -- "${seed}"
# shellcheck disable=SC2016  ## ${seed} is expanded now (the dir the stub mktemp returns)
printf '%s\n' '#!/bin/bash' "printf '%s\\n' '${seed}'" 'exit 0' > "${shimdir}/mktemp"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${shimdir}/mount"
printf '%s\n' '#!/bin/bash' 'exit 1' > "${shimdir}/mountpoint"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${shimdir}/umount"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${shimdir}/rmdir"
chmod 0770 -- "${shimdir}"/*

## An empty helper tree for the missing-lib case.
emptyhelp="${work}/empty"
mkdir --parents -- "${emptyhelp}"

## cmdline files: one WITH the active overlay token, one without.
cmdline_overlay="${work}/cmdline_overlay"
printf '%s\n' 'BOOT_IMAGE=/vmlinuz rd.live.overlay=LABEL=persistence ro' > "${cmdline_overlay}"
cmdline_plain="${work}/cmdline_plain"
printf '%s\n' 'BOOT_IMAGE=/vmlinuz ro' > "${cmdline_plain}"

pass_count=0; fail_count=0
check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1 ($3)"
   fi
}

## Run persistence-boot-sync as a subprocess with a controlled environment.
## Positional env via name=value pairs in $@ before the marker reset.
run_sync() {
   ## $1=provision(true/false) $2=helper_path $3=cmdline_file ; STUB_* come from env.
   local prov="$1" hp="$2" cf="$3" rc=0
   safe-rm --force -- "${marker}"
   env -i PATH="${shimdir}:/usr/bin:/bin" \
      HELPER_SCRIPTS_PATH="${hp}" \
      PERSISTENCE_BOOT_SYNC_PROVISION="${prov}" \
      PERSISTENCE_BOOT_SYNC_LUKS_UUID="${PROV_UUID:-}" \
      PERSISTENT_BOOT_CMDLINE_FILE="${cf}" \
      STUB_BOOT_DEV="${STUB_BOOT_DEV-/dev/fake-boot}" \
      STUB_INSTALL_RC="${STUB_INSTALL_RC:-0}" \
      STUB_CMDLINE="${STUB_CMDLINE-root=live rd.live.overlay=LABEL=persistence}" \
      STUB_CMDLINE_RC="${STUB_CMDLINE_RC:-0}" \
      STUB_WRITE_RC="${STUB_WRITE_RC:-0}" \
      STUB_MARKER="${marker}" \
      bash "${subject}" >/dev/null 2>&1 || rc=$?
   sync_rc="${rc}"
}
marker="${work}/install_ran"
helper_ok="${work}/helpers"

## reset the STUB_* knobs to the healthy defaults
reset_stubs() {
   STUB_BOOT_DEV='/dev/fake-boot'; STUB_INSTALL_RC='0'
   STUB_CMDLINE='root=live rd.live.overlay=LABEL=persistence'; STUB_CMDLINE_RC='0'; STUB_WRITE_RC='0'
}

## --- h8h: provisioning bypasses the active-overlay gate ----------------------
reset_stubs
run_sync 'true' "${helper_ok}" "${cmdline_plain}"
check "h8h: provisioning runs the sync even with no active overlay (gate bypassed)" \
   "$( [ "${sync_rc}" -eq 0 ] && [ -e "${marker}" ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc} marker=$( [ -e "${marker}" ] && printf '%s' yes || printf '%s' no )"

## an ordinary hook call with NO active overlay still exits 0 early (no sync)
reset_stubs
run_sync 'false' "${helper_ok}" "${cmdline_plain}"
check "ordinary hook with no active overlay exits 0 without syncing" \
   "$( [ "${sync_rc}" -eq 0 ] && [ ! -e "${marker}" ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc} marker=$( [ -e "${marker}" ] && printf '%s' yes || printf '%s' no )"

## an ordinary hook call WITH an active overlay does sync
reset_stubs
run_sync 'false' "${helper_ok}" "${cmdline_overlay}"
check "ordinary hook with an active overlay syncs (rc 0)" \
   "$( [ "${sync_rc}" -eq 0 ] && [ -e "${marker}" ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

## --- h8c: provisioning missing-lib + sync-failure are FATAL ------------------
reset_stubs
run_sync 'true' "${emptyhelp}" "${cmdline_plain}"
check "h8c: provisioning with a missing helper lib exits non-zero" \
   "$( [ "${sync_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

reset_stubs
run_sync 'false' "${emptyhelp}" "${cmdline_overlay}"
check "ordinary hook with a missing helper lib stays best-effort (exit 0)" \
   "$( [ "${sync_rc}" -eq 0 ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

reset_stubs; STUB_BOOT_DEV=''
run_sync 'true' "${helper_ok}" "${cmdline_plain}"
check "h8c: provisioning with no persistbootx device exits non-zero" \
   "$( [ "${sync_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

reset_stubs; STUB_INSTALL_RC='1'
run_sync 'true' "${helper_ok}" "${cmdline_plain}"
check "h8c: provisioning with a kernel-install failure exits non-zero" \
   "$( [ "${sync_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

## --- h8l: a GRUB config build/write failure fails provisioning ---------------
reset_stubs; STUB_CMDLINE_RC='1'
run_sync 'true' "${helper_ok}" "${cmdline_plain}"
check "h8l: provisioning fails when the GRUB cmdline build fails" \
   "$( [ "${sync_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

reset_stubs; STUB_CMDLINE=''
run_sync 'true' "${helper_ok}" "${cmdline_plain}"
check "h8l: provisioning fails when the GRUB cmdline is empty" \
   "$( [ "${sync_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

reset_stubs; STUB_WRITE_RC='1'
run_sync 'true' "${helper_ok}" "${cmdline_plain}"
check "h8l: provisioning fails when the GRUB config write fails" \
   "$( [ "${sync_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${sync_rc}"

printf '%s\n' ""
printf '%s\n' "===== persistence-boot-sync provision: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
