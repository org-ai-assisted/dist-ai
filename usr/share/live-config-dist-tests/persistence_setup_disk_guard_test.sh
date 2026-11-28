#!/bin/bash

## These globals cross the sourced-subject boundary (set here, read by the
## detect_existing_state / clear_overlay_area / create_partitions functions).
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests persistence-setup's disk-safety guards (sourced; main() behind a
## was_executed guard). lsblk / blkid / sgdisk / partprobe / udevadm are invoked
## by bare name, so PATH-prepended stubs feed controlled output -- no real device
## is ever touched. Regressions covered (org-ai-assisted/live-config-dist#3):
##   * h8r: clear_overlay_area must treat an lsblk failure as an error, not as an
##     empty overlay list (fail-open would skip the cleanup).
##   * h8v: create_partitions must refuse to write when the globally-located
##     overlay partitions are NOT on the target disk.
##   * h89: an explicit --device target that already holds a partition table must
##     be refused without --force.
##   * h9A: the use-freespace overlay-reuse check must read the PARTLABEL column,
##     not block on stdin (and must detect an idle persistbootx partition).
##   * h9G: use-freespace --force must NOT be refused by a whole-disk signature
##     check (the live ISO disk always has a partition table).
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
   subject="${LIVE_CONFIG_DIST_REPO}/usr/bin/persistence-setup"
   postrm="${LIVE_CONFIG_DIST_REPO}/debian/live-config-dist.postrm"
else
   subject='/usr/bin/persistence-setup'
   ## dpkg keeps maintainer scripts here, NOT under /usr/share/doc; the subject's
   ## presence above means the package is installed, so this exists.
   postrm='/var/lib/dpkg/info/live-config-dist.postrm'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not found: ${subject}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
export HELPER_SCRIPTS_PATH

# shellcheck disable=SC1090
source "${subject}"

for fn in detect_existing_state clear_overlay_area create_partitions; do
   if [ ! "$(type -t "${fn}")" = 'function' ]; then
      printf '%s\n' "FATAL: sourcing '${subject}' defined no '${fn}'" >&2
      exit 1
   fi
done

work="$(mktemp --directory --tmpdir persistence-setup-guard.XXXXXX)"
# shellcheck disable=SC2317  ## EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## One stub for lsblk (column-aware) and thin stubs for blkid/sgdisk/partprobe/
## udevadm. All driven by STUB_* env vars so each case controls the fake topology.
shimdir="${work}/bin"; mkdir --parents -- "${shimdir}"
lsblk_stub="${shimdir}/lsblk"
## placeholders are literal in the emitted shim, expanded when it runs
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'col=""; prev=""'
   printf '%s\n' 'for a in "$@"; do'
   printf '%s\n' '  case "$a" in'
   printf '%s\n' '    --output=*) col="${a#--output=}";;'
   printf '%s\n' '    --output) prev=output;;'
   printf '%s\n' '    *) [ "$prev" = output ] && { col="$a"; prev=""; };;'
   printf '%s\n' '  esac'
   printf '%s\n' 'done'
   printf '%s\n' 'case "$col" in'
   printf '%s\n' '  FSTYPE) printf "%s\n" "${STUB_FSTYPE:-}";;'
   printf '%s\n' '  PARTLABEL) printf "%s\n" "${STUB_PARTLABEL:-}";;'
   printf '%s\n' '  LABEL) printf "%s\n" "${STUB_LABEL:-}";;'
   printf '%s\n' '  PKNAME) printf "%s\n" "${STUB_PKNAME:-}";;'
   printf '%s\n' '  NAME,PARTLABEL) printf "%b" "${STUB_SCAN:-}";;'
   printf '%s\n' '  NAME,PARTN,PARTLABEL) printf "%b" "${STUB_OVERLAY_ROWS:-}";;'
   printf '%s\n' '  *) :;;'
   printf '%s\n' 'esac'
   printf '%s\n' 'exit "${STUB_LSBLK_RC:-0}"'
} > "${lsblk_stub}"
blkid_stub="${shimdir}/blkid"
## placeholders are literal in the emitted shim, expanded when it runs
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'tag=""'
   printf '%s\n' 'for a in "$@"; do case "$a" in --match-tag=*) tag="${a#--match-tag=}";; esac; done'
   printf '%s\n' 'case "$tag" in'
   printf '%s\n' '  PTTYPE) printf "%s" "${STUB_PTTYPE:-}";;'
   printf '%s\n' '  TYPE) printf "%s" "${STUB_TYPE:-}";;'
   printf '%s\n' 'esac'
   printf '%s\n' 'exit 0'
} > "${blkid_stub}"
for n in sgdisk partprobe udevadm; do
   printf '%s\n' '#!/bin/bash' > "${shimdir}/${n}"
   printf '%s\n' 'exit 0' >> "${shimdir}/${n}"
done
chmod 0770 -- "${shimdir}"/*
export PATH="${shimdir}:${PATH}"

pass_count=0; fail_count=0
check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1 ($3)"
   fi
}

## detect_existing_state writes the global existing_state; run it, capture state+rc.
run_detect() {
   existing_state='PRESET'; local rc=0
   detect_existing_state || rc=$?
   det_rc="${rc}"
}

## Export so the stub child processes inherit them; plain re-assignments below
## keep the export attribute.
export STUB_FSTYPE='' STUB_PARTLABEL='' STUB_LABEL='' STUB_PKNAME='' STUB_SCAN='' \
   STUB_OVERLAY_ROWS='' STUB_PTTYPE='' STUB_TYPE='' STUB_LSBLK_RC=''

## --- h9A: use-freespace, no force, idle persistbootx in PARTLABEL -> detected --
use_freespace='true'; do_force='false'; target_device='/dev/sdz'
STUB_FSTYPE=''; STUB_PARTLABEL='persistbootx'; STUB_LABEL=''
run_detect
check "h9A: idle persistbootx PARTLABEL is detected as an overlay partition" \
   "$( [ "${existing_state}" = 'an existing overlay partition' ] && printf '%s' true || printf '%s' false )" "state='${existing_state}'"

## a LUKS overlay is detected via FSTYPE
STUB_FSTYPE='crypto_LUKS'; STUB_PARTLABEL=''; STUB_LABEL=''
run_detect
check "use-freespace LUKS overlay is detected" \
   "$( [ "${existing_state}" = 'a LUKS volume' ] && printf '%s' true || printf '%s' false )" "state='${existing_state}'"

## a pristine free-space disk (no overlay labels) proceeds
STUB_FSTYPE='vfat'; STUB_PARTLABEL='EFI'; STUB_LABEL='BOOT'
run_detect
check "use-freespace with no overlay partitions proceeds" \
   "$( [ -z "${existing_state}" ] && [ "${det_rc}" -eq 0 ] && printf '%s' true || printf '%s' false )" "state='${existing_state}' rc=${det_rc}"

## --- h9G: use-freespace + force must NOT be refused on the live disk's GPT -----
use_freespace='true'; do_force='true'; STUB_FSTYPE='crypto_LUKS'; STUB_PARTLABEL='persistbootx'
run_detect
check "h9G: use-freespace --force proceeds despite existing content" \
   "$( [ -z "${existing_state}" ] && [ "${det_rc}" -eq 0 ] && printf '%s' true || printf '%s' false )" "state='${existing_state}' rc=${det_rc}"

## --- h89: explicit --device with a partition table is refused without --force --
use_freespace='false'; do_force='false'; STUB_PTTYPE='gpt'; STUB_TYPE=''
run_detect
check "h89: --device with an existing partition table is refused" \
   "$( [ "${existing_state}" = 'an existing partition table' ] && printf '%s' true || printf '%s' false )" "state='${existing_state}'"

## a blank --device disk proceeds
use_freespace='false'; do_force='false'; STUB_PTTYPE=''; STUB_TYPE=''
run_detect
check "h89: a blank --device disk proceeds without --force" \
   "$( [ -z "${existing_state}" ] && [ "${det_rc}" -eq 0 ] && printf '%s' true || printf '%s' false )" "state='${existing_state}' rc=${det_rc}"

## --device + force overrides
use_freespace='false'; do_force='true'; STUB_PTTYPE='gpt'
run_detect
check "--device --force overrides an existing partition table" \
   "$( [ -z "${existing_state}" ] && [ "${det_rc}" -eq 0 ] && printf '%s' true || printf '%s' false )" "state='${existing_state}' rc=${det_rc}"

## --- h8r: clear_overlay_area must FAIL (not fail-open) on an lsblk error -------
use_freespace='true'; target_device='/dev/sdz'; persistence_partition=''; boot_partition=''
STUB_LSBLK_RC='1'
coa_rc=0; ( clear_overlay_area ) >/dev/null 2>&1 || coa_rc=$?
check "h8r: clear_overlay_area returns nonzero when lsblk fails" \
   "$( [ "${coa_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${coa_rc}"
unset STUB_LSBLK_RC

## clear_overlay_area must return 0 (proceed) when lsblk SUCCEEDS but finds no
## overlay partitions -- the common fresh-disk case. A bare ${#arr} (vs ${#arr[@]})
## on the empty list aborts under set -u ('unbound variable'), which would crash
## the real run; ${#arr[@]} yields 0 cleanly.
use_freespace='true'; target_device='/dev/sdz'; persistence_partition=''; boot_partition=''
STUB_OVERLAY_ROWS=''
coae_rc=0; ( clear_overlay_area ) >/dev/null 2>&1 || coae_rc=$?
check "clear_overlay_area returns 0 when no overlay partitions exist (set -u safe)" \
   "$( [ "${coae_rc}" -eq 0 ] && printf '%s' true || printf '%s' false )" "rc=${coae_rc}"

## --- h8v: create_partitions must refuse partitions NOT on the target disk ------
target_device='/dev/target'; boot_partition=''; persistence_partition=''
STUB_SCAN='/dev/other1 persistbootx\n/dev/other2 persistence\n'
STUB_PKNAME='/dev/other'   ## parent disk of the located partitions != target_device
cp_rc=0; ( create_partitions ) >/dev/null 2>&1 || cp_rc=$?
check "h8v: create_partitions refuses partitions on a non-target disk" \
   "$( [ "${cp_rc}" -ne 0 ] && printf '%s' true || printf '%s' false )" "rc=${cp_rc}"

## positive: partitions on the target proceed
target_device='/dev/target'; boot_partition=''; persistence_partition=''
STUB_SCAN='/dev/target1 persistbootx\n/dev/target2 persistence\n'
STUB_PKNAME='/dev/target'
cp_ok_rc=0; ( create_partitions ) >/dev/null 2>&1 || cp_ok_rc=$?
check "h8v: create_partitions accepts partitions on the target disk" \
   "$( [ "${cp_ok_rc}" -eq 0 ] && printf '%s' true || printf '%s' false )" "rc=${cp_ok_rc}"

## --- h8a: the postrm removal runs unprivileged (runuser), never a root rm on home
## A maintainer script is required (never skip-to-green): repo mode points at the
## checkout's debian/live-config-dist.postrm, installed mode at the dpkg copy.
if [ ! -r "${postrm}" ]; then
   printf '%s\n' "FATAL: postrm not readable: ${postrm}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a checkout, or install live-config-dist" >&2
   exit 1
fi
## Scan CODE lines only -- a comment that merely discusses the avoided root rm
## must not satisfy (or trip) these checks.
postrm_code="$( grep --extended-regexp --invert-match '^[[:space:]]*(#|$)' "${postrm}" )"
## The launcher removal must go THROUGH 'runuser -u user -- rm' so parent-path
## symlink resolution uses the user's privileges, not root's.
check "h8a: postrm removes the launcher via 'runuser -u user -- rm'" \
   "$( grep --extended-regexp --quiet 'runuser[[:space:]]+-u[[:space:]]+user[[:space:]]+--[[:space:]]+rm[[:space:]]' <<< "${postrm_code}" && printf '%s' true || printf '%s' false )" "no 'runuser ... rm' line"
## No RECURSIVE rm anywhere (catches -rf, -fr, -Rf, -fR, -r, -R, --recursive,
## /usr/bin/rm, any line position) -- the correct postrm removes a single file.
check "h8a: postrm runs NO recursive rm" \
   "$( grep --extended-regexp --quiet 'rm[[:space:]]+(-[[:alnum:]]*[rR]|--recursive)' <<< "${postrm_code}" && printf '%s' false || printf '%s' true )" "recursive rm present"
## No ROOT (non-runuser) rm touching a home path at all: a root rm of a
## user-controlled path follows a parent symlink as root even without -r.
home_rm="$( grep --extended-regexp 'rm[[:space:]].*(/home|~)' <<< "${postrm_code}" | grep --extended-regexp --invert-match 'runuser' | head --lines 1 || true )"
check "h8a: postrm runs NO root (non-runuser) rm on a home path" \
   "$( [ -z "${home_rm}" ] && printf '%s' true || printf '%s' false )" "root rm on home: ${home_rm}"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup disk guard: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
