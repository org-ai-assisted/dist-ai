#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## swap-file-creator: every PURE, source-able function + the source-ability
## contract. (The privileged create/teardown path -- fallocate/mkswap/swapon/
## btrfs/safe-rm -- is exercised by the root+loop e2e lane, not here.)
##  (1) select_swap_backend(): given DO_PRE_CHECK, the systemd-detect-virt
##      output and whether the swapfile path is on LUKS, returns exactly one of
##      skip-xen | skip-no-luks | proceed. The whole decision table is asserted.
##  (2) swap_size_field_to_gb(): swapon SIZE field (G/M) -> rounded integer GB,
##      or reject an unrecognized unit.
##  (3) swap_fits_free_disk() / (4) swap_size_self_check_ok(): the disk-space
##      and post-swapon size-check comparisons, both boundaries.
##  (5) swapfile_path_is_absolute(): absolute-path validation.
##  (6) swap_safe_to_remove(): the P0 teardown gate -- shred/remove only when
##      swapoff succeeded (rc 0); refuse for any non-zero / empty code.
##  (7) Sourcing the REAL script does NOT auto-run main(), leaks no strict-mode
##      option and no trap, and the functions are defined. Probed by the
##      committed non-strict swap_file_creator_source_probe.sh.
##
## Drives the REAL swap-file-creator script -- no synthetic copy. A missing
## REQUIRED dependency (the subject, helper-scripts' check_runtime.bsh, the
## probe) is a HARD FAIL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${tool_dir}/swap_file_creator_source_probe.sh"

## Subject: the REAL swap-file-creator from a checkout (SWAP_FILE_CREATOR_REPO)
## else the installed one.
[ -v SWAP_FILE_CREATOR_REPO ] || SWAP_FILE_CREATOR_REPO=""
if [ -n "${SWAP_FILE_CREATOR_REPO}" ]; then
   subject="${SWAP_FILE_CREATOR_REPO}/usr/share/swap-file-creator/swap-file-creator"
else
   subject='/usr/share/swap-file-creator/swap-file-creator'
fi

## helper-scripts libs: the subject sources check_runtime.bsh at source time.
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -n "${HELPER_SCRIPTS_PATH}" ]; then
   libdir="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts"
else
   libdir='/usr/libexec/helper-scripts'
fi

## REQUIRED dependencies absent -> FATAL (R-220: never a silent skip).
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set SWAP_FILE_CREATOR_REPO to a swap-file-creator checkout, or install swap-file-creator" >&2
   exit 1
fi
if [ ! -r "${libdir}/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable under '${libdir}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -x "${probe}" ]; then
   printf '%s\n' "FATAL: source probe missing next to '${tool_dir}'" >&2
   exit 1
fi

## The subject MUST be the source-able version. A pre-refactor swap-file-creator
## runs its top-level body on source (live-mode exit, root check, even do_start/
## do_stop with real I/O), which would false-pass or delete/allocate swap. Static
## check first -- fail loud instead of sourcing the wrong script. (R-220.)
if ! grep --quiet -e 'select_swap_backend' -- "${subject}"; then
   printf '%s\n' "FATAL: subject at '${subject}' is not the source-able version (no select_swap_backend)" >&2
   printf '%s\n' "needs swap-file-creator with the source-able refactor; a pre-refactor script must not be sourced" >&2
   exit 1
fi

## The subject resolves its check_runtime.bsh via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## Run a predicate function and print its exit code (so an expected non-zero
## return does not trip the test's own errexit).
rc_of() {
   local rc=0
   "$@" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## Verify source-ability in ISOLATION before sourcing into THIS process. A subject that
## 'exit's during sourcing would otherwise exit the test here with success and ZERO
## assertions (an early 'exit 0' is indistinguishable from a clean source by rc+stdout
## alone). The probe writes a completion marker ONLY after sourcing runs to the end;
## require it (plus no-leak / no-auto-run) before the direct source below.
probe_tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
probe_tmp_cleanup() { safe-rm --recursive --force -- "${probe_tmp}"; }
trap probe_tmp_cleanup EXIT
marker="${probe_tmp}/source-complete"

src_out=""
src_rc=0
src_out="$(SUBJECT="${subject}" SOURCE_COMPLETE_MARKER="${marker}" "${probe}" source 2>/dev/null)" || src_rc=$?
check "isolated source does not enable errexit (no leak)"   "${src_rc}" "0"
check "isolated source does not auto-run main"              "${src_out}" ""
check "isolated source runs to completion (marker present)" \
   "$([ -f "${marker}" ] && printf '%s' yes || printf '%s' no)" "yes"

call_rc=0
SUBJECT="${subject}" "${probe}" call >/dev/null 2>&1 || call_rc=$?
check "calling select_swap_backend stays pure (no leak)" "${call_rc}" "0"

## FATAL if the isolation gate did not pass: refuse to source a subject that exits or
## leaks into this process (a silent false green), fail loud instead.
if [ "${src_rc}" -ne 0 ] || [ ! -f "${marker}" ]; then
   printf '%s\n' "FATAL: subject at '${subject}' did not source cleanly to completion (rc=${src_rc}); refusing to source into the test process" >&2
   exit 1
fi

## Source the REAL subject to obtain select_swap_backend (main() does not run:
## its was_executed guard is false when sourced). Clear positional args first so
## no forwarded arg can reach a dispatch in the sourced script.
set --
# shellcheck disable=SC1090,SC1091
source "${subject}"

if ! declare -F select_swap_backend >/dev/null ; then
   printf '%s\n' "FATAL: select_swap_backend not defined after sourcing subject" >&2
   exit 1
fi

## --- (1) decision table: select_swap_backend <do_pre_check> <virt> <luks_ok> ---

## DO_PRE_CHECK opt-out short-circuits before virt/luks are consulted.
check "pre-check off -> proceed (ignores xen+no-luks)" "$(select_swap_backend no xen no)" "proceed"
check "pre-check off, empty virt+luks -> proceed"      "$(select_swap_backend no '' '')"  "proceed"
check "pre-check empty string (not 'yes') -> proceed"  "$(select_swap_backend '' xen no)" "proceed"
check "pre-check arbitrary (not 'yes') -> proceed"     "$(select_swap_backend maybe xen no)" "proceed"

## xen wins over everything else under the gate (Qubes: host manages swap).
check "xen, luks yes -> skip-xen"       "$(select_swap_backend yes xen yes)"     "skip-xen"
check "xen, luks no -> skip-xen"        "$(select_swap_backend yes xen no)"      "skip-xen"
check "xen, luks unknown -> skip-xen"   "$(select_swap_backend yes xen unknown)" "skip-xen"

## Not xen: LUKS decides.
check "no virt, luks yes -> proceed"        "$(select_swap_backend yes '' yes)"      "proceed"
check "no virt, luks no -> skip-no-luks"    "$(select_swap_backend yes '' no)"       "skip-no-luks"
check "no virt, luks unknown -> skip-no-luks" "$(select_swap_backend yes '' unknown)" "skip-no-luks"

## Only 'xen' is special; other virtualizers are treated like bare metal.
check "kvm, luks yes -> proceed"        "$(select_swap_backend yes kvm yes)"     "proceed"
check "kvm, luks no -> skip-no-luks"    "$(select_swap_backend yes kvm no)"      "skip-no-luks"
check "qemu, luks yes -> proceed"       "$(select_swap_backend yes qemu yes)"    "proceed"
check "oracle (vbox), luks yes -> proceed" "$(select_swap_backend yes oracle yes)" "proceed"
check "microsoft (hyperv), luks no -> skip-no-luks" "$(select_swap_backend yes microsoft no)" "skip-no-luks"

## luks_ok is a strict 'yes' match: any other token is treated as not-on-LUKS.
check "luks token 'YES' (wrong case) -> skip-no-luks" "$(select_swap_backend yes '' YES)" "skip-no-luks"
check "luks token empty -> skip-no-luks"              "$(select_swap_backend yes '' '')"  "skip-no-luks"

## --- (2) swap_size_field_to_gb: swapon SIZE field -> rounded integer GB ---
check "4G -> 4"        "$(swap_size_field_to_gb 4G)"     "4"
check "16G -> 16"      "$(swap_size_field_to_gb 16G)"    "16"
check "1024M -> 1"     "$(swap_size_field_to_gb 1024M)"  "1"
check "2048M -> 2"     "$(swap_size_field_to_gb 2048M)"  "2"
check "6144M -> 6"     "$(swap_size_field_to_gb 6144M)"  "6"
check "1500M -> 1 (1.46 rounds down)" "$(swap_size_field_to_gb 1500M)" "1"
check "2600M -> 3 (2.53 rounds up)"   "$(swap_size_field_to_gb 2600M)" "3"
check "unknown unit K rejected"  "$(rc_of swap_size_field_to_gb 2048K)" "1"
check "no unit rejected"         "$(rc_of swap_size_field_to_gb 123)"   "1"
check "empty rejected"           "$(rc_of swap_size_field_to_gb '')"    "1"

## --- (3) swap_fits_free_disk: target GB strictly below free GB (+headroom) ---
check "4 fits in 10"             "$(rc_of swap_fits_free_disk 4 10)"  "0"
check "equal 10 does NOT fit"    "$(rc_of swap_fits_free_disk 10 10)" "1"
check "11 does NOT fit in 10"    "$(rc_of swap_fits_free_disk 11 10)" "1"

## --- (4) swap_size_self_check_ok: reported (+headroom) GB >= target GB ---
check "5 >= 4 ok"                "$(rc_of swap_size_self_check_ok 5 4)" "0"
check "4 >= 4 ok (equal)"        "$(rc_of swap_size_self_check_ok 4 4)" "0"
check "3 >= 4 fails"             "$(rc_of swap_size_self_check_ok 3 4)" "1"

## --- (5) swapfile_path_is_absolute ---
check "/var/swapfile is absolute"   "$(rc_of swapfile_path_is_absolute /var/swapfile)" "0"
check "relative path rejected"      "$(rc_of swapfile_path_is_absolute var/swapfile)"  "1"
check "empty path rejected"         "$(rc_of swapfile_path_is_absolute '')"            "1"

## --- (6) swap_safe_to_remove: shred/remove ONLY when swapoff succeeded (P0) ---
check "swapoff rc 0 -> safe to remove"        "$(rc_of swap_safe_to_remove 0)"  "0"
check "swapoff rc 1 -> NOT safe (keep file)"  "$(rc_of swap_safe_to_remove 1)"  "1"
check "swapoff rc 32 -> NOT safe"             "$(rc_of swap_safe_to_remove 32)" "1"
check "empty rc -> NOT safe (fail closed)"    "$(rc_of swap_safe_to_remove '')" "1"

## --- (7) swapon_record_for: EXACT first-field match, never a substring ---
two=$'/var/swapfile 1024M\n/var/swapfile-old 8G'
check "exact match selects the right row"   "$(swapon_record_for "${two}" /var/swapfile)"     "/var/swapfile 1024M"
check "sibling path matches itself exactly" "$(swapon_record_for "${two}" /var/swapfile-old)" "/var/swapfile-old 8G"
check "no substring false-match"            "$(swapon_record_for '/var/swapfile-old 8G' /var/swapfile)" ""
check "unrelated device -> empty"           "$(swapon_record_for '/dev/dm-0 partition 8G' /var/swapfile)" ""
tbl=$'NAME TYPE SIZE\n/dev/dm-0 partition 8G\n/var/swapfile file 1G'
check "header + partition skipped, file row matched" "$(swapon_record_for "${tbl}" /var/swapfile)" "/var/swapfile file 1G"
dup=$'/var/swapfile 1G\n/var/swapfile 2G'
check "duplicate exact row -> last wins"    "$(swapon_record_for "${dup}" /var/swapfile)"     "/var/swapfile 2G"

## --- (8) source-ability contract: functions defined in THIS process after source ---
## (no-auto-run / no-leak / completion were proven by the isolation gate above.)
check "main defined after source"                 "$(declare -F main >/dev/null && printf '%s' yes || printf '%s' no)" "yes"
check "select_swap_backend defined after source"  "$(declare -F select_swap_backend >/dev/null && printf '%s' yes || printf '%s' no)" "yes"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
