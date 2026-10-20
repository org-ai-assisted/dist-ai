#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## swap-file-creator: the pure platform/LUKS skip-decision and source-ability.
##  (1) select_swap_backend() is a PURE decision function (no I/O, no side
##      effects): given DO_PRE_CHECK, the systemd-detect-virt output and whether
##      the swapfile path is on LUKS, it returns exactly one of
##      skip-xen | skip-no-luks | proceed. The whole decision table is asserted.
##  (2) Sourcing the REAL script does NOT auto-run main() and does NOT leak
##      strict-mode, and select_swap_backend + main are defined. Probed by the
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

## --- (2) source-ability contract: no auto-run, no strict leak, defined ---
check "main defined after source"                 "$(declare -F main >/dev/null && printf '%s' yes || printf '%s' no)" "yes"
check "select_swap_backend defined after source"  "$(declare -F select_swap_backend >/dev/null && printf '%s' yes || printf '%s' no)" "yes"

src_out=""
src_rc=0
src_out="$(SUBJECT="${subject}" "${probe}" source 2>/dev/null)" || src_rc=$?
check "sourcing does not enable errexit (no leak)" "${src_rc}" "0"
check "sourcing does not auto-run main"            "${src_out}" ""

call_rc=0
SUBJECT="${subject}" "${probe}" call >/dev/null 2>&1 || call_rc=$?
check "calling select_swap_backend stays pure (no leak)" "${call_rc}" "0"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
