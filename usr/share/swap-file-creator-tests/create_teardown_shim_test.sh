#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## swap-file-creator do_start / do_stop command-trace lane. Drives the REAL
## do_start / do_stop (sourced from the subject) with every side-effecting
## external command replaced by a PATH shim that records its invocation to a
## trace file. No root, no loop devices -- it verifies CONTROL FLOW and ORDER
## that a pure-function unit test cannot:
##   (A) non-btrfs create order: fallocate -> chown -> chmod -> mkswap -> swapon,
##       and chmod 0600 happens BEFORE swapon (no window of a world-readable
##       live swap file).
##   (B) btrfs branch: 'btrfs filesystem mkswapfile' is used and plain
##       fallocate / mkswap are NOT.
##   (C) teardown safety (P0): swapoff FAILS -> do_stop must NOT shred or remove
##       the still-active swap file.
##   (D) teardown success: swapoff OK + SHRED_ON_STOP=yes -> shred then safe-rm.
##
## A missing REQUIRED dependency (subject, helper-scripts) is a HARD FAIL.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"

## --- subject + helper-scripts resolution (same contract as the unit lane) ---
[ -v SWAP_FILE_CREATOR_REPO ] || SWAP_FILE_CREATOR_REPO=""
if [ -n "${SWAP_FILE_CREATOR_REPO}" ]; then
   subject="${SWAP_FILE_CREATOR_REPO}/usr/share/swap-file-creator/swap-file-creator"
else
   subject='/usr/share/swap-file-creator/swap-file-creator'
fi
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -n "${HELPER_SCRIPTS_PATH}" ]; then
   libdir="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts"
else
   libdir='/usr/libexec/helper-scripts'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   exit 1
fi
if [ ! -r "${libdir}/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable under '${libdir}'" >&2
   exit 1
fi
if ! grep --quiet -e 'do_start' -- "${subject}" || ! grep --quiet -e 'select_swap_backend' -- "${subject}"; then
   printf '%s\n' "FATAL: subject at '${subject}' is not the source-able version" >&2
   exit 1
fi
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

## True (0) if $1 appears before $2 in the trace file (both must appear).
ordered_before() {
   local first second l1 l2
   first="$1"
   second="$2"
   l1="$(grep --line-number --max-count=1 -e "${first}" -- "${trace}" 2>/dev/null | cut -d: -f1)"
   l2="$(grep --line-number --max-count=1 -e "${second}" -- "${trace}" 2>/dev/null | cut -d: -f1)"
   [ -n "${l1}" ] && [ -n "${l2}" ] && [ "${l1}" -lt "${l2}" ]
}

## True (0) if $1 appears anywhere in the trace.
traced() {
   grep --quiet -e "$1" -- "${trace}"
}

work="$(mktemp --directory)"
cleanup() { safe-rm -r -f -- "${work}"; }
trap cleanup EXIT

bindir="${work}/bin"
mkdir --parents -- "${bindir}"

## Simple recorders: append "<name> <args>" to the trace (read $TRACE at run
## time) and succeed.
for name in fallocate mkswap btrfs shred chown chmod safe-rm; do
   cat > "${bindir}/${name}" <<EOF
#!/bin/bash
printf '%s %s\n' "${name}" "\$*" >> "\${TRACE}"
exit 0
EOF
done

## swapoff: record, then exit with the caller-selected code (default 0).
cat > "${bindir}/swapoff" <<'EOF'
#!/bin/bash
printf 'swapoff %s\n' "$*" >> "${TRACE}"
exit "${SWAPOFF_RC:-0}"
EOF

## findmnt: print the caller-selected filesystem type.
cat > "${bindir}/findmnt" <<'EOF'
#!/bin/bash
printf '%s\n' "${FAKE_FSTYPE:-ext4}"
EOF

## df: a deterministic one-row table with ample space (total/avail in KB).
cat > "${bindir}/df" <<'EOF'
#!/bin/bash
printf '%s\n' 'Filesystem 1K-blocks Used Available Use% Mounted'
printf '%s\n' 'fake 104857600 1048576 103809024 1% /'
EOF

## swapon: no args -> the "active swaps" listing (do_stop); --show -> the
## size line for the self-check; otherwise the enable call (recorded).
cat > "${bindir}/swapon" <<'EOF'
#!/bin/bash
case "$*" in
   "")       printf '%s\n' "${FAKE_SWAPON_LIST:-}" ;;
   *--show*) printf '%s\n' "${FAKE_SWAPON_SHOW:-}" ;;
   *)        printf 'swapon %s\n' "$*" >> "${TRACE}" ;;
esac
exit 0
EOF

chmod +x -- "${bindir}"/*

## The drive helper sources the subject and calls do_start / do_stop with the
## DRIVE_* knobs; the subject resolves check_runtime.bsh via HELPER_SCRIPTS_PATH.
drive="${tool_dir}/swap_file_creator_drive.sh"
if [ ! -r "${drive}" ]; then
   printf '%s\n' "FATAL: drive helper missing at '${drive}'" >&2
   exit 1
fi
export SUBJECT="${subject}"
SWAPFILE="${work}/swapfile"

## --- (A) non-btrfs create order ---
trace="${work}/trace-a"
true > "${trace}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(A) do_start succeeds (non-btrfs)"         "${rc}" "0"
check "(A) fallocate called"                      "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "y"
check "(A) mkswap called"                          "$(traced '^mkswap ' && printf '%s' y || printf '%s' n)"   "y"
check "(A) swapon enable called"                   "$(traced '^swapon ' && printf '%s' y || printf '%s' n)"   "y"
check "(A) chmod before swapon (no world-readable window)" "$(ordered_before '^chmod ' '^swapon ' && printf '%s' y || printf '%s' n)" "y"
check "(A) chown before mkswap"                    "$(ordered_before '^chown ' '^mkswap ' && printf '%s' y || printf '%s' n)" "y"
check "(A) fallocate before mkswap"                "$(ordered_before '^fallocate ' '^mkswap ' && printf '%s' y || printf '%s' n)" "y"

## --- (B) btrfs allocator branch ---
trace="${work}/trace-b"
true > "${trace}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=btrfs FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(B) do_start succeeds (btrfs)"             "${rc}" "0"
check "(B) btrfs mkswapfile used"                 "$(traced '^btrfs filesystem mkswapfile' && printf '%s' y || printf '%s' n)" "y"
check "(B) plain fallocate NOT used on btrfs"     "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"
check "(B) plain mkswap NOT used on btrfs"        "$(traced '^mkswap ' && printf '%s' y || printf '%s' n)"    "n"

## --- (C) teardown safety: swapoff fails -> no shred, no remove ---
trace="${work}/trace-c"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" SWAPOFF_RC=32 FAKE_SWAPON_LIST="${SWAPFILE} file 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SHRED_ON_STOP=yes PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(C) do_stop returns 0 despite swapoff fail" "${rc}" "0"
check "(C) swapoff was attempted"                  "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"
check "(C) shred NOT called after swapoff fail"    "$(traced '^shred ' && printf '%s' y || printf '%s' n)"   "n"
check "(C) safe-rm NOT called after swapoff fail"  "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"
check "(C) swap file still present"                "$([ -e "${SWAPFILE}" ] && printf '%s' y || printf '%s' n)" "y"

## --- (D) teardown success: swapoff ok + SHRED_ON_STOP=yes -> shred then safe-rm ---
trace="${work}/trace-d"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" SWAPOFF_RC=0 FAKE_SWAPON_LIST="${SWAPFILE} file 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SHRED_ON_STOP=yes PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(D) do_stop returns 0"               "${rc}" "0"
check "(D) shred called"                    "$(traced '^shred ' && printf '%s' y || printf '%s' n)"   "y"
check "(D) safe-rm called"                  "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "y"
check "(D) shred before safe-rm"            "$(ordered_before '^shred ' '^safe-rm ' && printf '%s' y || printf '%s' n)" "y"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
