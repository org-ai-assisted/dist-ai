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
##   (B) btrfs branch: 'btrfs filesystem mkswapfile' is used with a BYTE size
##       (never rounded to 0G for a sub-GiB target), and plain fallocate / mkswap
##       are NOT.
##   (C) teardown safety (P0): swapoff FAILS -> do_stop must NOT remove the
##       still-active swap file, AND must return nonzero (fail loud, #7).
##   (D) teardown success: swapoff OK -> do_stop removes the file (safe-rm),
##       after swapoff.
##   (E) df -P: free space is read from the right column even when a long mapper
##       device name would wrap non-POSIX df output.
##   (F) exact swap-record match: a sibling "<file>-old" active swap does not
##       make do_stop swapoff our (inactive) file.
##   (G) teardown fail-closed: a FAILED swap enumeration cannot prove the file
##       inactive, so do_stop must swapoff and remove ONLY on success -- never
##       remove an unproven, possibly-active file on an empty/failed listing.
##   (H) byte-based free-space check REJECTS an over-large swap (no +2 GiB
##       headroom added to available; no GiB truncation).
##   (I) restart idempotency: the existing managed swap file's bytes are
##       credited (do_stop reclaims them), so a restart on a full-ish disk is
##       not falsely blocked.
##   (J) #8 rollback: a post-enable failure (size self-check mismatch) must
##       swapoff the swap do_start just enabled, not leave a mis-sized active
##       swap behind the failure.
##   (K) #7 abort-before-overwrite: do_stop could not deactivate an existing
##       active swap (swapoff fails) -> do_start must bail BEFORE fallocate,
##       never format a possibly-live swap file.
##   (L) edge-2 best-effort size check: a FAILED informational size probe
##       (swapon --show exits nonzero) keeps the enabled swap and skips the
##       check -- it must NOT tear down healthy swap; only a verified wrong
##       size rolls back, which is (J).
##   (M) do_stop fail-closed on a non-absolute SWAPFILE: a relative path is
##       refused before any file op (never safe-rm's a CWD file).
##   (N) safe-rm failure surfaces LOUD: do_start calls do_stop as 'if ! do_stop'
##       (errexit suppressed), so an unchecked safe-rm failure would be swallowed
##       and do_start would recreate swap over the undeleted file -- do_stop must
##       return nonzero and do_start must abort before fallocate.
##   (O) a failing logger must not abort a critical path: log()'s
##       'printf | systemd-cat' pipeline (systemd-cat failing under pipefail)
##       must not fire the ERR trap before the rollback swapoff runs.
##   (P) #8 logger fail-safe on the VERBOSE=yes branch: log()'s plain 'printf'
##       (not the systemd-cat pipeline) must not abort a caller when its write
##       fails (stderr to a full disk) -- low RAM forces VERBOSE=yes, so this is a
##       normal runtime path; the rollback swapoff must STILL run.
##   (Q) size validation before do_stop: a zero/non-integer SWAP_FILE_SIZE must be
##       rejected up front, never after do_stop has destroyed the existing swap.
##   (R) #11 octal: a leading-zero SWAP_FILE_SIZE is DECIMAL (base-10 normalized),
##       not octal -- '001024' allocates 1 GiB, not ~557 MB.
##   (S) #4 UUID validation before do_stop: an invalid UUID is rejected up front,
##       not after do_stop removed the old swap (it only fails at 'mkswap --uuid').
##   (T) #10 verbatim swap-record match: a sibling listing line with a '\c' escape
##       must not (via a 'printf %b' decode) hide an ACTIVE configured swap and let
##       do_stop delete a live swap without a swapoff.
##   (V) size overflow: a digit string above signed 64-bit must be rejected, not
##       wrapped by $((...)) back into the valid range (arbitrary-precision bc check).
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
for name in fallocate mkswap btrfs chown chmod; do
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

## df: ONE filesystem state in two unit formats, driven by byte knobs so the 1K
## (sizing) read 'df -P' and the byte (free-check) read 'df -P --block-size=1'
## AGREE. With -P (POSIX) emit one row per fs; WITHOUT -P simulate a long mapper
## device name wrapping onto its own line -- the breakage 'df -P' prevents, so a
## regression dropping -P from EITHER call misreads the column and the
## sufficiency check wrongly rejects. FAKE_FREE_BYTES / FAKE_TOTAL_BYTES override
## the (ample) defaults so a case can simulate a nearly-full disk.
cat > "${bindir}/df" <<'EOF'
#!/bin/bash
total_bytes="${FAKE_TOTAL_BYTES:-107374182400}"
free_bytes="${FAKE_FREE_BYTES:-106300440576}"
used_bytes=$(( total_bytes - free_bytes ))
if [[ "$*" == *--block-size=1* ]]; then
   hdr='1B-blocks'; t="${total_bytes}"; u="${used_bytes}"; a="${free_bytes}"
else
   hdr='1K-blocks'; t=$(( total_bytes / 1024 )); u=$(( used_bytes / 1024 )); a=$(( free_bytes / 1024 ))
fi
if [[ "$*" == *-P* ]]; then
   printf '%s\n' "Filesystem ${hdr} Used Available Use% Mounted"
   printf '%s\n' "/dev/mapper/luks-root ${t} ${u} ${a} 1% /"
else
   printf '%s\n' "Filesystem ${hdr} Used Available Use% Mounted"
   printf '%s\n' '/dev/mapper/luks-very-long-logical-volume-name'
   printf '%s\n' "          ${t} ${u} ${a} 1% /"
fi
EOF

## swapon: no args -> the "active swaps" listing (do_stop); --show -> the
## size line for the self-check; otherwise the enable call (recorded).
cat > "${bindir}/swapon" <<'EOF'
#!/bin/bash
case "$*" in
   "")       printf '%s\n' "${FAKE_SWAPON_LIST:-}"; exit "${SWAPON_LIST_RC:-0}" ;;
   *--show*) printf '%s\n' "${FAKE_SWAPON_SHOW:-}"; exit "${SWAPON_SHOW_RC:-0}" ;;
   *)        printf 'swapon %s\n' "$*" >> "${TRACE}" ;;
esac
exit 0
EOF

## safe-rm: record, then exit with the caller-selected code (default 0). A
## nonzero SAFE_RM_RC simulates a removal that FAILED (e.g. immutable attr,
## EROFS) so a case can prove do_stop surfaces that failure instead of
## swallowing it under the errexit-suppressed 'if ! do_stop' call.
cat > "${bindir}/safe-rm" <<'EOF'
#!/bin/bash
printf 'safe-rm %s\n' "$*" >> "${TRACE}"
exit "${SAFE_RM_RC:-0}"
EOF

## systemd-cat: consume stdin, then exit with the caller-selected code. A
## nonzero SYSTEMD_CAT_RC simulates journald unavailable, so a case can prove
## log()'s 'printf | systemd-cat' pipeline cannot abort the program (ERR trap)
## before a critical action such as the rollback swapoff.
cat > "${bindir}/systemd-cat" <<'EOF'
#!/bin/bash
cat >/dev/null 2>&1 || true
exit "${SYSTEMD_CAT_RC:-0}"
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

## --- (B) btrfs allocator branch; size passed in BYTES, never rounded to 0G ---
trace="${work}/trace-b"
true > "${trace}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=btrfs FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 512M" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=512 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(B) do_start succeeds (btrfs, 512 MiB)"    "${rc}" "0"
check "(B) btrfs mkswapfile used"                 "$(traced '^btrfs filesystem mkswapfile' && printf '%s' y || printf '%s' n)" "y"
check "(B) btrfs size in bytes (536870912), not rounded G" "$(traced 'mkswapfile --size 536870912' && printf '%s' y || printf '%s' n)" "y"
## Anchor to the mkswapfile size TOKEN, not a bare '0G': 'traced' greps the
## whole trace and every line embeds the mktemp path ${work}, whose random
## suffix can itself contain "0G" (false-FAIL ~1/430 runs). A G-suffixed size
## after 'mkswapfile --size' is the sub-GiB rounding regression; a byte size is not.
check "(B) btrfs size never G-suffixed (sub-GiB rounds to 0G)" "$(traced 'mkswapfile --size [0-9]*G' && printf '%s' y || printf '%s' n)" "n"
check "(B) plain fallocate NOT used on btrfs"     "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"
check "(B) plain mkswap NOT used on btrfs"        "$(traced '^mkswap ' && printf '%s' y || printf '%s' n)"    "n"

## --- (C) teardown safety: swapoff fails -> no remove, and FAIL LOUD (#7). The
## old code kept the file but returned 0, so a service stop falsely succeeded
## and do_start proceeded unsafely. do_stop must now return nonzero. ---
trace="${work}/trace-c"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" SWAPOFF_RC=32 FAKE_SWAPON_LIST="${SWAPFILE} file 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(C) do_stop fails (nonzero) on unconfirmed swapoff" "${rc}" "1"
check "(C) swapoff was attempted"                  "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"
check "(C) safe-rm NOT called after swapoff fail"  "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"
check "(C) swap file still present"                "$([ -e "${SWAPFILE}" ] && printf '%s' y || printf '%s' n)" "y"

## --- (D) teardown success: swapoff ok -> do_stop removes the file via safe-rm ---
trace="${work}/trace-d"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" SWAPOFF_RC=0 FAKE_SWAPON_LIST="${SWAPFILE} file 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(D) do_stop returns 0"               "${rc}" "0"
check "(D) safe-rm called (file removed)"   "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "y"
check "(D) swapoff before safe-rm"          "$(ordered_before '^swapoff ' '^safe-rm ' && printf '%s' y || printf '%s' n)" "y"

## --- (E) df -P: free space read correctly despite a wrapping long device name.
## The df shim wraps WITHOUT -P (free then reads 0), so a 5 GiB swap would fail
## the sufficiency check; succeeding here proves do_start uses 'df -P'. ---
trace="${work}/trace-e"
true > "${trace}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 5G" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=5120 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(E) 5 GiB swap allowed (df -P read free space)" "${rc}" "0"
check "(E) fallocate reached (sufficiency check passed)" "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "y"

## --- (F) exact swap-record match: a SIBLING active swap ("<file>-old") must NOT
## make do_stop swapoff OUR (inactive) file -- the substring-match bug. ---
trace="${work}/trace-f"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" SWAPOFF_RC=0 FAKE_SWAPON_LIST="${SWAPFILE}-old file 8G" \
   DRIVE_SWAPFILE="${SWAPFILE}" PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(F) do_stop returns 0"                        "${rc}" "0"
check "(F) sibling active -> our swapoff NOT called" "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "n"
check "(F) our inactive file removed"                "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "y"

## --- (G) teardown fail-closed on a FAILED swap enumeration. 'swapon' (listing)
## exits non-zero, so do_stop cannot prove the file inactive: it must attempt
## swapoff and remove ONLY on success. Here swapoff also fails, so the
## (possibly active) file must be KEPT. Old code read the empty listing as
## "not active", skipped swapoff, and safe-rm'd it -> fail open. ---
trace="${work}/trace-g"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" SWAPON_LIST_RC=1 SWAPOFF_RC=32 FAKE_SWAPON_LIST="" \
   DRIVE_SWAPFILE="${SWAPFILE}" PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(G) do_stop fails (nonzero) on enumeration+swapoff failure" "${rc}" "1"
check "(G) swapoff attempted (empty list not trusted)" "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"
check "(G) safe-rm NOT called (fail closed)"           "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"
check "(G) swap file still present"                    "$([ -e "${SWAPFILE}" ] && printf '%s' y || printf '%s' n)" "y"

## --- (H) #9/#10: byte-based sufficiency REJECTS an over-large swap. Only 3 GiB
## free, no existing file to credit; a 4 GiB target (+2 GiB headroom = 6 GiB
## required) does not fit, so do_start must bail BEFORE fallocate. The old
## GiB-truncated check added the +2 headroom to AVAILABLE, so it approved a 4
## GiB swap into 3 GiB free. ---
trace="${work}/trace-h"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
free3g=$(( 3 * 1024 * 1024 * 1024 ))
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 4G" \
   FAKE_FREE_BYTES="${free3g}" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=4096 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(H) do_start FAILS (4 GiB swap, only 3 GiB free)" "${rc}" "1"
check "(H) fallocate NOT reached (rejected pre-alloc)"   "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"

## --- (I) #11: restart idempotency. Only 1 GiB raw free, but the existing
## managed swap file is 7 GiB (sparse) and do_stop reclaims it before
## allocation, so a 5 GiB target (+2 GiB headroom = 7 GiB) fits the 8 GiB
## effective free -> do_start must REACH fallocate. Old code ignored the
## existing file and falsely failed on the 1 GiB raw free. ---
trace="${work}/trace-i"
true > "${trace}"
truncate --size 7G "${SWAPFILE}"
rc=0
free1g=$(( 1 * 1024 * 1024 * 1024 ))
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 5G" \
   FAKE_FREE_BYTES="${free1g}" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=5120 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(I) do_start succeeds (existing 7 GiB credited)"  "${rc}" "0"
check "(I) fallocate reached (restart not falsely blocked)" "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "y"

## --- (J) #8: a post-enable failure rolls the swap back. swapon enables
## successfully, but the size self-check sees the kernel-reported size (1 GiB)
## far below the 5 GiB target, so do_start must swapoff (roll back) the swap it
## just enabled before failing -- not leave a mis-sized active swap behind. No
## existing file (no do_stop swapoff), so the ONLY swapoff is the rollback. Old
## code logged the mismatch and exited WITHOUT any swapoff. ---
trace="${work}/trace-j"
true > "${trace}"
safe-rm --force -- "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 1G" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=5120 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(J) do_start FAILS (size self-check mismatch)"   "${rc}" "1"
check "(J) rollback swapoff called after failed check"  "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"

## --- (K) #7: do_start must ABORT before overwriting a swap it could not
## deactivate. The existing managed file is an ACTIVE swap and swapoff fails, so
## do_stop returns nonzero; do_start must bail BEFORE fallocate rather than
## format a possibly-live swap file. Old code ignored do_stop's result and
## proceeded to fallocate (overwriting a still-active swap). ---
trace="${work}/trace-k"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 SWAPOFF_RC=32 FAKE_SWAPON_LIST="${SWAPFILE} file 1024M" \
   FAKE_SWAPON_SHOW="${SWAPFILE} 5G" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=5120 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(K) do_start FAILS (could not deactivate active swap)" "${rc}" "1"
check "(K) fallocate NOT reached (no overwrite of live swap)" "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"
check "(K) swapoff was attempted"                             "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"

## --- (L) edge-2 best-effort size check: a FAILED informational size probe
## must NOT tear down healthy swap. swapon enables OK but 'swapon --show' exits
## nonzero, so the size self-check cannot run. do_start keeps the enabled swap
## and SUCCEEDS (same policy as an unparseable unit), never rolling back -- even
## with the production ERR trap installed, the '|| true' guard keeps it from
## firing. No existing file (no do_stop swapoff), so ANY swapoff would be a
## rollback. The pre-edge-2 code rolled the swap back here (swapoff + exit 1). ---
trace="${work}/trace-l"
true > "${trace}"
safe-rm --force -- "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="" SWAPON_SHOW_RC=1 \
   DRIVE_INSTALL_ERR_TRAP=yes \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=5120 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(L) do_start SUCCEEDS (size-probe failure tolerated)" "${rc}" "0"
check "(L) swap KEPT: enabling swapon reached"               "$(traced '^swapon ' && printf '%s' y || printf '%s' n)" "y"
check "(L) NO rollback swapoff (healthy swap not torn down)" "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "n"

## --- (M) do_stop must REJECT a non-absolute SWAPFILE (fail closed). do_stop
## safe-rm's the configured path and runs independently as the unit's ExecStop,
## so a relative value (misconfig) must be refused before any file op -- never
## safe-rm a path in the service's CWD. do_start already validated absoluteness;
## the old do_stop had no guard and returned 0 on a relative path. ---
trace="${work}/trace-m"
true > "${trace}"
rc=0
TRACE="${trace}" FAKE_SWAPON_LIST="" \
   DRIVE_SWAPFILE="relative-swapfile" PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(M) do_stop FAILS (nonzero) on a non-absolute SWAPFILE" "${rc}" "1"
check "(M) safe-rm NOT reached (guard precedes file ops)"      "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"

## --- (N) safe-rm failure must be LOUD even inside 'if ! do_stop'. do_start
## calls do_stop as 'if ! do_stop', which DISABLES errexit for the whole
## function, so an unchecked 'safe-rm' failure (line 295) would fall through to
## 'return 0': do_stop would falsely report success and do_start would recreate
## swap over the undeleted (wrong-size) file. The existing file is proven
## INACTIVE (empty listing lists it absent), so do_stop reaches safe-rm; safe-rm
## fails. do_start must ABORT before fallocate. Old code proceeded to fallocate
## (do_stop returned 0 despite the failed remove). ---
trace="${work}/trace-n"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" SAFE_RM_RC=1 \
   FAKE_SWAPON_SHOW="${SWAPFILE} 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=1024 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(N) do_start FAILS when safe-rm of the old file fails" "${rc}" "1"
check "(N) safe-rm was attempted (reached removal)"           "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "y"
check "(N) fallocate NOT reached (do_stop failure not swallowed)" "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"

## --- (O) a failing logger must NOT abort a critical path. log() ends with
## 'return 0' but pipes through systemd-cat; under pipefail+errexit+errtrace a
## systemd-cat failure would fire the ERR trap on that pipeline BEFORE the
## return, killing do_start mid-rollback (swap_rollback logs before it swapoffs).
## This drives the (J) size-mismatch rollback with VERBOSE=no (log hits the
## systemd-cat branch), systemd-cat failing, and the production ERR trap
## installed: the rollback swapoff must STILL run. Old code (unguarded pipeline)
## aborted via error_handler before any rollback swapoff. ---
trace="${work}/trace-o"
true > "${trace}"
safe-rm --force -- "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 1G" \
   DRIVE_VERBOSE=no SYSTEMD_CAT_RC=1 DRIVE_INSTALL_ERR_TRAP=yes \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=5120 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(O) do_start FAILS (size mismatch)"                     "${rc}" "1"
check "(O) enabling swapon reached despite failing logger"     "$(traced '^swapon ' && printf '%s' y || printf '%s' n)" "y"
check "(O) rollback swapoff STILL called though systemd-cat fails" "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"

## --- (P) #8 logger fail-safe on the VERBOSE=yes branch. Drive the (J)
## size-mismatch rollback with VERBOSE=yes, the production ERR trap, and the
## drive's stderr pointed at /dev/full: the error logs at 561-563 and the
## rollback's own log at 71 all write to the full device, but the rollback
## swapoff at 72 must STILL run. Old code (unguarded 'printf' on line 19) fired
## the ERR trap on the first failed write and aborted before any rollback. ---
if [ ! -c /dev/full ]; then
   printf '%s\n' "FATAL: /dev/full missing (required for (P))" >&2
   exit 1
fi
trace="${work}/trace-p"
true > "${trace}"
safe-rm --force -- "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 1G" \
   DRIVE_VERBOSE=yes DRIVE_INSTALL_ERR_TRAP=yes \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=5120 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start 1>/dev/null 2>/dev/full || rc=$?
check "(P) do_start FAILS (size mismatch)"                     "${rc}" "1"
check "(P) enabling swapon reached despite failing logger"     "$(traced '^swapon ' && printf '%s' y || printf '%s' n)" "y"
check "(P) rollback swapoff STILL called though stderr is full" "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"

## --- (Q) size validation before do_stop. A zero SWAP_FILE_SIZE would pass the
## free gate (required = 2 GiB headroom only) and the old swap would be deleted
## before 'fallocate --length 0' fails. Validation now fails up front: do_stop
## (safe-rm) and fallocate are never reached. Old code reached both. ---
trace="${work}/trace-q"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=0 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(Q) do_start FAILS (zero size rejected)"          "${rc}" "1"
check "(Q) safe-rm NOT reached (old swap not destroyed)" "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"
check "(Q) fallocate NOT reached"                        "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"

## --- (R) #11 octal: a leading-zero size is DECIMAL. '001024' MiB must allocate
## 1073741824 bytes (1 GiB); old code read it as octal 532 -> 557842432 bytes. ---
trace="${work}/trace-r"
true > "${trace}"
safe-rm --force -- "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" FAKE_SWAPON_SHOW="${SWAPFILE} 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=001024 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(R) do_start succeeds (001024 normalized to decimal)"    "${rc}" "0"
check "(R) fallocate uses decimal 1 GiB (1073741824 bytes)"     "$(traced 'fallocate --length 1073741824' && printf '%s' y || printf '%s' n)" "y"
check "(R) fallocate NOT the octal-532 byte count (557842432)"  "$(traced 'fallocate --length 557842432' && printf '%s' y || printf '%s' n)" "n"

## --- (S) #4 UUID validation before do_stop. An invalid UUID only fails at
## 'mkswap --uuid' AFTER do_stop removed the old swap. Reject it up front:
## do_stop (safe-rm) and fallocate are never reached. Old code reached both. ---
trace="${work}/trace-s"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" \
   DRIVE_UUID="not-a-valid-uuid" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=1024 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(S) do_start FAILS (invalid UUID rejected)"       "${rc}" "1"
check "(S) safe-rm NOT reached (old swap not destroyed)" "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"
check "(S) fallocate NOT reached"                        "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"

## --- (T) #10 verbatim swap-record match. The configured file is ACTIVE, but an
## earlier listing line carries a '\c' escape. Under the old 'printf %b' decode
## the listing truncated at '\c' before our record, our file looked inactive,
## swapoff was skipped, and safe-rm deleted a LIVE swap (returning 0). With
## verbatim matching our record is found, swapoff is required; swapoff fails here,
## so do_stop fails LOUD and the live file is KEPT. ---
trace="${work}/trace-t"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" SWAPOFF_RC=32 \
   FAKE_SWAPON_LIST=$'/other/swap\\cfile file 8G\n'"${SWAPFILE} file 1024M" \
   DRIVE_SWAPFILE="${SWAPFILE}" PATH="${bindir}:${PATH}" \
   bash "${drive}" stop >/dev/null 2>&1 || rc=$?
check "(T) do_stop FAILS (active swap, swapoff unconfirmed)" "${rc}" "1"
check "(T) swapoff attempted (record matched verbatim)"      "$(traced '^swapoff ' && printf '%s' y || printf '%s' n)" "y"
check "(T) safe-rm NOT called (live swap not deleted)"       "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"
check "(T) swap file still present"                          "$([ -e "${SWAPFILE}" ] && printf '%s' y || printf '%s' n)" "y"

## --- (V) size overflow must be rejected, not wrapped. A value above signed
## 64-bit (2^64 + 2048) would wrap in $((10#...)) back to 2048 (a valid-looking
## size) and proceed to destroy the old swap. The arbitrary-precision bc range
## check rejects it before do_stop. Old code (shell-arithmetic range check only)
## wrapped it into range and reached do_stop + fallocate. ---
trace="${work}/trace-v"
true > "${trace}"
true > "${SWAPFILE}"
rc=0
TRACE="${trace}" FAKE_FSTYPE=ext4 FAKE_SWAPON_LIST="" \
   DRIVE_SWAPFILE="${SWAPFILE}" DRIVE_SIZE_MB=18446744073709553664 DRIVE_DO_PRE_CHECK=no PATH="${bindir}:${PATH}" \
   bash "${drive}" start >/dev/null 2>&1 || rc=$?
check "(V) do_start FAILS (overflow size rejected, not wrapped)" "${rc}" "1"
check "(V) safe-rm NOT reached (old swap not destroyed)"         "$(traced '^safe-rm ' && printf '%s' y || printf '%s' n)" "n"
check "(V) fallocate NOT reached"                                "$(traced '^fallocate ' && printf '%s' y || printf '%s' n)" "n"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
