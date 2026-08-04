#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- SKIP-guards on external tools (dosfstools/mtools); this
## test may run before helper-scripts has.sh is available.

## dm-normalize-fat-partition must make a FAT filesystem byte-reproducible
## regardless of the order its files were written.
##
## THE PROPERTY THAT MATTERS: two FAT images holding the SAME files but written in
## a DIFFERENT order (so their cluster allocation, free space and directory-entry
## order differ) must normalize to the SAME bytes -- that convergence is what
## makes a local image's EFI System Partition identical to CI's. Also asserts the
## geometry, volume serial and label are preserved (a changed serial breaks an
## fstab 'UUID=' mount of the ESP) and the files survive intact.
##
## Needs mkfs.fat (dosfstools) + mcopy (mtools). No root, no network, no build:
## it builds plain FAT IMAGE FILES and drives them with mtools, never a mount.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
tool="${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-normalize-fat-partition"
if [ ! -x "${tool}" ]; then
   tool="$( type -P dm-normalize-fat-partition || true )"
fi
if [ -z "${tool}" ] || [ ! -x "${tool}" ]; then
   printf '%s\n' "SKIP: dm-normalize-fat-partition not found (set DERIVATIVE_MAKER_DIR)." >&2
   exit 77
fi
for dep in mkfs.fat mcopy mmd; do
   if ! command -v "${dep}" >/dev/null 2>&1; then
      printf '%s\n' "SKIP: ${dep} not installed (need dosfstools + mtools)." >&2
      exit 77
   fi
done

export SOURCE_DATE_EPOCH=1785245370
export MTOOLS_SKIP_CHECK=1
export MTOOLSRC=/dev/null
export TZ=UTC

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## Build a 16 MiB FAT32 image with a fixed serial/label, then add the given files
## in the given order (order drives cluster allocation, the source of the bug).
## $1 = output image, remaining args = relative paths under a content pool.
make_fat() {
   local image="$1"; shift
   truncate --size=16777216 "${image}"
   mkfs.fat -F 32 -S 512 -s 1 -R 32 -i cafebabe -n "ESP" "${image}" >/dev/null
   mmd -i "${image}" "::EFI"
   mmd -i "${image}" "::EFI/BOOT"
   local rel
   for rel in "$@"; do
      touch --date="@${SOURCE_DATE_EPOCH}" -- "${work_dir}/pool/${rel##*/}"
      mcopy -m -i "${image}" "${work_dir}/pool/${rel##*/}" "::${rel}"
   done
}

## A content pool: distinct sizes so misplacement is detectable.
mkdir -p "${work_dir}/pool"
head -c 40000 /dev/urandom > "${work_dir}/pool/BOOTX64.EFI"
head -c 90000 /dev/urandom > "${work_dir}/pool/grubx64.efi"
head -c 15000 /dev/urandom > "${work_dir}/pool/mmx64.efi"

## Image A: files added in one order. Image B: SAME files, reverse order.
make_fat "${work_dir}/a.img" EFI/BOOT/BOOTX64.EFI EFI/BOOT/grubx64.efi EFI/BOOT/mmx64.efi
make_fat "${work_dir}/b.img" EFI/BOOT/mmx64.efi EFI/BOOT/grubx64.efi EFI/BOOT/BOOTX64.EFI

## The on-disk volume serial (raw little-endian at offset 0x43), captured before
## normalize so preservation is checked against the actual original, not against
## the mkfs.fat '-i' argument (which is byte-swapped relative to on-disk order).
serial_before="$( dd if="${work_dir}/a.img" bs=1 skip=67 count=4 2>/dev/null | xxd -p )"

## --- 1. the two diverge before normalization (the bug is real) --------------
if ! cmp --quiet "${work_dir}/a.img" "${work_dir}/b.img"; then
   pass 'two FATs with the same files in different write order DIFFER pre-normalize'
else
   fail 'the two fixtures are already identical; the test proves nothing'
fi

## --- 2. normalization converges them to byte-identical ----------------------
"${tool}" "${work_dir}/a.img" >/dev/null
"${tool}" "${work_dir}/b.img" >/dev/null
if cmp --quiet "${work_dir}/a.img" "${work_dir}/b.img"; then
   pass 'after normalize the two FATs are BYTE-IDENTICAL (reproducible)'
else
   fail "still differ after normalize: $( cmp -l "${work_dir}/a.img" "${work_dir}/b.img" 2>/dev/null | wc -l ) bytes"
fi

## --- 3. idempotent -----------------------------------------------------------
cp "${work_dir}/a.img" "${work_dir}/a.before"
"${tool}" "${work_dir}/a.img" >/dev/null
if cmp --quiet "${work_dir}/a.before" "${work_dir}/a.img"; then
   pass 'idempotent: a second normalize is a no-op'
else
   fail 'second normalize changed the image'
fi

## --- 4. volume serial + label preserved (else fstab UUID= mount breaks) ------
serial_after="$( dd if="${work_dir}/a.img" bs=1 skip=67 count=4 2>/dev/null | xxd -p )"
label="$( mlabel -i "${work_dir}/a.img" -s :: 2>/dev/null | sed 's/^Volume label is //; s/ *$//' )"
if [ "${serial_after}" = "${serial_before}" ]; then
   pass "volume serial preserved (${serial_before})"
else
   fail "volume serial changed: ${serial_before} -> ${serial_after}"
fi
if printf '%s' "${label}" | grep -q 'ESP'; then
   pass 'volume label preserved (ESP)'
else
   fail "volume label not preserved: [${label}]"
fi

## --- 5. files survive intact (names + content) ------------------------------
files_now="$( mdir -i "${work_dir}/a.img" -b ::/EFI/BOOT 2>/dev/null | LC_ALL=C sort | tr '\n' ' ' )"
if [[ "${files_now}" == *BOOTX64.EFI* ]] && [[ "${files_now}" == *grubx64.efi* ]] \
   && [[ "${files_now}" == *mmx64.efi* ]]; then
   mcopy -i "${work_dir}/a.img" "::EFI/BOOT/grubx64.efi" "${work_dir}/extracted" 2>/dev/null
   if cmp --quiet "${work_dir}/pool/grubx64.efi" "${work_dir}/extracted"; then
      pass 'all files present and content intact after normalize'
   else
      fail 'a file content changed after normalize'
   fi
else
   fail "files missing after normalize: [${files_now}]"
fi

## --- 6. fsck clean -----------------------------------------------------------
if fsck.fat -n "${work_dir}/a.img" >/dev/null 2>&1; then
   pass 'fsck.fat reports the normalized image clean'
else
   fail 'fsck.fat found errors in the normalized image'
fi

## --- 7. refuses without SOURCE_DATE_EPOCH (no silent non-reproducible run) ---
status=0
env --unset=SOURCE_DATE_EPOCH "${tool}" "${work_dir}/a.img" >/dev/null 2>&1 || status="$?"
if [ "${status}" -ne 0 ]; then
   pass 'refuses to run without SOURCE_DATE_EPOCH'
else
   fail 'ran without SOURCE_DATE_EPOCH (silent non-reproducible)'
fi

## --- 8. an empty / too-short file is refused cleanly (not a crash) -----------
## Guards against the '$(( 16# ))' arithmetic crash on unreadable boot-sector bytes.
truncate --size=0 -- "${work_dir}/empty.img"
status=0
out="$( "${tool}" "${work_dir}/empty.img" 2>&1 )" || status="$?"
if [ "${status}" -ne 0 ] && [[ "${out}" != *"syntax error"* ]] \
   && [[ "${out}" != *"operand expected"* ]]; then
   pass 'an empty file is refused cleanly, not a bash arithmetic crash'
else
   fail "empty file gave status=${status} out=${out}"
fi

## --- 9. a non-FAT32 (FAT16) image is REFUSED, not corrupted ------------------
## Hardcoded FAT32 offsets would mangle a FAT16 ESP; the tool must refuse it.
## mkfs.fat -C SIZE_KB makes a 16 MiB filesystem, which mkfs.fat lays out as FAT16.
mkfs.fat -C "${work_dir}/fat16.img" 16384 >/dev/null 2>&1
cp "${work_dir}/fat16.img" "${work_dir}/fat16.before"
status=0
"${tool}" "${work_dir}/fat16.img" >/dev/null 2>&1 || status="$?"
fat16_state="MODIFIED"
if cmp --quiet "${work_dir}/fat16.before" "${work_dir}/fat16.img"; then
   fat16_state="unchanged"
fi
if [ "${status}" -ne 0 ] && [ "${fat16_state}" = "unchanged" ]; then
   pass 'a FAT16 image is refused and left byte-for-byte unchanged'
else
   fail "FAT16 handling: status=${status}, image ${fat16_state}"
fi

printf '%s\n' "===== dm-normalize-fat-partition: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
