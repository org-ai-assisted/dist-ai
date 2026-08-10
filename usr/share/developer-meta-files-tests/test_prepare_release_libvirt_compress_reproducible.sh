#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproducibility regression test for developer-meta-files 'dm-prepare-release',
## libvirt_compress(): the '.libvirt.xz' archive must be BYTE-IDENTICAL across
## builds. To give pv a real percentage, the tool splits tar's internal '--xz'
## into an explicit '| xz' and runs 'pv -s <size>' on the uncompressed tar stream
## in between. That split, and the pv pass-through, must not change a single byte
## of the archive.
##
## This test runs standalone (no helper-scripts), so it detects its tools with
## command -v rather than has().
## style-ok: no-has
##
## Two layers:
##   * STRUCTURAL -- the shipped libvirt_compress() still uses the split
##     'tar ... | pv -s ... | xz' form (not bare 'pv', not tar '--xz'), and
##     keeps every determinism flag (sorted, fixed mtime, numeric 0/0 owner,
##     fixed mode, sparse). Guards a silent revert.
##   * BEHAVIOURAL (the before/after test) -- reproduce the OLD pipeline
##     ('tar ... --xz') and the NEW one ('tar ... | pv -s N | xz'), over a
##     fixture that INCLUDES a sparse raw member, and assert the archives are
##     byte-identical (sha256). Also asserts each pipeline is internally
##     reproducible (identical across two runs).
##
## pv/xz/tar are hard requirements (declared in the consumer apt-packages); a
## present subject with an absent prerequisite is a FATAL, never a skip.
## Needs no root, no network, no build.

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

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## A prefixed candidate is only added when its prefix var is set: an unset
## '${DEVELOPER_META_FILES_DIR:-}/usr/bin/...' collapses to '/usr/bin/...' and
## would short-circuit to the INSTALLED (possibly stale) copy before the checkout
## candidate is ever tried -- exactly what would make this test judge old code.
candidates=()
[ -z "${DM_PREPARE_RELEASE:-}" ] || candidates+=( "${DM_PREPARE_RELEASE}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/usr/bin/dm-prepare-release" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-prepare-release" )
candidates+=( "/usr/bin/dm-prepare-release" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "SKIP: dm-prepare-release not found (set DM_PREPARE_RELEASE)." >&2
   exit 77
fi

## Present subject: its prerequisites are required, not optional.
for tool in tar xz pv du sha256sum; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; it is a hard requirement of the pipeline under test." >&2
      exit 1
   fi
done

## --- STRUCTURAL: the shipped pipeline still has the reproducible pv form ----
block="$(sed -n '/^libvirt_compress()/,/^}/p' -- "${subject}")"
if [ -z "${block}" ]; then
   printf '%s\n' "FATAL: could not extract libvirt_compress() from ${subject}." >&2
   exit 1
fi
## Strip comment-only lines before structural greps: '--xz' still appears in the
## explanatory comment, so a raw grep for it would false-positive on prose.
code="$(printf '%s\n' "${block}" | grep --invert-match --extended-regexp -- '^[[:space:]]*#')"

## The whole point of the split: pv needs the uncompressed size for a real %,
## so xz must be an explicit stage and pv must be given '-s <size>'.
if printf '%s\n' "${code}" | grep --quiet --extended-regexp -- '[|][[:space:]]*pv[[:space:]]+-s[[:space:]]'; then
   pass "structural: pv runs with an explicit size ('pv -s'), so the meter shows a real percentage"
else
   fail "structural: pv is not given a size; the meter would show throughput only (or was removed)"
fi
if printf '%s\n' "${code}" | grep --quiet --extended-regexp -- '[|][[:space:]]*xz\b'; then
   pass "structural: xz is an explicit pipeline stage"
else
   fail "structural: xz is not an explicit stage"
fi
## A revert to tar's internal '--xz' would compress before pv could size it.
if printf '%s\n' "${code}" | grep --quiet --extended-regexp -- '(^|[[:space:]])--xz($|[[:space:]])'; then
   fail "structural: tar still uses '--xz'; that compresses inside tar, defeating the pv size meter"
else
   pass "structural: tar does not use its internal '--xz'"
fi

## Every determinism flag must survive; losing any one silently breaks byte
## reproducibility of the archive.
for flag_desc in \
   '--sort=name:members sorted deterministically' \
   "--mtime=:fixed member mtime" \
   '--numeric-owner:numeric owner ids' \
   '--owner=0:owner normalised to 0' \
   '--group=0:group normalised to 0' \
   '--sparse:sparse members handled deterministically' \
   '--mode=:fixed member mode'; do
   flag="${flag_desc%%:*}"
   desc="${flag_desc#*:}"
   if printf '%s\n' "${code}" | grep --quiet --fixed-strings -- "${flag}"; then
      pass "structural: keeps '${flag}' (${desc})"
   else
      fail "structural: dropped '${flag}' (${desc}); archive would no longer be reproducible"
   fi
done

## --- BEHAVIOURAL: OLD (--xz) vs NEW (| pv -s | xz) are byte-identical -------
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

members_dir="${workdir}/members"
mkdir --parents -- "${members_dir}"
## A regular text member, a binary member, and a SPARSE raw member -- the sparse
## case is exactly what libvirt_compress() archives (a raw disk image) and the
## one most sensitive to the tar path taken.
printf '%s\n' 'reproducible fixture member' > "${members_dir}/notes.txt"
head --bytes=4096 /dev/zero | tr '\0' 'A' > "${members_dir}/blob.bin"
truncate --size=8M -- "${members_dir}/disk.raw"
printf '%s' 'HEADER-BYTES' | dd of="${members_dir}/disk.raw" conv=notrunc status=none
printf '%s' 'TAILER-BYTES' | dd of="${members_dir}/disk.raw" bs=1 seek=8388600 conv=notrunc status=none

## Members in a fixed order; tar --sort=name makes order irrelevant, but keep it
## stable so the fixture itself is deterministic.
members=( blob.bin disk.raw notes.txt )

## The canonical determinism flags, matching libvirt_compress(). The structural
## block above asserts the shipped tool still carries these same flags, so this
## fixture exercises the tool's real invariant.
## Hoisted so the comma-containing mode string is not a bare array element
## (shellcheck SC2054 reads inline commas as element separators).
tar_mode='go=rX,u+rw,a-s'
tar_mtime='2015-10-21 00:00Z'
tar_common=(
   --create
   --owner=0 --group=0 --numeric-owner
   --mode="${tar_mode}"
   --sort=name
   --sparse
   --mtime="${tar_mtime}"
   --directory="${members_dir}"
   --file -
)

## OLD pipeline: tar compresses internally with --xz.
old_a="${workdir}/old_a.tar.xz"
old_b="${workdir}/old_b.tar.xz"
tar "${tar_common[@]}" --xz "${members[@]}" > "${old_a}"
tar "${tar_common[@]}" --xz "${members[@]}" > "${old_b}"

## NEW pipeline: split '--xz' into an explicit '| xz', with 'pv -s <size>' in
## between (the real shipped form). du -scB1 is the size source in the tool.
input_size="$(du -scB1 -- "${members_dir}"/* | tail -1 | cut -f1)"
new_a="${workdir}/new_a.tar.xz"
new_b="${workdir}/new_b.tar.xz"
tar "${tar_common[@]}" "${members[@]}" | pv -s "${input_size}" 2>/dev/null | xz > "${new_a}"
tar "${tar_common[@]}" "${members[@]}" | pv -s "${input_size}" 2>/dev/null | xz > "${new_b}"

## NEW pipeline WITHOUT pv, to isolate the '--xz' -> '| xz' split from pv itself.
nopv="${workdir}/nopv.tar.xz"
tar "${tar_common[@]}" "${members[@]}" | xz > "${nopv}"

sum() {
   sha256sum -- "$1" | cut -d' ' -f1
}
old_a_sum="$(sum "${old_a}")"
old_b_sum="$(sum "${old_b}")"
new_a_sum="$(sum "${new_a}")"
new_b_sum="$(sum "${new_b}")"
nopv_sum="$(sum "${nopv}")"

## Each pipeline is internally reproducible.
if [ "${old_a_sum}" = "${old_b_sum}" ]; then
   pass "behavioural: OLD pipeline ('tar --xz') is internally reproducible"
else
   fail "behavioural: OLD pipeline is NOT reproducible across runs (${old_a_sum} != ${old_b_sum})"
fi
if [ "${new_a_sum}" = "${new_b_sum}" ]; then
   pass "behavioural: NEW pipeline ('tar | pv -s | xz') is internally reproducible"
else
   fail "behavioural: NEW pipeline is NOT reproducible across runs (${new_a_sum} != ${new_b_sum})"
fi

## The before/after invariant: NEW == OLD, byte for byte.
if [ "${new_a_sum}" = "${old_a_sum}" ]; then
   pass "behavioural: NEW archive is byte-identical to OLD (pv split preserves reproducibility)"
else
   fail "behavioural: NEW archive DIFFERS from OLD (${new_a_sum} != ${old_a_sum}); the pv split broke reproducibility"
fi
## And the split alone (without pv) is also identity -- pins the blame precisely
## if the equality above ever fails.
if [ "${nopv_sum}" = "${old_a_sum}" ]; then
   pass "behavioural: 'tar | xz' == 'tar --xz' (the split itself is byte-neutral)"
else
   fail "behavioural: 'tar | xz' differs from 'tar --xz' (${nopv_sum} != ${old_a_sum})"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: prepare-release libvirt_compress reproducible (pv split is byte-neutral)."
