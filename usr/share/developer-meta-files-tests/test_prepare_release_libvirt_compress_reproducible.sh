#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproducibility regression test for developer-meta-files 'dm-prepare-release',
## libvirt_compress(): the '.libvirt.xz' archive must be BYTE-IDENTICAL across
## builds. It is built with 'tar ... | pv -s <size> | xz', member mtimes pinned to
## SOURCE_DATE_EPOCH, then run through strip-nondeterminism.
##
## This drives the REAL function -- libvirt_compress() is extracted verbatim from
## the shipped dm-prepare-release and invoked against a fixture -- so the actual
## tar/pv/xz/strip-nondeterminism pipeline is what runs, not a copy of it. A pure
## structural grep would pass a rewrite that silently changed the bytes; running
## the function catches that.
##
## This test runs standalone (no helper-scripts), so it detects its tools with
## command -v rather than has().
## style-ok: no-has
##
## Two layers:
##   * STRUCTURAL -- a fast, explicit guard that the function still uses the
##     'tar ... | pv -s ... | xz' form (not bare 'pv', not tar '--xz'), pins the
##     mtime to SOURCE_DATE_EPOCH (not a hardcoded date) and guards an unset epoch.
##   * BEHAVIOURAL -- invoke the real function over a fixture with incompressible,
##     compressible and sparse content and assert: byte-identical across three
##     runs (reproducible), the archive is far smaller than the members (it
##     actually compresses), extraction reproduces every member bit-for-bit
##     (lossless), and an unset SOURCE_DATE_EPOCH aborts (the guard fires).
##
## pv/xz/tar/strip-nondeterminism are hard requirements (declared in the consumer
## apt-packages); a present subject with an absent prerequisite is a FATAL, never
## a skip. Needs no root, no network, no build.

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

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
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
for tool in tar xz pv du sha256sum strip-nondeterminism; do
   if ! command -v "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: '${tool}' missing; it is a hard requirement of the pipeline under test." >&2
      exit 1
   fi
done

## --- extract the REAL libvirt_compress() -----------------------------------
## Its closing brace is the first line-initial '}' after the definition (no
## nested line-initial braces), so this captures the whole function verbatim.
func_src="$(sed -n '/^libvirt_compress()/,/^}/p' -- "${subject}")"
if [ -z "${func_src}" ]; then
   printf '%s\n' "FATAL: could not extract libvirt_compress() from ${subject}." >&2
   exit 1
fi
## Strip comment-only lines before structural greps: '--xz' still appears in the
## explanatory comment, so a raw grep would false-positive on prose.
code="$(printf '%s\n' "${func_src}" | grep --invert-match --extended-regexp -- '^[[:space:]]*#')"

## --- STRUCTURAL: fast guards on the shipped pipeline ------------------------
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
if printf '%s\n' "${code}" | grep --quiet --extended-regexp -- '(^|[[:space:]])--xz($|[[:space:]])'; then
   fail "structural: tar still uses '--xz'; that compresses inside tar, defeating the pv size meter"
else
   pass "structural: tar does not use its internal '--xz'"
fi
if printf '%s\n' "${code}" | grep --quiet --fixed-strings -- '--mtime="@${SOURCE_DATE_EPOCH}"'; then
   pass "structural: member mtime pinned to SOURCE_DATE_EPOCH (not a hardcoded date)"
else
   fail "structural: member mtime is not @SOURCE_DATE_EPOCH; a hardcoded date desyncs the archive from every other artifact"
fi
if printf '%s\n' "${code}" | grep --quiet --fixed-strings -- 'SOURCE_DATE_EPOCH:-'; then
   pass "structural: unset SOURCE_DATE_EPOCH is guarded (fails loudly, not silently)"
else
   fail "structural: SOURCE_DATE_EPOCH is used without an unset guard"
fi

## --- BEHAVIOURAL: run the real function ------------------------------------
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## Source the extracted function plus the minimal helpers it calls. 'error' is
## normally from help-steps/pre; stub it to a hard failure (its contract).
## 'legal_files_copy' copies license/disclaimer files into the build folder;
## under dist_build_type_short=test they are not added to the archive list, so a
## no-op stub is faithful for this path.
func_file="${workdir}/libvirt_compress.bsh"
{
   ## The real 'error' is fatal (it trips the ERR trap and exits); a stub that
   ## only 'return'ed would be swallowed where errexit is off, so exit hard.
   printf '%s\n' 'error() { printf "%s\n" "ERROR: $*" >&2; exit 1; }'
   printf '%s\n' 'legal_files_copy() { true; }'
   printf '%s\n' "${func_src}"
} > "${func_file}"
# shellcheck disable=SC1090 # dynamic path: the function is extracted at runtime
source "${func_file}"

## Master fixture, generated ONCE. The image member mixes:
##   * random head + tail  -- INCOMPRESSIBLE, so the archive is not trivially tiny
##   * a zero region        -- compressible / a hole under '--sparse'
##   * a repeated-byte region -- compressible but NON-zero, so tar cannot hole it
##                              and xz must actually compress it
## plus a sparse gap between regions. The XML member is small text.
master="${workdir}/master"
mkdir --parents -- "${master}"
cat > "${master}/Whonix-Gateway.xml" <<'XML'
<domain type='kvm'>
  <name>Whonix-Gateway</name>
  <memory unit='KiB'>524288</memory>
</domain>
XML
image="${master}/Whonix-Gateway.qcow2"
truncate --size=16M -- "${image}"
head --bytes=1048576 /dev/urandom | dd of="${image}" bs=1M seek=0 conv=notrunc status=none
head --bytes=4194304 /dev/zero | dd of="${image}" bs=1M seek=2 conv=notrunc status=none
head --bytes=4194304 /dev/zero | tr '\0' 'A' | dd of="${image}" bs=1M seek=7 conv=notrunc status=none
head --bytes=1048576 /dev/urandom | dd of="${image}" bs=1M seek=15 conv=notrunc status=none

member_names=( Whonix-Gateway.qcow2 Whonix-Gateway.xml )

## The globals libvirt_compress() reads for the vm_multiple=false / qcow2 path.
build_folder="${workdir}/build"
dist_binary_build_folder="${build_folder}"
SHORT_VMNAME="Whonix-Gateway"
vm_multiple="false"
dist_build_qcow2="true"
dist_build_type_short="test"
binary_image_qcow2_file="${build_folder}/Whonix-Gateway.qcow2"
libvirt_target_qcow2_xz_archive_file="${build_folder}/Whonix-Gateway.libvirt.xz"
export dist_binary_build_folder SHORT_VMNAME vm_multiple dist_build_qcow2 \
   dist_build_type_short binary_image_qcow2_file libvirt_target_qcow2_xz_archive_file

## The function deletes its input members, so lay down fresh copies from the
## master before each invocation.
prepare_members() {
   safe-rm --recursive --force -- "${build_folder}"
   mkdir --parents -- "${build_folder}"
   cp --preserve=all -- "${master}/Whonix-Gateway.xml" "${build_folder}/"
   cp --preserve=all --sparse=always -- "${image}" "${build_folder}/Whonix-Gateway.qcow2"
}
## Run the REAL function once and copy out the archive it produced.
archive_out="${workdir}/archive.libvirt.xz"
run_real_compress() {
   prepare_members
   ( cd -- "${build_folder}" && libvirt_compress ) 1>&2
   cp --preserve=all -- "${libvirt_target_qcow2_xz_archive_file}" "${archive_out}"
}

sum() {
   sha256sum -- "$1" | cut -d' ' -f1
}

## Reproducible: three real runs, byte-identical archives.
run_sums=()
run_index=0
saved_archive="${workdir}/run1.libvirt.xz"
while [ "${run_index}" -lt 3 ]; do
   run_index=$(( run_index + 1 ))
   export SOURCE_DATE_EPOCH=1445385600
   run_real_compress
   run_sums+=( "$(sum "${archive_out}")" )
   [ "${run_index}" -ne 1 ] || cp --preserve=all -- "${archive_out}" "${saved_archive}"
done
runs_identical=true
for one_sum in "${run_sums[@]}"; do
   [ "${one_sum}" = "${run_sums[0]}" ] || runs_identical=false
done
if [ "${runs_identical}" = true ]; then
   pass "reproducible: real libvirt_compress() is byte-identical across 3 runs (${run_sums[0]})"
else
   fail "reproducible: real libvirt_compress() differs across runs (${run_sums[*]})"
fi

## Compression is actually ON: the archive is far smaller than the members it
## packs (which include the compressible zero + pattern regions).
members_bytes=0
for member_name in "${member_names[@]}"; do
   member_size="$(stat --format=%s -- "${master}/${member_name}")"
   members_bytes=$(( members_bytes + member_size ))
done
archive_bytes="$(stat --format=%s -- "${saved_archive}")"
if [ "${archive_bytes}" -lt "$(( members_bytes / 2 ))" ]; then
   pass "compression: archive ${archive_bytes}B < half the ${members_bytes}B of members -- xz is compressing, not storing"
else
   fail "compression: archive ${archive_bytes}B not < half the ${members_bytes}B of members; xz may be storing, not compressing"
fi

## Round-trip: extract the real archive and confirm every member's content hash
## matches the pre-compression master, holes included.
extract_dir="${workdir}/extract"
mkdir --parents -- "${extract_dir}"
xz --decompress --stdout "${saved_archive}" | tar --extract --sparse --directory="${extract_dir}"
roundtrip_ok=true
for member_name in "${member_names[@]}"; do
   if [ ! -e "${extract_dir}/${member_name}" ]; then
      fail "round-trip: member '${member_name}' missing after extraction"
      roundtrip_ok=false
      continue
   fi
   before_hash="$(sum "${master}/${member_name}")"
   after_hash="$(sum "${extract_dir}/${member_name}")"
   if [ "${before_hash}" != "${after_hash}" ]; then
      fail "round-trip: '${member_name}' changed (pre ${before_hash} != post ${after_hash})"
      roundtrip_ok=false
   fi
done
if [ "${roundtrip_ok}" = true ]; then
   pass "round-trip: every member's content hash is identical before compression and after extraction"
fi

## The SOURCE_DATE_EPOCH guard actually fires: with it unset, the real function
## must abort (and produce no archive) rather than a wrong-dated one. Invoke the
## function directly so the assertion is about the guard, not the copy wrapper.
prepare_members
guard_rc=0
( cd -- "${build_folder}" && unset SOURCE_DATE_EPOCH && libvirt_compress ) >/dev/null 2>&1 || guard_rc="$?"
if [ "${guard_rc}" -ne 0 ] && [ ! -e "${libvirt_target_qcow2_xz_archive_file}" ]; then
   pass "guard: real libvirt_compress() aborts on unset SOURCE_DATE_EPOCH (exit ${guard_rc}, no archive)"
elif [ "${guard_rc}" -eq 0 ]; then
   fail "guard: real libvirt_compress() did NOT abort on unset SOURCE_DATE_EPOCH"
else
   fail "guard: aborted (exit ${guard_rc}) but still left an archive behind"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: real libvirt_compress() reproducible (byte-identical across runs, compresses, lossless round-trip, epoch-guarded)."
