#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build-steps.d/4300_run-chroot-scripts-post-d: copy_image_sbom_out copies the
## embedded image SBOM out of the still-mounted rootfs for the release step to
## sign.
##
## REGRESSION for the cross-flavor clobbering bug (ai-review, 3 reviewers): the
## copy MUST be named after this build's raw image (${binary_image_raw_file}.cdx.json),
## NOT a fixed shared name, because flavor/target builds share
## ${dist_binary_build_folder}. A fixed name let each build overwrite the
## previous one's SBOM, so the release step signed the wrong image's SBOM onto
## every artifact.
##
## dm-build-step-fn extracts the function (the build step sources pre/variables
## and ends in main "$@", so it cannot be sourced whole). SUDO_TO_ROOT is empty
## so the real safe-rm/cp/chown run on tmpdir fixtures, no root, no network.
## Asserts: per-build naming; two flavor builds coexist without clobber; the old
## fixed name is never produced; absent embedded SBOM is a no-op; a pre-existing
## symlink at the output path is replaced, not followed.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
step="${dm_checkout}/build-steps.d/4300_run-chroot-scripts-post-d"
if [ ! -r "${step}" ]; then
   printf '%s\n' "FATAL: build step not readable at '${step}' (set DERIVATIVE_MAKER_DIR)" >&2
   exit 1
fi

if [ -n "${DIST_AI_DIR:-}" ]; then
   dist_ai_dir="${DIST_AI_DIR}"
else
   dist_ai_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
fi
tool="${dist_ai_dir}/usr/bin/dm-build-step-fn"
[ -x "${tool}" ] || tool="$(type -P dm-build-step-fn || true)"
if [ -z "${tool}" ] || [ ! -x "${tool}" ]; then
   printf '%s\n' "FATAL: dm-build-step-fn not found or not executable" >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"; got="$2"; want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"; pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')" >&2; fail=$((fail + 1))
   fi
}
exists() { if [ -e "$1" ]; then printf '%s' yes; else printf '%s' no; fi; }

## Empty = run safe-rm/cp/chown directly (chown to self is a no-op). The step
## interpolates ${SUDO_TO_ROOT} before each.
export SUDO_TO_ROOT=""

## Fixtures: a mounted rootfs with an embedded SBOM, and a shared output folder.
chroot_dir="${work}/chroot"
outdir="${work}/binary"
mkdir --parents -- "${chroot_dir}/usr/share/sbom" "${outdir}"
embedded="${chroot_dir}/usr/share/sbom/system.cdx.json"

## Define the real function (not a copy).
eval "$("${tool}" --file "${step}" --fn copy_image_sbom_out)"
check "function extracted" "$(type -t copy_image_sbom_out)" "function"

## These names mimic two flavors of one product build sharing ${outdir}.
raw_a="${outdir}/Kicksecure-A-18.0.amd64.raw"
raw_b="${outdir}/Kicksecure-B-18.0.amd64.raw"
fixed_old="${outdir}/system.cdx.json"   ## the pre-fix (clobbering) name

## ---- flavor A ----
printf '%s\n' 'SBOM-FLAVOR-A' > "${embedded}"
CHROOT_FOLDER="${chroot_dir}" binary_image_raw_file="${raw_a}" dist_binary_build_folder="${outdir}" \
   copy_image_sbom_out
check "A: sidecar named after the raw image" "$(exists "${raw_a}.cdx.json")" "yes"
check "A: sidecar carries flavor A content" "$(cat -- "${raw_a}.cdx.json" 2>/dev/null)" "SBOM-FLAVOR-A"
check "A: the old fixed shared name is NOT produced" "$(exists "${fixed_old}")" "no"

## ---- flavor B (same output folder, different rootfs content) ----
printf '%s\n' 'SBOM-FLAVOR-B' > "${embedded}"
CHROOT_FOLDER="${chroot_dir}" binary_image_raw_file="${raw_b}" dist_binary_build_folder="${outdir}" \
   copy_image_sbom_out
check "B: sidecar named after its own raw image" "$(exists "${raw_b}.cdx.json")" "yes"
check "B: sidecar carries flavor B content" "$(cat -- "${raw_b}.cdx.json" 2>/dev/null)" "SBOM-FLAVOR-B"
## The clobbering regression: A's sidecar must still exist AND still hold A's
## content after B's run (a fixed shared name would have overwritten it).
check "no-clobber: A's sidecar survives B's build" "$(exists "${raw_a}.cdx.json")" "yes"
check "no-clobber: A's content is intact" "$(cat -- "${raw_a}.cdx.json" 2>/dev/null)" "SBOM-FLAVOR-A"

## ---- rerun of the SAME build refreshes (safe-rm + cp), never stale ----
## A rebuild of flavor A at the same version reuses raw_a; the copy-out must
## overwrite the old sidecar with the new rootfs's SBOM, not leave the stale one.
printf '%s\n' 'SBOM-FLAVOR-A-REBUILT' > "${embedded}"
CHROOT_FOLDER="${chroot_dir}" binary_image_raw_file="${raw_a}" dist_binary_build_folder="${outdir}" \
   copy_image_sbom_out
check "rerun: same-build sidecar refreshed, not stale" \
   "$(cat -- "${raw_a}.cdx.json" 2>/dev/null)" "SBOM-FLAVOR-A-REBUILT"

## ---- absent embedded SBOM (hook skipped: SOURCE_DATE_EPOCH unset) -> no-op ----
safe-rm --force -- "${embedded}"
raw_c="${outdir}/Kicksecure-C-18.0.amd64.raw"
rc=0
CHROOT_FOLDER="${chroot_dir}" binary_image_raw_file="${raw_c}" dist_binary_build_folder="${outdir}" \
   copy_image_sbom_out || rc=$?
check "no-embedded: returns 0 (no-op)" "${rc}" "0"
check "no-embedded: no sidecar written" "$(exists "${raw_c}.cdx.json")" "no"

## ---- symlink safety: a pre-existing symlink at the output path is replaced ----
printf '%s\n' 'SBOM-FLAVOR-D' > "${embedded}"
raw_d="${outdir}/Kicksecure-D-18.0.amd64.raw"
sentinel="${work}/sentinel-must-not-change"
printf '%s\n' 'SENTINEL-UNTOUCHED' > "${sentinel}"
ln --symbolic -- "${sentinel}" "${raw_d}.cdx.json"
CHROOT_FOLDER="${chroot_dir}" binary_image_raw_file="${raw_d}" dist_binary_build_folder="${outdir}" \
   copy_image_sbom_out
check "symlink: output is now a regular file, not a symlink" \
   "$(if [ -L "${raw_d}.cdx.json" ]; then printf '%s' symlink; else printf '%s' regular; fi)" "regular"
check "symlink: the symlink target was NOT overwritten" "$(cat -- "${sentinel}")" "SENTINEL-UNTOUCHED"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
