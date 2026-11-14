#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## developer-meta-files 'dm-prepare-release': image_sbom_sidecar_sign publishes
## the image's embedded CycloneDX SBOM as a signed sidecar next to one artifact.
##
## CONSUMER side of the cross-flavor clobbering fix (ai-review, 3 reviewers):
## the sidecar content MUST come from this build's own
## ${binary_image_raw_file}.cdx.json (named per flavor/target), and only IMAGE
## artifacts (a non-empty target: ova/raw/qcow2/iso) get it -- source/installer
## artifacts must not, matching .dm-buildinfo.
##
## dm-prepare-release sources help-steps/pre + variables at load, so it cannot
## be sourced whole; dm-build-step-fn extracts just this function. The test
## defines it with sign_and_verify_signify stubbed (recording), against tmpdir
## fixtures. No root, no network, no build.

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
subject=""
for candidate in "${DM_PREPARE_RELEASE:-}" \
   "${DEVELOPER_META_FILES_DIR:+${DEVELOPER_META_FILES_DIR}/usr/bin/dm-prepare-release}" \
   "${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-prepare-release" \
   "/usr/bin/dm-prepare-release"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-prepare-release not found (set DM_PREPARE_RELEASE)." >&2
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

## Stub the signer: record the file it is asked to sign.
signed_rec="${work}/signed.list"
printf '%s' "" > "${signed_rec}"
sign_and_verify_signify() { printf '%s\n' "$1" >> "${signed_rec}"; }
signed_with() { grep --quiet --fixed-strings --line-regexp -- "$1" "${signed_rec}"; }
yn() { if "$@"; then printf '%s' yes; else printf '%s' no; fi; }

## This build's per-flavor SBOM staging file (what 4300 produced).
export binary_image_raw_file="${work}/Kicksecure-A-18.0.amd64.raw"
printf '%s\n' 'SBOM-OF-THIS-BUILD' > "${binary_image_raw_file}.cdx.json"

eval "$("${tool}" --file "${subject}" --fn image_sbom_sidecar_sign)"
check "function extracted" "$(type -t image_sbom_sidecar_sign)" "function"

## ---- image artifact (compressed raw) gets a signed sidecar ----
printf '%s' "" > "${signed_rec}"
raw_xz="${work}/Kicksecure-A-18.0.amd64.raw.libvirt.xz"
image_sbom_sidecar_sign "${raw_xz}" "raw"
check "image: sidecar created next to the artifact" "$(exists "${raw_xz}.cdx.json")" "yes"
check "image: sidecar content from THIS build's staging" "$(cat -- "${raw_xz}.cdx.json" 2>/dev/null)" "SBOM-OF-THIS-BUILD"
check "image: the sidecar was signed" "$(yn signed_with "${raw_xz}.cdx.json")" "yes"

## ---- non-image artifact (empty target: source/installer) gets NO sidecar ----
printf '%s' "" > "${signed_rec}"
src_xz="${work}/derivative-maker-source.tar.xz"
image_sbom_sidecar_sign "${src_xz}" ""
check "non-image: no sidecar for an empty target" "$(exists "${src_xz}.cdx.json")" "no"
check "non-image: nothing signed" "$(yn signed_with "${src_xz}.cdx.json")" "no"

## ---- staging SBOM absent (hook skipped upstream) -> no-op ----
printf '%s' "" > "${signed_rec}"
safe-rm --force -- "${binary_image_raw_file}.cdx.json"
iso="${work}/Kicksecure-A-18.0.amd64.iso"
rc=0
image_sbom_sidecar_sign "${iso}" "iso" || rc=$?
check "absent-staging: returns 0 (no-op)" "${rc}" "0"
check "absent-staging: no sidecar" "$(exists "${iso}.cdx.json")" "no"
check "absent-staging: nothing signed" "$(yn signed_with "${iso}.cdx.json")" "no"

## ---- symlink safety: a pre-existing symlink at the dest is replaced ----
printf '%s' "" > "${signed_rec}"
printf '%s\n' 'SBOM-OF-THIS-BUILD-2' > "${binary_image_raw_file}.cdx.json"
ova="${work}/Kicksecure-A-18.0.amd64.ova"
sentinel="${work}/sentinel-must-not-change"
printf '%s\n' 'SENTINEL-UNTOUCHED' > "${sentinel}"
ln --symbolic -- "${sentinel}" "${ova}.cdx.json"
image_sbom_sidecar_sign "${ova}" "virtualbox"
check "symlink: dest is now a regular file" \
   "$(if [ -L "${ova}.cdx.json" ]; then printf '%s' symlink; else printf '%s' regular; fi)" "regular"
check "symlink: the symlink target was NOT overwritten" "$(cat -- "${sentinel}")" "SENTINEL-UNTOUCHED"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
