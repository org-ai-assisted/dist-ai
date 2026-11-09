#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build-steps.d/2100_create-debian-packages: the trixie-backports downloader
## that carries debsbom into our apt repo for the image-level SBOM.
##
## The function is a thin config wrapper: it sets the engine's knobs then calls
## build_run_function get_newer_packages_from_third_party_repositories. A build
## step sources pre/variables and ends in main "$@", so it cannot be sourced
## whole; dm-build-step-fn extracts just this function. The test defines it
## against fixture vars + a build_run_function stub, calls it, and asserts the
## knobs (target release, package, sources list, source-package flag) and the
## dispatch -- so a regression (wrong suite, dropped debsbom, back to a
## different backports) fails loudly without a ~50min build.
##
## No root, no network, no build.

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
step="${dm_checkout}/build-steps.d/2100_create-debian-packages"
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

## Fixture values for the vars the function interpolates; the engine itself is
## stubbed, so these are just distinguishable sentinels.
dist_source_help_steps_folder="/fixture/help-steps"
dist_build_sources_list_debian_trixie_backports="/fixture/debian_trixie_backports.sources"
binary_build_folder_dist="/fixture/binary"

## Stub the engine: record the function it is dispatched to; run nothing.
dispatched=""
build_run_function() { dispatched="$1"; }

## Define the real function from the real build step (not a copy).
fn_text="$("${tool}" --file "${step}" --fn download_packages_from_debian_trixie_backports)"
eval "${fn_text}"

check "function was extracted" "$(type -t download_packages_from_debian_trixie_backports)" "function"

download_packages_from_debian_trixie_backports

check "target release is trixie-backports"        "${apt_target_release:-}"                       "trixie-backports"
check "fetches debsbom"                           "${newer_package_list:-}"                       "debsbom"
check "source-package download off (binary only)" "${download_source_package:-}"                  "false"
check "sources list = trixie-backports .sources"  "${repo_sources_list:-}"                        "${dist_build_sources_list_debian_trixie_backports}"
check "Debian archive key trusted (none to add)"  "${repo_signing_key:-}"                         "none"
check "arch-all download"                         "${available_architectures_for_download_only_list:-}" "all"
check "chroot download script"                    "${dist_build_special_packages_chroot_script:-}" "${dist_source_help_steps_folder}/repo_download_chroot_script"
check "temp dir is suite-distinct"                "${temp_newer_packages:-}"                      "${binary_build_folder_dist}/temp_packages_debian_trixie_backports"
check "dispatches to the shared download engine"  "${dispatched}"                                 "get_newer_packages_from_third_party_repositories"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
