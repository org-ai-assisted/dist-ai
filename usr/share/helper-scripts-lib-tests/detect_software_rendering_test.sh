#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## detect-software-rendering: short-circuits, source-ability, classification and
## the per-boot cache.
##  (1) Fast-exit before any GL probe: LIBGL_ALWAYS_SOFTWARE truthy -> software,
##      and no DRM node -> software; both WITHOUT invoking eglinfo.
##  (2) Sourcing the script does NOT auto-run and does NOT leak strict-mode, and
##      the reusable detect_software_rendering() is pure and defined. Probed by
##      the committed non-strict detect_software_rendering_source_probe.sh -- no
##      inline shell program here.
##  (3) With a DRM node present it falls through to the mock eglinfo
##      (detect_software_rendering_eglinfo_stub.sh): a vendor string ->
##      accelerated (exit 1), llvmpipe -> software (exit 0), unrecognized or
##      empty -> unknown (exit 2).
##  (4) The per-boot cache means the eglinfo fall-through runs at most once across
##      two shells.
##
## Drives the REAL script. A missing dependency is a HARD FAIL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
stub_file="${tool_dir}/detect_software_rendering_eglinfo_stub.sh"
probe="${tool_dir}/detect_software_rendering_source_probe.sh"

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/bin/detect-software-rendering"
   libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
else
   subject='/usr/bin/detect-software-rendering'
   libdir='/usr/libexec/helper-scripts'
fi

if [ ! -x "${subject}" ]; then
   printf '%s\n' "FATAL: subject not executable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -r "${libdir}/has.sh" ] || [ ! -r "${libdir}/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: helper-scripts libs not readable under '${libdir}'" >&2
   exit 1
fi
if [ ! -x "${stub_file}" ] || [ ! -x "${probe}" ]; then
   printf '%s\n' "FATAL: test support scripts missing next to '${tool_dir}'" >&2
   exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${libdir}/has.sh"

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

## The mock eglinfo goes on PATH under its real name.
bindir="${test_dir}/bin"
mkdir --parents -- "${bindir}"
ln -s -- "${stub_file}" "${bindir}/eglinfo"
probe_path="${bindir}:${PATH}"

## Two DRM-node dirs for the short-circuit seam: one WITH a fake render node (so
## the subject falls through to eglinfo), one empty (so it short-circuits).
with_dri="${test_dir}/with-dri"
no_dri="${test_dir}/no-dri"
mkdir --parents -- "${with_dri}" "${no_dri}"
touch -- "${with_dri}/renderD128"

## NVIDIA control-node seam: an absent path (default for run_subject, so the
## no-DRM cases short-circuit) and a present one (for the fall-through case).
nvidia_absent="${test_dir}/no-nvidiactl"
nvidia_present="${test_dir}/nvidiactl"
touch -- "${nvidia_present}"

## A nonexistent runtime dir disables the cache (an EMPTY XDG_RUNTIME_DIR would
## fall back to /run/user/<uid>, which exists on the test host).
no_cache_dir="${test_dir}/absent-runtime-dir"

## The subject resolves its own libs via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

## Env prefix that forces the eglinfo fall-through: no forced-software, a DRM node
## present, cache disabled.
count_file="${test_dir}/eglinfo.count"
llvmpipe_line='OpenGL core profile renderer: llvmpipe (LLVM)'

## Byte count of a file, or 0 when it does not exist (a short-circuit never
## creates the eglinfo counter).
count_of() {
   if [ -e "${1}" ]; then
      wc -c <"${1}" | tr -d ' '
   else
      printf '%s' 0
   fi
}

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

## Runs the subject and reports 'word:exitcode'. Named args after the env:
## $1 renderer line for the mock, $2 LIBGL value, $3 DRM dir, $4 count file (or '').
run_subject() {
   local line libgl dri_dir count out rc

   line="$1"
   libgl="$2"
   dri_dir="$3"
   count="$4"
   rc=0
   out="$(LIBGL_ALWAYS_SOFTWARE="${libgl}" DETECT_SOFTWARE_RENDERING_DRI_DIR="${dri_dir}" \
      DETECT_SOFTWARE_RENDERING_NVIDIA_CTL="${nvidia_absent}" \
      EGLINFO_STUB_RENDERER="${line}" EGLINFO_STUB_COUNT="${count}" \
      XDG_RUNTIME_DIR="${no_cache_dir}" PATH="${probe_path}" "${subject}")" || rc=$?
   printf '%s\n' "${out}:${rc}"
}

## --- (1) fast-exit short-circuits: no eglinfo invoked ---
safe-rm -f -- "${count_file}"
sc1="$(run_subject "${llvmpipe_line}" 1 "${with_dri}" "${count_file}")"
check "LIBGL_ALWAYS_SOFTWARE=1 -> software/0" "${sc1}" "software:0"
check "LIBGL short-circuit does not invoke eglinfo" "$(count_of "${count_file}")" "0"

safe-rm -f -- "${count_file}"
sc2="$(run_subject "${llvmpipe_line}" '' "${no_dri}" "${count_file}")"
check "no DRM node -> software/0" "${sc2}" "software:0"
check "no-DRM short-circuit does not invoke eglinfo" "$(count_of "${count_file}")" "0"

## NVIDIA control node present with no DRM node -> NOT short-circuited; falls
## through to eglinfo (proprietary NVIDIA renders via /dev/nvidia*, not a DRM node).
nv_rc=0
nv_out="$(LIBGL_ALWAYS_SOFTWARE='' DETECT_SOFTWARE_RENDERING_DRI_DIR="${no_dri}" \
   DETECT_SOFTWARE_RENDERING_NVIDIA_CTL="${nvidia_present}" \
   EGLINFO_STUB_RENDERER='OpenGL core profile renderer: NVIDIA GeForce' \
   XDG_RUNTIME_DIR="${no_cache_dir}" PATH="${probe_path}" "${subject}")" || nv_rc=$?
check "NVIDIA node present, no DRM -> falls through to eglinfo" "${nv_out}:${nv_rc}" "accelerated:1"

## --- (2) source-ability: no auto-run, no strict leak, pure + defined ---
src_out=""
src_rc=0
src_out="$(SUBJECT="${subject}" PATH="${probe_path}" "${probe}" source 2>/dev/null)" || src_rc=$?
check "sourcing does not enable errexit" "${src_rc}" "0"
check "sourcing does not auto-run" "${src_out}" ""

call_rc=0
SUBJECT="${subject}" PATH="${probe_path}" "${probe}" call >/dev/null 2>&1 || call_rc=$?
check "calling detect_software_rendering stays pure and defined" "${call_rc}" "0"

## --- (3) classification via the eglinfo fall-through (DRM node present) ---
check "vendor -> accelerated/1"   "$(run_subject 'OpenGL core profile renderer: NVIDIA GeForce' '' "${with_dri}" '')" "accelerated:1"
check "llvmpipe -> software/0"    "$(run_subject "${llvmpipe_line}" '' "${with_dri}" '')" "software:0"
check "unrecognized -> unknown/2" "$(run_subject 'some unrelated line' '' "${with_dri}" '')" "unknown:2"
check "empty output -> unknown/2" "$(run_subject '' '' "${with_dri}" '')" "unknown:2"

## --- (4) per-boot cache: the eglinfo fall-through runs at most once ---
safe-rm -f -- "${count_file}"
xdg="${test_dir}/xdg"
mkdir --parents -- "${xdg}"
c1="$(LIBGL_ALWAYS_SOFTWARE='' DETECT_SOFTWARE_RENDERING_DRI_DIR="${with_dri}" EGLINFO_STUB_RENDERER="${llvmpipe_line}" EGLINFO_STUB_COUNT="${count_file}" XDG_RUNTIME_DIR="${xdg}" PATH="${probe_path}" "${subject}")" || true
c2="$(LIBGL_ALWAYS_SOFTWARE='' DETECT_SOFTWARE_RENDERING_DRI_DIR="${with_dri}" EGLINFO_STUB_RENDERER="${llvmpipe_line}" EGLINFO_STUB_COUNT="${count_file}" XDG_RUNTIME_DIR="${xdg}" PATH="${probe_path}" "${subject}")" || true
eg_count="$(count_of "${count_file}")"
check "cache: both calls report software" "${c1}:${c2}" "software:software"
check "cache: eglinfo probed at most once across two shells" "${eg_count}" "1"
## Positively pin the marker filename, so the "cache not written" negative checks
## below (which test for this exact path) cannot pass vacuously.
xdg_cached="no"
if [ -e "${xdg}/detect-software-rendering.software" ]; then
   xdg_cached="yes"
fi
check "cache: marker written under the expected name" "${xdg_cached}" "yes"

## LIBGL_ALWAYS_SOFTWARE set is a per-env override -> the cache is NOT written,
## so a later shell without the var cannot read the forced-software marker.
lg_xdg="${test_dir}/lg-xdg"
mkdir --parents -- "${lg_xdg}"
LIBGL_ALWAYS_SOFTWARE=1 DETECT_SOFTWARE_RENDERING_DRI_DIR="${with_dri}" \
   DETECT_SOFTWARE_RENDERING_NVIDIA_CTL="${nvidia_absent}" XDG_RUNTIME_DIR="${lg_xdg}" \
   PATH="${probe_path}" "${subject}" >/dev/null 2>&1 || true
lg_cached="no"
if [ -e "${lg_xdg}/detect-software-rendering.software" ]; then
   lg_cached="yes"
fi
check "LIBGL_ALWAYS_SOFTWARE set -> cache not written" "${lg_cached}" "no"

## The no-GPU-node short-circuit must NOT write a cache marker either -- it would
## go stale if a GPU node appears later this boot (NVIDIA on-demand nodes, hot-add).
sc_xdg="${test_dir}/sc-xdg"
mkdir --parents -- "${sc_xdg}"
LIBGL_ALWAYS_SOFTWARE='' DETECT_SOFTWARE_RENDERING_DRI_DIR="${no_dri}" \
   DETECT_SOFTWARE_RENDERING_NVIDIA_CTL="${nvidia_absent}" XDG_RUNTIME_DIR="${sc_xdg}" \
   PATH="${probe_path}" "${subject}" >/dev/null 2>&1 || true
sc_cached="no"
if [ -e "${sc_xdg}/detect-software-rendering.software" ]; then
   sc_cached="yes"
fi
check "no-GPU-node short-circuit -> cache not written" "${sc_cached}" "no"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
