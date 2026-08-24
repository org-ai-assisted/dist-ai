#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## detect-software-rendering: short-circuits, source-ability and classification.
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
##
## Drives the REAL script. A missing dependency is a HARD FAIL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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

## The SUBJECT (helper-scripts detect-software-rendering + its libs) is a REQUIRED
## dependency: absent it means helper-scripts is not installed or HELPER_SCRIPTS_REPO
## is not set, an environment bug -> exit 1 (FATAL), never a skip (R-220). Matches the
## sibling lanes (has_builtin, read_integer_file). The test's OWN support scripts
## missing (below) is likewise a FAIL -- a broken test install.
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

## LIBGL_ALWAYS_SOFTWARE is a deliberate user/admin directive: honored
## unconditionally (software), even with an NVIDIA node present, and WITHOUT
## probing eglinfo. Reports the requested intent, not a driver guess.
safe-rm -f -- "${count_file}"
libgl_nv_rc=0
libgl_nv_out="$(LIBGL_ALWAYS_SOFTWARE=1 DETECT_SOFTWARE_RENDERING_DRI_DIR="${no_dri}" \
   DETECT_SOFTWARE_RENDERING_NVIDIA_CTL="${nvidia_present}" \
   EGLINFO_STUB_RENDERER='OpenGL core profile renderer: NVIDIA GeForce RTX 4090' \
   EGLINFO_STUB_COUNT="${count_file}" \
   XDG_RUNTIME_DIR="${no_cache_dir}" PATH="${probe_path}" "${subject}")" || libgl_nv_rc=$?
check "LIBGL_ALWAYS_SOFTWARE=1 + NVIDIA node -> software/0 (directive honored)" \
   "${libgl_nv_out}:${libgl_nv_rc}" "software:0"
check "LIBGL directive honored without probing eglinfo (NVIDIA node present)" \
   "$(count_of "${count_file}")" "0"

## The 'yes' spelling is truthy too (Mesa treats it so). With no NVIDIA node it
## short-circuits to software without probing, even though eglinfo would report a
## vendor. (Old code accepted only '1'/'true', so 'yes' probed -> accelerated.)
check "LIBGL_ALWAYS_SOFTWARE=yes (no NVIDIA) -> software/0 without probing" \
   "$(run_subject 'OpenGL core profile renderer: NVIDIA GeForce' yes "${with_dri}" '')" "software:0"
## Case-insensitive: uppercase spellings are lowercased before the compare.
check "LIBGL_ALWAYS_SOFTWARE=TRUE (uppercase, no NVIDIA) -> software/0" \
   "$(run_subject 'OpenGL core profile renderer: NVIDIA GeForce' TRUE "${with_dri}" '')" "software:0"

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

## REGRESSION (classification): a software renderer whose name embeds a hardware
## vendor token must NOT be reported as accelerated. Software markers are matched
## BEFORE the vendor list, and vendor matching is whole-word. (Old code reported
## all three as accelerated: 'Apple'/'D3D12' substrings, and 'ATI' inside 'NATIVE'.)
check "Apple Software Renderer -> software/0" \
   "$(run_subject 'OpenGL core profile renderer: Apple Software Renderer' '' "${with_dri}" '')" "software:0"
check "WARP D3D12 Basic Render Driver -> software/0" \
   "$(run_subject 'OpenGL core profile renderer: D3D12 (Microsoft Basic Render Driver)' '' "${with_dri}" '')" "software:0"
check "ATI substring in NATIVE not matched -> software/0" \
   "$(run_subject 'OpenGL core profile renderer: NATIVE software rasterizer' '' "${with_dri}" '')" "software:0"
## Real hardware whose name contains the same tokens still classifies as accelerated.
check "real ATI Radeon -> accelerated/1" \
   "$(run_subject 'OpenGL core profile renderer: ATI Radeon HD 5770' '' "${with_dri}" '')" "accelerated:1"
check "real Apple M1 -> accelerated/1" \
   "$(run_subject 'OpenGL core profile renderer: Apple M1' '' "${with_dri}" '')" "accelerated:1"

## REGRESSION (multi-platform): 'eglinfo -B' prints a renderer line per EGL
## platform. A platform that falls back to llvmpipe must NOT mask another platform
## reporting the real GPU -- hardware wins across lines. All-software multi-line
## stays software.
mixed_renderer=$'OpenGL core profile renderer: llvmpipe (LLVM 15.0.7)\nOpenGL core profile renderer: NVIDIA GeForce RTX 4090'
check "mixed llvmpipe + NVIDIA lines -> accelerated/1 (hardware wins)" \
   "$(run_subject "${mixed_renderer}" '' "${with_dri}" '')" "accelerated:1"
multi_software=$'OpenGL core profile renderer: llvmpipe (LLVM 15.0.7)\nOpenGL core profile renderer: softpipe'
check "multiple software-only lines -> software/0" \
   "$(run_subject "${multi_software}" '' "${with_dri}" '')" "software:0"

## eglinfo NOT installed (GPU node present, no eglinfo on PATH) -> unknown/2.
## PATH is an empty dir: probe_renderer reaches the 'has eglinfo' check using only
## shell builtins, so no other tool is needed before that early return.
empty_bin="${test_dir}/empty-bin"
mkdir --parents -- "${empty_bin}"
ea_rc=0
ea_out="$(LIBGL_ALWAYS_SOFTWARE='' DETECT_SOFTWARE_RENDERING_DRI_DIR="${with_dri}" \
   DETECT_SOFTWARE_RENDERING_NVIDIA_CTL="${nvidia_absent}" \
   PATH="${empty_bin}" "${subject}")" || ea_rc=$?
check "eglinfo absent (node present) -> unknown/2" "${ea_out}:${ea_rc}" "unknown:2"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
