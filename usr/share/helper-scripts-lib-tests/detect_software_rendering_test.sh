#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## detect-software-rendering: source-ability, classification and per-boot cache.
##  (1) Sourcing the script does NOT auto-run and does NOT leak strict-mode into
##      the sourcing shell, and the reusable detect_software_rendering() is pure
##      (calling it does not enable errexit) and defined. Probed by the committed
##      non-strict helper detect_software_rendering_source_probe.sh via its exit
##      code and stdout -- no inline shell program here.
##  (2) With the committed mock eglinfo (detect_software_rendering_eglinfo_stub.sh)
##      an executed run classifies the renderer: a vendor string -> accelerated
##      (exit 1), llvmpipe -> software (exit 0), unrecognized or empty -> unknown
##      (exit 2).
##  (3) The per-boot cache means the probe runs at most once across two shells.
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

## The subject resolves its own libs via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

llvmpipe_line='OpenGL core profile renderer: llvmpipe (LLVM)'

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

## --- (1) source-ability: no auto-run, no strict leak, pure + defined ---
src_out=""
src_rc=0
src_out="$(SUBJECT="${subject}" PATH="${probe_path}" "${probe}" source 2>/dev/null)" || src_rc=$?
check "sourcing does not enable errexit" "${src_rc}" "0"
check "sourcing does not auto-run" "${src_out}" ""

call_rc=0
SUBJECT="${subject}" PATH="${probe_path}" "${probe}" call >/dev/null 2>&1 || call_rc=$?
check "calling detect_software_rendering stays pure and defined" "${call_rc}" "0"

## --- (2) classification (executed; XDG_RUNTIME_DIR='' disables the cache) ---
classify() {
   local line out rc

   line="$1"
   rc=0
   out="$(EGLINFO_STUB_RENDERER="${line}" XDG_RUNTIME_DIR='' PATH="${probe_path}" "${subject}")" || rc=$?
   printf '%s\n' "${out}:${rc}"
}
check "vendor -> accelerated/1"   "$(classify 'OpenGL core profile renderer: NVIDIA GeForce')" "accelerated:1"
check "llvmpipe -> software/0"    "$(classify "${llvmpipe_line}")" "software:0"
check "unrecognized -> unknown/2" "$(classify 'some unrelated line')" "unknown:2"
check "empty output -> unknown/2" "$(classify '')" "unknown:2"

## --- (3) per-boot cache: the probe runs at most once across two shells ---
count_file="${test_dir}/eglinfo.count"
safe-rm -f -- "${count_file}"
xdg="${test_dir}/xdg"
mkdir --parents -- "${xdg}"
c1="$(EGLINFO_STUB_RENDERER="${llvmpipe_line}" EGLINFO_STUB_COUNT="${count_file}" XDG_RUNTIME_DIR="${xdg}" PATH="${probe_path}" "${subject}")" || true
c2="$(EGLINFO_STUB_RENDERER="${llvmpipe_line}" EGLINFO_STUB_COUNT="${count_file}" XDG_RUNTIME_DIR="${xdg}" PATH="${probe_path}" "${subject}")" || true
eg_count="$(wc -c <"${count_file}" | tr -d ' ')"
check "cache: both calls report software" "${c1}:${c2}" "software:software"
check "cache: eglinfo probed at most once across two shells" "${eg_count}" "1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
