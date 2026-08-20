#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## detect-software-rendering: source-ability and classification.
##  (1) Sourcing the script does NOT auto-run and does NOT leak strict-mode into
##      the sourcing shell; detect_software_rendering() and main() are defined;
##      calling detect_software_rendering() directly does not enable errexit in
##      the caller -- the function is pure, main() owns strict-mode. A fresh
##      'bash -c' starts with errexit OFF (SHELLOPTS is not exported), so a
##      leak would abort a following 'false' and the child would exit non-zero.
##  (2) With a stub 'eglinfo', an executed run classifies the renderer: a vendor
##      string -> accelerated (exit 1), llvmpipe -> software (exit 0), an
##      unrecognized or empty renderer -> unknown (exit 2).
##
## Drives the REAL script. A missing dependency is a HARD FAIL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

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

## The script resolves its own libs via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

## A stub 'eglinfo' (fast + deterministic; the real one can hang for the
## timeout). It prints whatever 'set_eglinfo' last wrote to eglinfo.out and
## ignores its arguments.
stub_dir="${test_dir}/bin"
mkdir --parents -- "${stub_dir}"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "cat -- '${stub_dir}/eglinfo.out' 2>/dev/null || true"
} >"${stub_dir}/eglinfo"
chmod 0755 -- "${stub_dir}/eglinfo"
set_eglinfo() {
   printf '%s\n' "$1" >"${stub_dir}/eglinfo.out"
}

## The subject sources check_runtime.bsh and has.sh (from HELPER_SCRIPTS_PATH,
## exported above) and finds the stub eglinfo via this PATH.
probe_path="${stub_dir}:${PATH}"

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

## --- (1) source-ability / no strict-mode leak ---
set_eglinfo "OpenGL core profile renderer: llvmpipe (LLVM)"

auto="$(SUBJECT="${subject}" PATH="${probe_path}" bash -c 'source "${SUBJECT}"')" || true
check "sourcing does not auto-run" "${auto}" ""

fn="$(SUBJECT="${subject}" PATH="${probe_path}" bash -c 'source "${SUBJECT}"; type -t detect_software_rendering')" || true
check "detect_software_rendering is defined" "${fn}" "function"

mn="$(SUBJECT="${subject}" PATH="${probe_path}" bash -c 'source "${SUBJECT}"; type -t main')" || true
check "main is defined" "${mn}" "function"

## Behavioural leak probe via the child EXIT CODE: with errexit OFF, 'false; true'
## exits 0; if sourcing (or the call below) enabled errexit, 'false' aborts the
## child and it exits non-zero.
src_leak_rc=0
SUBJECT="${subject}" PATH="${probe_path}" bash -c 'source "${SUBJECT}"; false; true' 2>/dev/null || src_leak_rc=$?
check "sourcing does not enable errexit" "${src_leak_rc}" "0"

call_leak_rc=0
SUBJECT="${subject}" PATH="${probe_path}" bash -c 'source "${SUBJECT}"; detect_software_rendering >/dev/null 2>&1 || true; false; true' 2>/dev/null || call_leak_rc=$?
check "calling detect_software_rendering does not enable errexit" "${call_leak_rc}" "0"

## --- (2) classification (executed) ---
classify() {
   local line out rc

   line="$1"
   set_eglinfo "${line}"
   rc=0
   out="$(PATH="${probe_path}" "${subject}")" || rc=$?
   printf '%s\n' "${out}:${rc}"
}
check "vendor -> accelerated/1"   "$(classify 'OpenGL core profile renderer: NVIDIA GeForce')" "accelerated:1"
check "llvmpipe -> software/0"    "$(classify 'OpenGL core profile renderer: llvmpipe (LLVM)')" "software:0"
check "unrecognized -> unknown/2" "$(classify 'some unrelated line')" "unknown:2"
check "empty output -> unknown/2" "$(classify '')" "unknown:2"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
