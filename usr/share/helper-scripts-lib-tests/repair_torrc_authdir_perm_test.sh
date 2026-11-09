#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## repair-torrc: the client-onion-auth dir is created WITHOUT widening its
## parents. Regression guard for helper-scripts 82fa53e9.
##
## The bug: a bare 'install -d -m 0700 -- <authdir>' force-creates any MISSING
## parent (e.g. /var/lib/tor) at 0755 -- 'install -d' ignores umask AND -m for
## ancestors -- so under a restrictive (hardened) umask the parent went
## world-readable. The fix creates ancestors with umask-honored 'mkdir
## --parents' first, then 'install -d -m 0700' the authdir itself atomically.
##
## Canary: under umask 0077 drive the REAL repair_torrc_create_authdir() on an
## authdir whose parents are ALL absent, and assert the immediate parent dir is
## 0700 (NOT 0755) and the authdir is 0700. FAILS on the pre-82fa53e9 code
## (parent 0755), PASSES after. Also asserts source-ability (no auto-run, no
## strict-mode leak). Drives the real script; a missing dependency is a HARD
## FAIL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${tool_dir}/repair_torrc_authdir_perm_probe.sh"

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/repair-torrc"
   libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
else
   subject='/usr/libexec/helper-scripts/repair-torrc'
   libdir='/usr/libexec/helper-scripts'
fi

## The SUBJECT (helper-scripts repair-torrc + the libs it sources) is a REQUIRED
## dependency: absent it means helper-scripts is not installed or
## HELPER_SCRIPTS_REPO is not set, an environment bug -> exit 1 (FATAL), never a
## skip (R-220). The test's OWN probe missing is likewise a FAIL.
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -r "${libdir}/check_runtime.bsh" ] || [ ! -r "${libdir}/strings.bsh" ]; then
   printf '%s\n' "FATAL: helper-scripts libs not readable under '${libdir}'" >&2
   exit 1
fi
if [ ! -x "${probe}" ]; then
   printf '%s\n' "FATAL: test support probe missing at '${probe}'" >&2
   exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${libdir}/has.bsh"

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## The probe sources repair-torrc, which resolves its own libs via
## HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
export SUBJECT="${subject}"

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

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

## Octal mode of a path, or 'MISSING' when it does not exist.
mode_of() {
   if [ -e "${1}" ]; then
      stat -c '%a' -- "${1}"
   else
      printf '%s' MISSING
   fi
}

## --- (1) the perm canary: restrictive umask, ALL parents absent ---
## The authdir sits several levels below an absent root so 'install -d' would
## have to force-create every ancestor (the exact bug surface). The umask is
## scoped to the subshell driving the probe.
authdir="${test_dir}/root/var/lib/tor/authdir"
parent_dir="${authdir%/*}"
( umask 0077; "${probe}" create "${authdir}" )

check "authdir created at 0700"              "$(mode_of "${authdir}")"    "700"
check "immediate parent at 0700 (not 0755)"  "$(mode_of "${parent_dir}")" "700"
check "mid ancestor at 0700 (not 0755)"      "$(mode_of "${test_dir}/root/var")" "700"

## --- (2) a pre-existing parent is not disturbed; authdir still 0700 ---
## Parent present at a tighter 0700 already (the hardened steady state): the
## authdir is created at 0700 and the parent mode is left untouched.
existing_parent="${test_dir}/existing"
install -d -m 0700 -- "${existing_parent}"
authdir2="${existing_parent}/authdir"
( umask 0077; "${probe}" create "${authdir2}" )
check "authdir under existing parent at 0700" "$(mode_of "${authdir2}")"       "700"
check "existing parent mode untouched (0700)" "$(mode_of "${existing_parent}")" "700"

## --- (3) source-ability: no auto-run, no strict-mode leak, fn defined ---
src_rc=0
src_out="$("${probe}" source 2>/dev/null)" || src_rc=$?
check "sourcing does not enable errexit (no strict leak)" "${src_rc}" "0"
check "sourcing does not auto-run repair-torrc"            "${src_out}" ""

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
