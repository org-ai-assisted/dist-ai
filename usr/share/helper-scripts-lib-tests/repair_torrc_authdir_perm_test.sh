#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## repair-torrc: the client-onion-auth dir is created WITHOUT widening its
## parents, via the source-able repair_torrc_create_authdir().
##
## The bug: a bare 'install -d -m 0700 -- <authdir>' force-creates any MISSING
## parent (e.g. /var/lib/tor) at 0755 -- 'install -d' ignores umask AND -m for
## ancestors -- so under a restrictive (hardened) umask the parent went
## world-readable. Perm fix: helper-scripts 82fa53e9 (create ancestors with
## umask-honored 'mkdir --parents' first, then 'install -d -m 0700' the authdir
## itself atomically). Made unit-testable at 37c2d31a (authdir-create extracted
## to repair_torrc_create_authdir + a was_executed source guard); THIS oracle
## drives that function, so it requires 37c2d31a or later -- it cannot run at
## 82fa53e9, where the function does not exist yet.
##
## Canary: under umask 0077 drive the REAL repair_torrc_create_authdir() on an
## authdir whose parents are ALL absent, and assert each created ancestor is
## 0700 (NOT 0755) and the authdir is 0700 -- would FAIL on the parent-widening
## (0755) bug. A pre-existing parent is seeded at a DISTINCT 0750 and asserted
## UNCHANGED, so a subject that force-chmods parents is caught. Also asserts
## source-ability: no auto-run, no strict-mode leak (errexit AND nounset), and
## that a broken library source aborts BEFORE main (no filesystem side effects).
## Drives the real script; a missing dependency is a HARD FAIL, never a skip.

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

## Permission bits of a DIRECTORY, else a marker.
## - stat prints a leading special-bits digit (setgid/setuid/sticky) only when
##   one is set, so the last three digits are the rwx bits. A setgid bit
##   inherited from an ancestor of the mktemp tree is an environment artifact,
##   not a widening of the bits this canary guards -- drop it.
## - Requires a directory: a subject creating a regular file at 0700 (e.g.
##   'install -m 0700' without -d) must not read as a correct authdir.
mode_of() {
   local octal
   if [ -d "${1}" ]; then
      octal="$(stat -c '%a' -- "${1}")"
      printf '%s' "${octal: -3}"
   elif [ -e "${1}" ]; then
      printf '%s' NOTADIR
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
## Seed the parent at a DISTINCT, group-accessible 0750 (NOT the 0700 target):
## the authdir is created at 0700 and the parent mode is left EXACTLY 0750. A
## subject that force-chmods every parent to 0700 (removing group access) is
## caught -- seeding at the 0700 target could not tell preservation from a reset.
existing_parent="${test_dir}/existing"
install -d -m 0750 -- "${existing_parent}"
authdir2="${existing_parent}/authdir"
( umask 0077; "${probe}" create "${authdir2}" )
check "authdir under existing parent at 0700" "$(mode_of "${authdir2}")"       "700"
check "existing parent mode untouched (0750)" "$(mode_of "${existing_parent}")" "750"

## --- (3) source-ability: no auto-run, no strict-mode leak, fn defined ---
## The sentinel is reached ONLY if sourcing neither leaked strict-mode (which
## would abort the probe at its 'false') nor auto-ran a main that 'exit's. An
## empty / non-sentinel stdout therefore fails loud instead of passing vacuously.
src_rc=0
src_out="$("${probe}" source 2>/dev/null)" || src_rc=$?
check "sourcing does not enable errexit (no strict leak)"  "${src_rc}"  "0"
check "sourcing does not auto-run repair-torrc"            "${src_out}" "PROBE_SOURCE_END"

## --- (4) a broken library source aborts BEFORE main (no side effects) ---
## repair-torrc sources strings.bsh at the TOP LEVEL; its '#!/bin/bash -e'
## shebang gives the top level errexit so a FAILED source aborts before main()
## runs any filesystem action. Point HELPER_SCRIPTS_PATH at a fixture that
## resolves check_runtime.bsh (SYMLINKED -- was_executed must be defined so the
## first guard passes) but has NO strings.bsh, EXECUTE the real subject, and
## assert it exits non-zero WITHOUT reaching main (main's 'set -x' START trace
## absent). A subject whose top level lacks errexit falls through to main
## instead -- the pre-fix bug; the R-010 gate is the commit-time guard, this is
## its runtime companion. Host-safe: the test runner is unprivileged, so even a
## regressed subject's root-only /etc,/var writes fail harmlessly.
broken_root="${test_dir}/broken"
broken_libdir="${broken_root}/usr/libexec/helper-scripts"
mkdir --parents -- "${broken_libdir}"
ln --symbolic -- "${libdir}/check_runtime.bsh" "${broken_libdir}/check_runtime.bsh"
broken_rc=0
broken_out="$(HELPER_SCRIPTS_PATH="${broken_root}" "${subject}" 2>&1)" || broken_rc=$?
if grep --quiet -- START <<< "${broken_out}" ; then
   reached_main=yes
else
   reached_main=no
fi
if [ "${broken_rc}" -ne 0 ]; then
   abort_state=aborted
else
   abort_state=ran0
fi
check "broken library source aborts (non-zero exit)" "${abort_state}" "aborted"
check "broken library source aborts BEFORE main (no START trace)" \
   "${reached_main}" "no"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
