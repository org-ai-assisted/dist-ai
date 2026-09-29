#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the anon-apt-sources-list preinst function
## debian_sources_backup_unowned. It moves an unowned trixie
## /etc/apt/sources.list.d/debian.sources aside before unpack so dpkg installs
## this package's conffile without the (noninteractive-fatal) conffile prompt.
##
## Two bugs guarded (both were live, grok-found):
##   #1 FAIL-OPEN ownership check. The old guard '! dpkg-query -S FILE' took the
##      mv branch on EVERY nonzero rc, not only rc 1 (path owned by no package).
##      A fatal dpkg-query (rc 2: corrupt admindir / DB error) then SEIZED a
##      package-OWNED conffile, dropping the admin's local changes. The fix moves
##      ONLY on rc 1.
##   #2 NON-IDEMPOTENT do-once marker. The marker was touched unconditionally,
##      even when the file was NOT moved aside, so a later retry hit the early
##      'return 0' and the conffile prompt this function exists to avoid still
##      fired. The fix records the marker ONLY once no copy of debian.sources
##      remains where apt would read it, so a partial/failed run can be retried.
##
## BEHAVIORAL: drives the REAL preinst end-to-end with dpkg-query stubbed on PATH
## and the /etc + /var/lib bases redirected under a temp root (the preinst's
## overridable ${debian_sources_file}/${do_once_dir} bases, unset in production).
## Asserts filesystem effects (existence AND content, so an in-place wipe cannot
## masquerade as "not seized"), not source text. DPKG_MAINTSCRIPT_* are unset (as
## apt leaves them) so an unguarded nounset reference would surface. Every run's
## exit status is asserted 0 -- a maintscript crash is a test failure.
##
## Targets a checkout via ANON_APT_SOURCES_LIST_REPO; a maintscript has no
## installed runtime path, so without it the subject cannot be resolved -> SKIP.
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v ANON_APT_SOURCES_LIST_REPO ] || ANON_APT_SOURCES_LIST_REPO=""

if [ -z "${ANON_APT_SOURCES_LIST_REPO}" ]; then
   printf '%s\n' "SKIP: set ANON_APT_SOURCES_LIST_REPO to an anon-apt-sources-list checkout" >&2
   exit 77  ## style-ok: allow-skip: optional target absent (no checkout wired for this run)
fi

preinst="${ANON_APT_SOURCES_LIST_REPO}/debian/anon-apt-sources-list.preinst"

if [ ! -f "${preinst}" ]; then
   ## A gitlink submodule that was not checked out leaves the dir without a
   ## debian/ tree. Skip (the runner counts an unauthorized skip as a failure),
   ## rather than a false green against a subject that is not there.
   printf '%s\n' "SKIP: preinst not found at '${preinst}' (submodule not checked out?)" >&2
   exit 77  ## style-ok: allow-skip: optional target absent (submodule not checked out)
fi

## SAFETY: this test drives the REAL maintscript, which writes under
## /etc/apt/sources.list.d and /var/lib/anon-apt-sources-list. It is safe ONLY
## because the maintscript reads those two paths from overridable bases that we
## redirect into a temp root. A maintscript WITHOUT that seam (e.g. an older
## pinned revision) would ignore the overrides and touch the real host paths --
## refuse to run it. This is a containment precondition, not an assertion, so a
## source check is the right tool; the behavioral assertions below never trust it.
if ! grep --quiet 'debian_sources_file:-' "${preinst}" \
   || ! grep --quiet 'do_once_dir:-' "${preinst}"; then
   printf '%s\n' "SKIP: preinst lacks the path-override seam; refusing to run it against real host paths" >&2
   exit 77  ## style-ok: allow-skip: optional target lacks the test seam (would touch host)
fi

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
harness="${tool_dir}/../dist-ai-tests-common/stub-path-harness.bash"
if [ ! -r "${harness}" ]; then
   printf '%s\n' "FATAL: stub-path harness not found at '${harness}'" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/stub-path-harness.bash
source "${harness}"

test_root="$(mktemp --directory -- "${TMP}/anon-apt-sources-list-test.XXXXXX")"

test_cleanup_handler() {
   ## '|| true': a cleanup failure (e.g. a restrictive mode left in the temp
   ## tree) must never override the real pass/fail exit status.
   stub_path_cleanup
   safe-rm --recursive --force -- "${test_root}" || true
}
trap test_cleanup_handler EXIT

stub_path_init

## Distinctive on-disk content so a check proves the ORIGINAL bytes survived, not
## merely that some file exists (an in-place truncate leaves an empty file that -e
## would still accept).
sentinel='ORIG-debian-sources-content-9f3a2b'

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## check "<label>" <test-expr...>  -- e.g. check "msg" -e "${f}" / check "msg" ! -e "${f}"
## Uses if/test (not '&& ok || notok') so a failing assertion never double-counts.
check() {
   local label="$1"
   shift
   if test "$@"; then
      ok "${label}"
   else
      notok "${label}"
   fi
}

## check_content "<label>" <path> <want>  -- the file exists AND its bytes equal
## <want>. Guards the in-place-wipe / empty-backup false pass an -e check misses.
check_content() {
   local label="$1" path="$2" want="$3"
   if [ -e "${path}" ] && [ "$(cat -- "${path}")" = "${want}" ]; then
      ok "${label}"
   else
      notok "${label}"
   fi
}

## Per-case temp tree + the paths the preinst will touch, redirected under it.
setup_case() {
   case_root="${test_root}/$1"
   sources_dir="${case_root}/etc/apt/sources.list.d"
   sources_file="${sources_dir}/debian.sources"
   backup_file="${sources_file}.pre-anon-apt-sources-list.bak"
   do_once_dir="${case_root}/var/lib/anon-apt-sources-list/do_once"
   marker="${do_once_dir}/debian_sources_backup_unowned_version_1"
   mkdir --parents -- "${sources_dir}"
}

## Run the REAL preinst once with dpkg-query stubbed to exit $1. Returns the
## preinst's own exit code (a crash is itself a failure).
run_preinst() {
   local dpkg_rc="$1" rc=0
   stub_cmd dpkg-query "${dpkg_rc}"
   env -u DPKG_MAINTSCRIPT_PACKAGE -u DPKG_MAINTSCRIPT_NAME \
      debian_sources_file="${sources_file}" \
      do_once_dir="${do_once_dir}" \
      bash "${preinst}" install >/dev/null 2>&1 || rc=$?
   return "${rc}"
}

## ---- Test #1: fail-open ownership check -----------------------------------
## dpkg-query rc 2 (fatal: corrupt admindir). The file's ownership is UNKNOWN,
## so it must NOT be seized. Pre-fix: '! dpkg-query' was true -> mv ran -> file
## moved. Post-fix: no move, no marker (a retry after DB repair can finish).
setup_case fail_open
printf '%s\n' "${sentinel}" > "${sources_file}"
prc=0
run_preinst 2 || prc=$?
check "#1 preinst exited 0 on dpkg-query rc 2" "${prc}" -eq 0
if stub_called_with dpkg-query -S "${sources_file}"; then
   ok "#1 preinst consulted dpkg-query (assertion is not vacuous)"
else
   notok "#1 preinst never called 'dpkg-query -S ${sources_file}'"
fi
check_content "#1 unknown-ownership file left intact (not seized/wiped)" "${sources_file}" "${sentinel}"
check "#1 no backup created for an unknown-ownership file" ! -e "${backup_file}"
check "#1 marker NOT written (retry stays possible)" ! -e "${marker}"

## ---- Test #2: non-idempotent do-once marker -------------------------------
## Run 1: dpkg-query rc 0 (owned) -> never seize, and (post-fix) leave the marker
## unset. Run 2: the owner is purged so the path is now unowned (rc 1) -> the
## file must STILL be migrated. Pre-fix: run 1 wrote the marker unconditionally,
## so run 2 early-returned and never moved the now-unowned file.
setup_case retry
printf '%s\n' "${sentinel}" > "${sources_file}"

prc=0
run_preinst 0 || prc=$?
check "#2 run1 preinst exited 0 (owned)" "${prc}" -eq 0
check_content "#2 run1 owned file left intact (not moved/wiped)" "${sources_file}" "${sentinel}"
check "#2 run1 owned: marker NOT written (blocks retry otherwise)" ! -e "${marker}"

prc=0
run_preinst 1 || prc=$?
check "#2 retry preinst exited 0 (now unowned)" "${prc}" -eq 0
check "#2 retry moved the now-unowned file aside (early-skip bug)" ! -e "${sources_file}"
check_content "#2 retry backup holds the original bytes" "${backup_file}" "${sentinel}"
check "#2 retry recorded the marker" -e "${marker}"

## ---- Test #3: happy path + absent file (marker-predicate branches) ---------
## Unowned present (rc 1) on a first run -> migrate + mark. Absent file -> nothing
## to migrate, still mark (so it is not rechecked forever). Both assert exit 0.
setup_case happy_unowned
printf '%s\n' "${sentinel}" > "${sources_file}"
prc=0
run_preinst 1 || prc=$?
check "#3 happy preinst exited 0" "${prc}" -eq 0
check "#3 unowned file migrated" ! -e "${sources_file}"
check_content "#3 backup holds the original bytes" "${backup_file}" "${sentinel}"
check "#3 marker recorded after migration" -e "${marker}"

setup_case absent
prc=0
run_preinst 1 || prc=$?
check "#3 absent preinst exited 0" "${prc}" -eq 0
check "#3 absent file: nothing moved" ! -e "${sources_file}"
check "#3 absent file: no backup created" ! -e "${backup_file}"
check "#3 absent file: marker recorded" -e "${marker}"

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
