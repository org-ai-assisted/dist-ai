#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for the anon-apt-sources-list preinst function
## debian_sources_backup_unowned. It moves an unowned trixie
## /etc/apt/sources.list.d/debian.sources aside before unpack so dpkg installs
## this package's conffile without the (noninteractive-fatal) conffile prompt.
##
## Bugs guarded (all live, ai-review-found):
##   #1 FAIL-OPEN ownership check. '! dpkg-query -S FILE' took the mv branch on
##      EVERY nonzero rc, not only rc 1 (owned by no package). A fatal dpkg-query
##      (rc 2: corrupt admindir) then SEIZED an owned conffile. Fix: move on rc 1.
##   #2 NON-IDEMPOTENT do-once marker. Written unconditionally, so a run that did
##      NOT move the file still blocked the retry that could. Fix: mark only once
##      no copy remains where apt would read it.
##   #3 --no-clobber WEDGE. A pre-existing backup made 'mv --no-clobber' a no-op
##      forever, so the file was never migrated and the fatal prompt recurred.
##      Fix: 'mv --backup=numbered' migrates and preserves any prior backup.
##   #4 SYMLINK treated as absent. '[ -e ]' follows links, so a dangling symlink
##      was marked done without migrating. Fix: treat a symlink as present.
##
## BEHAVIORAL: drives the REAL preinst end-to-end, CONTAINED under bwrap with the
## per-case temp dirs bound over the host paths it writes (/etc/apt/sources.list.d
## and /var/lib), so its hardcoded writes land in the temp tree and can never
## touch the host -- no production test seam. dpkg-query is stubbed on PATH.
## DPKG_MAINTSCRIPT_* are unset (as apt leaves them) so an unguarded nounset
## reference would surface. Every run's exit status is asserted 0 -- a maintscript
## crash is a test failure. Assertions check CONTENT, not mere existence, so an
## in-place wipe cannot masquerade as "not seized".
##
## Targets a checkout via ANON_APT_SOURCES_LIST_REPO; a maintscript has no
## installed runtime path, so without it the subject cannot be resolved -> SKIP.
## No root (bwrap supplies containment), no network.

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

## Per-case temp tree. case_etc / case_var are bound over the maintscript's real
## host paths; the *_file/backup/marker paths are where its writes land in the
## temp tree (so assertions read them back after the contained run).
setup_case() {
   case_root="${test_root}/$1"
   case_etc="${case_root}/etc-apt-sld"
   case_var="${case_root}/var-lib"
   sources_file="${case_etc}/debian.sources"
   backup_file="${sources_file}.pre-anon-apt-sources-list.bak"
   do_once_dir="${case_var}/anon-apt-sources-list/do_once"
   marker="${do_once_dir}/debian_sources_backup_unowned_version_1"
   mkdir --parents -- "${case_etc}" "${case_var}"
}

## Run the REAL preinst once with dpkg-query stubbed to exit $1, contained under
## bwrap: the per-case temp dirs are bound OVER the host paths the maintscript
## writes, so its writes cannot escape the temp tree. Returns the preinst's own
## exit code (a crash is itself a failure).
run_preinst() {
   local dpkg_rc="$1" rc=0
   stub_cmd dpkg-query "${dpkg_rc}"
   bwrap --dev-bind / / \
      --bind "${case_etc}" /etc/apt/sources.list.d \
      --bind "${case_var}" /var/lib \
      -- env -u DPKG_MAINTSCRIPT_PACKAGE -u DPKG_MAINTSCRIPT_NAME \
         bash "${preinst}" install >/dev/null 2>&1 || rc=$?
   return "${rc}"
}

## ---- Test #1: fail-open ownership check -----------------------------------
## dpkg-query rc 2 (fatal: corrupt admindir). Ownership is UNKNOWN, so the file
## must NOT be seized. Pre-fix: '! dpkg-query' true -> mv ran -> file moved.
setup_case fail_open
printf '%s\n' "${sentinel}" > "${sources_file}"
prc=0
run_preinst 2 || prc=$?
check "#1 preinst exited 0 on dpkg-query rc 2" "${prc}" -eq 0
if stub_called_with dpkg-query -S /etc/apt/sources.list.d/debian.sources; then
   ok "#1 preinst consulted dpkg-query (assertion is not vacuous)"
else
   notok "#1 preinst never called 'dpkg-query -S /etc/apt/sources.list.d/debian.sources'"
fi
check_content "#1 unknown-ownership file left intact (not seized/wiped)" "${sources_file}" "${sentinel}"
check "#1 no backup created for an unknown-ownership file" ! -e "${backup_file}"
check "#1 marker NOT written (retry stays possible)" ! -e "${marker}"

## ---- Test #2: non-idempotent do-once marker -------------------------------
## Run 1 rc 0 (owned) -> never seize, marker unset. Run 2 rc 1 (owner purged, now
## unowned) -> the file must STILL be migrated. Pre-fix: run 1 wrote the marker
## unconditionally, so run 2 early-returned and never moved the now-unowned file.
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

## ---- Test #4: pre-existing backup must not wedge the migration -------------
## A stale backup already sits at the .bak path. Pre-fix ('mv --no-clobber') this
## no-ops forever: the file is never migrated and the marker never set. Fix
## ('mv --backup=numbered') migrates the file AND preserves the old backup.
setup_case stale_backup
printf '%s\n' "${sentinel}" > "${sources_file}"
printf '%s\n' 'STALE-prior-backup' > "${backup_file}"
prc=0
run_preinst 1 || prc=$?
check "#4 preinst exited 0 (stale backup present)" "${prc}" -eq 0
check "#4 unowned file migrated despite a stale backup (no-clobber wedge)" ! -e "${sources_file}"
check_content "#4 new backup holds the migrated bytes" "${backup_file}" "${sentinel}"
if compgen -G "${backup_file}.~[0-9]*~" >/dev/null; then
   ok "#4 prior backup preserved as a numbered backup (no data loss)"
else
   notok "#4 prior backup was clobbered (no numbered backup found)"
fi
check "#4 marker recorded after migration" -e "${marker}"

## ---- Test #5: a dangling symlink must be migrated, not marked-done ---------
## '[ -e ]' follows links, so a dangling symlink reads as absent. Pre-fix the
## marker was written without migrating; dpkg then follows the link on unpack.
## Fix treats a symlink (incl. dangling) as present and moves it aside.
setup_case dangling_symlink
ln --symbolic -- /nonexistent/debian.sources.target "${sources_file}"
prc=0
run_preinst 1 || prc=$?
check "#5 preinst exited 0 (dangling symlink)" "${prc}" -eq 0
check "#5 nothing remains at the sources path" ! -e "${sources_file}"
check "#5 no symlink remains at the sources path" ! -L "${sources_file}"
check "#5 symlink moved to the backup path" -L "${backup_file}"
check "#5 marker recorded after migrating the symlink" -e "${marker}"

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
