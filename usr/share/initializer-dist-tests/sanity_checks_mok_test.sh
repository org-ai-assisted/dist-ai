#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The inline 'bash -c' programs run in a deliberately separate child shell.
## style-ok: allow-embedded-script
## 3-space indent to match the sibling suites (check_image_builtin_mok_test.sh,
## cleanup_test.sh).
## style-ok: R-003

## initializer-dist chroot-scripts-post.d '20_sanity_checks': source-ability plus
## the built-in-MOK-key gate and its mutual exclusion with the build-clean marker.
##
## Drives the REAL script. It is source-able (was_executed guard, strict-mode
## confined to the guarded block), so this test sources it and calls the MOK
## functions against a tmpdir fixture:
##   - check_no_builtin_mok_and_mark  no key present -> stamp the build-clean
##                                    marker; a key present -> unexpected_key_file.
##   - unexpected_key_file            delete the build-clean marker (a baked key
##                                    means the image is NOT clean), then 'die'.
## The marker basename is the shared contract: this test, the subject and the
## runtime check all read image_builtin_mok_absent_marker_basename from the one
## fragment, so a rename cannot drift.
##
## The path globals the test reassigns (legacy_dist_do_once_dir) and the fragment
## variable are CONSUMED inside the sourced subject, across a boundary shellcheck
## does not follow -- so its unused-variable warnings are false here.
# shellcheck disable=SC2034
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v INITIALIZER_DIST_REPO ] || INITIALIZER_DIST_REPO=""
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${INITIALIZER_DIST_REPO}" ]; then
   subject="${INITIALIZER_DIST_REPO}/usr/libexec/initializer-dist/chroot-scripts-post.d/20_sanity_checks"
else
   subject='/usr/libexec/initializer-dist/chroot-scripts-post.d/20_sanity_checks'
fi
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   real_hs_bindir="${HELPER_SCRIPTS_REPO}/usr/bin"
else
   real_hs_bindir='/usr/bin'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set INITIALIZER_DIST_REPO to an initializer-dist checkout, or install initializer-dist" >&2
   exit 1
fi

## The subject resolves check_runtime.bsh / log_run_die.sh / shim-signed-mok-setup /
## legacy_dist_do_once_markers.bsh via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO:-}"
export PATH="${real_hs_bindir}:${PATH}"

## provides has
# shellcheck disable=SC1090,SC1091
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.bsh
if ! has safe-rm; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Drift-guard: the shared marker basename variable must be present in the subject,
## else the gate drifted -- a hard error, not a silent pass.
if ! grep --quiet --fixed-strings -- 'image_builtin_mok_absent_marker_basename' "${subject}"; then
   printf '%s\n' "FATAL: subject '${subject}' no longer references image_builtin_mok_absent_marker_basename; it drifted." >&2
   exit 1
fi

## ================= source-ability (BEFORE the in-process source) =================
## 20_sanity_checks runs dpkg --configure / dpkg-reconfigure / debsums at file
## scope only via main(). Refuse to source unless the was_executed guard is present,
## so a stale pre-refactor subject cannot run its body here.
if ! grep --quiet -- 'was_executed' "${subject}"; then
   printf '%s\n' "FATAL: subject '${subject}' carries no was_executed guard; refusing to source." >&2
   exit 1
fi

leak_rc=0
HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" bash -c 'source "$1"; false; true' placeholder "${subject}" >/dev/null 2>&1 \
   || leak_rc=$?
## Append a sentinel AFTER the source. A subject that EXITS (even 'exit 0') when
## sourced never reaches it, so a capture missing the sentinel flags a silent exit
## that would otherwise abort the in-process source below with every MOK assertion
## unrun -- a false green. A clean subject prints ONLY the sentinel.
src_out="$(HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" bash -c 'source "$1"; printf %s SRC_RETURNED' placeholder "${subject}" 2>&1)" || true

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

check "sourcing does not leak strict-mode" "${leak_rc}" "0"
check "sourcing returns without auto-run output" "${src_out}" "SRC_RETURNED"
if [ "${leak_rc}" -ne 0 ] || [ "${src_out}" != "SRC_RETURNED" ]; then
   printf '%s\n' "FATAL: subject is not safe to source in-process (see checks above)" >&2
   exit 1
fi

## ================= in-process source =================
# shellcheck disable=SC1090,SC1091
source "${subject}"
for fn in check_no_builtin_mok_and_mark unexpected_key_file; do
   if [ "$(type -t "${fn}")" != 'function' ]; then
      printf '%s\n' "FATAL: sourcing '${subject}' defined no '${fn}' function" >&2
      exit 1
   fi
done
if [ -z "${image_builtin_mok_absent_marker_basename:-}" ]; then
   printf '%s\n' "FATAL: subject did not pull in image_builtin_mok_absent_marker_basename (fragment)" >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" || true; }
trap cleanup EXIT

do_once="${work}/legacy/do_once"
dkms="${work}/var/lib/dkms"
shim_mok="${work}/var/lib/shim-signed/mok"
marker="${do_once}/${image_builtin_mok_absent_marker_basename}"

## Redirect the subject's path globals at the temp tree. dkms_mok_variables_set
## honors the SHIM_SIGNED_MOK_SETUP_DKMS_MOK_DIR prefix -> keys under <prefix>/var/...
legacy_dist_do_once_dir="${do_once}"
export SHIM_SIGNED_MOK_SETUP_DKMS_MOK_DIR="${work}"

exists() {
   if [ -e "$1" ]; then printf '%s' "yes"; else printf '%s' "no"; fi
}
nonzero() {
   if [ "$1" -ne 0 ]; then printf '%s' "yes"; else printf '%s' "no"; fi
}
## Run a function that may 'die' (exit) in a SUBSHELL so it cannot abort the test;
## filesystem effects (the marker rm/touch) persist. Reports only the exit code.
run_dieable() {
   local rc=0
   ( "$@" ) >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}
reset_state() {
   safe-rm --recursive --force -- "${do_once}" "${dkms}" "${shim_mok}"
   mkdir --parents -- "${dkms}" "${shim_mok}"
}

## --- clean image: no key present -> stamp the build-clean marker ------------
reset_state
rc="$(run_dieable check_no_builtin_mok_and_mark)"
check "clean image -> returns 0" "${rc}" "0"
check "clean image -> marker stamped" "$(exists "${marker}")" "yes"

## --- baked key present -> abort AND the clean marker must not survive --------
## Even if a stale marker was already present, a built-in key means the image is
## not clean, so check_no_builtin_mok_and_mark must die and leave NO clean marker.
reset_state
mkdir --parents -- "${do_once}"
touch -- "${marker}"
touch -- "${dkms}/mok.pub"
rc="$(run_dieable check_no_builtin_mok_and_mark)"
check "baked key -> dies (nonzero)" "$(nonzero "${rc}")" "yes"
check "baked key -> clean marker deleted" "$(exists "${marker}")" "no"

## --- unexpected_key_file: deletes the marker, then dies ---------------------
## REGRESSION CANARY: before the fix, unexpected_key_file only die()d and left a
## stale clean marker in place.
reset_state
mkdir --parents -- "${do_once}"
touch -- "${marker}"
rc="$(run_dieable unexpected_key_file)"
check "unexpected_key_file -> dies (nonzero)" "$(nonzero "${rc}")" "yes"
check "unexpected_key_file -> deletes the clean marker" "$(exists "${marker}")" "no"

printf '%s\n' ""
printf '%s\n' "===== 20_sanity_checks MOK gate: ${pass} pass, ${fail} fail, 0 skip ====="
[ "${fail}" -eq 0 ]
