#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## check-image-builtin-mok: the return-code contract that gates legacy-dist's
## destructive image-builtin-MOK scrub and systemcheck check-8. Drives the REAL
## source-able script (the `sourceable` skill): sourcing defines
## check_image_builtin_mok (plus dkms_mok_variables_set via shim-signed-mok-setup
## and has via has.bsh) WITHOUT auto-running, then the test redirects the path
## globals to a temp tree and stubs mokutil to force each branch.
##
## Return-code contract (exit-code doc in the script):
##   0 = no vulnerable keys, or could not detect (the version_1 do_once marker
##       short-circuits here);
##   1 = vulnerable keys present, safe for legacy-dist to delete;
##   2 = vulnerable keys enrolled, user intervention required.
##
## A missing subject/dep is an ENVIRONMENT BUG -> exit 1 (FATAL), never a skip.

## The path globals this test reassigns (legacy_dist_do_once_dir, efi_sysfs_dir,
## dkms_mok_dir) are CONSUMED inside the sourced subject, across a boundary
## shellcheck does not follow -- so its unused-variable warnings are false here.
# shellcheck disable=SC2034
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/check-image-builtin-mok"
   export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
else
   subject='/usr/libexec/helper-scripts/check-image-builtin-mok'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

## Drift-guard: the enrolled-detection string and the do_once marker names are the
## load-bearing literals this test asserts on. A missing sentinel means the script
## drifted -- a hard error, not a silent pass.
for sentinel in \
   ' is already enrolled' \
   '_version_1'; do
   if ! grep --quiet --fixed-strings -- "${sentinel}" "${subject}"; then
      printf '%s\n' "FATAL: sentinel '${sentinel}' not found in '${subject}'; it drifted -- update this test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090,SC1091
source "${subject}"
if [ "$(type -t check_image_builtin_mok)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'check_image_builtin_mok' function" >&2
   exit 1
fi
if [ "$(type -t dkms_mok_variables_set)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' did not pull in 'dkms_mok_variables_set' (shim-signed-mok-setup)" >&2
   exit 1
fi
if ! has safe-rm; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

do_once="${work}/legacy-dist/do_once"
dkms="${work}/var/lib/dkms"
efi="${work}/efi"
bindir="${work}/bin"
sentinel_file="${work}/mokutil.invoked"
mkdir --parents -- "${bindir}"

## mokutil stub: records that it was invoked, then forces a branch via MOKUTIL_MODE.
## 'mokutil --test-key <pubfile>' is $1=--test-key $2=<pubfile>. The real script reads
## its combined output and treats a NONZERO exit as "enrolled". (The script comment:
## 'mokutil --test-key returns 1 if already enrolled, 0 if not'.)
cat > "${bindir}/mokutil" <<'STUB'
#!/bin/bash
printf '%s\n' invoked > "${MOKUTIL_SENTINEL:-/dev/null}" 2>/dev/null || true
case "${MOKUTIL_MODE:-}" in
   enrolled)     printf '%s is already enrolled\n' "$2"; exit 1 ;;
   notenrolled)  exit 0 ;;
   cannotdetect) printf '%s\n' 'could not determine key state'; exit 1 ;;
   *)            exit 0 ;;
esac
STUB
chmod +x -- "${bindir}/mokutil"

## Point the REAL script's path globals at the temp tree. The dkms key dir comes
## from dkms_mok_variables_set (sourced from shim-signed-mok-setup), which honors
## the SHIM_SIGNED_MOK_SETUP_DKMS_MOK_DIR prefix -> keys land under
## <prefix>/var/lib/dkms, i.e. exactly "${dkms}" above.
legacy_dist_do_once_dir="${do_once}"
efi_sysfs_dir="${efi}"
export SHIM_SIGNED_MOK_SETUP_DKMS_MOK_DIR="${work}"
export PATH="${bindir}:${PATH}"
export MOKUTIL_SENTINEL="${sentinel_file}"

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
   fi
}

## Fresh temp state: empty dkms dir, no markers, no efi dir, mokutil not-yet-invoked.
## $1 (optional): 'uefi' creates the efi-sysfs dir so the UEFI branch is taken.
reset_state() {
   safe-rm --recursive --force -- "${do_once}" "${dkms}" "${efi}" "${sentinel_file}"
   mkdir --parents -- "${dkms}"
   if [ "${1:-}" = 'uefi' ]; then
      mkdir --parents -- "${efi}"
   fi
   export MOKUTIL_MODE=''
}

## Runs the REAL function and echoes 'rc:invoked' (invoked = whether mokutil ran).
run_mok() {
   local rc=0 invoked='no'
   check_image_builtin_mok || rc=$?
   if [ -e "${sentinel_file}" ]; then
      invoked='yes'
   fi
   printf '%s' "${rc}:${invoked}"
}

## --- check_image_builtin_mok_version_1 do_once gate -> 0 --------------------
## Same enrolled setup; the version_1 marker (no mok-ok) must also short-circuit.
reset_state uefi
touch -- "${dkms}/mok.pub"
export MOKUTIL_MODE='enrolled'
mkdir --parents -- "${do_once}"
touch -- "${do_once}/check_image_builtin_mok_version_1"
check "version_1 do_once gate -> 0, mokutil not invoked" "$(run_mok)" "0:no"

## --- non-UEFI with a dkms key present -> 1 ----------------------------------
## No efi dir (non-UEFI). A present key is safe to delete -> 1.
reset_state
touch -- "${dkms}/mok.pub"
check "non-UEFI + dkms key present -> 1" "$(run_mok)" "1:no"

## --- UEFI, key present, NOT enrolled -> 1 -----------------------------------
reset_state uefi
touch -- "${dkms}/mok.pub"
export MOKUTIL_MODE='notenrolled'
check "UEFI key present, not enrolled -> 1" "$(run_mok)" "1:yes"

## --- UEFI, key present, ENROLLED -> 2 ---------------------------------------
reset_state uefi
touch -- "${dkms}/mok.pub"
export MOKUTIL_MODE='enrolled'
check "UEFI key present, enrolled -> 2" "$(run_mok)" "2:yes"

## --- no keys -> 0 AND the version_1 marker is written -----------------------
reset_state uefi
rc=0
check_image_builtin_mok || rc=$?
marker='absent'
if [ -f "${do_once}/check_image_builtin_mok_version_1" ]; then
   marker='present'
fi
check "no keys -> 0" "${rc}" "0"
check "no keys -> writes version_1 marker" "${marker}" "present"

## --- CANARY: the exact enrolled-string compare is load-bearing --------------
## With a key present + UEFI but mokutil returning a DIFFERENT message (nonzero),
## the script cannot confirm enrollment and must return 0 (NOT 2) and NOT set the
## marker. If the script matched any nonzero mokutil as "enrolled", this would be
## 2 -- so a 0 here proves the '<pubfile> is already enrolled' compare is real.
reset_state uefi
touch -- "${dkms}/mok.pub"
export MOKUTIL_MODE='cannotdetect'
canary_rc=0
check_image_builtin_mok || canary_rc=$?
canary_marker='absent'
if [ -f "${do_once}/check_image_builtin_mok_version_1" ]; then
   canary_marker='present'
fi
check "canary: unmatched mokutil message -> 0 (not 2)" "${canary_rc}" "0"
check "canary: cannot-detect does NOT set the do_once marker" "${canary_marker}" "absent"

printf '%s\n' ""
printf '%s\n' "===== check_image_builtin_mok: ${pass} pass, ${fail} fail, 0 skip ====="
[ "${fail}" -eq 0 ]
