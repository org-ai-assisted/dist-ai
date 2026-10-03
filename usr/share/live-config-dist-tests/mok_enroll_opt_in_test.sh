#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## mok-enroll-opt-in is the Calamares-install opt-in Secure Boot MOK step (OFF by
## default, gated on MOK_ENROLL + an EFI install). Drives the REAL source-able
## script (the `sourceable` skill): sourcing defines mok_enroll_opt_in WITHOUT
## running it, then the test redirects its path globals to a temp tree and stubs
## the three external signing commands.
##
## Covered: MOK_ENROLL unset -> skip (rc 0, no externals, no mok-ok marker);
## MOK_ENROLL set but not EFI -> skip; MOK_ENROLL set + EFI -> runs
## shim-signed-mok-setup + rebuild-dkms-modules + rebuild-vbox-ga-modules, writes
## the legit mok-ok marker, and logs. Each skip is a canary: the externals must
## NOT run and the marker must NOT appear.
##
## A missing subject/dep is an ENVIRONMENT BUG -> exit 1 (FATAL), never a skip.

## The path globals this test reassigns (mok_enroll_log_file, efi_sysfs_dir,
## legacy_dist_do_once_dir, dkms_mok_public_file) are CONSUMED inside the sourced
## subject, across a boundary shellcheck does not follow -- its warnings are false.
# shellcheck disable=SC2034
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/libexec/live-config-dist/mok-enroll-opt-in"
else
   subject='/usr/libexec/live-config-dist/mok-enroll-opt-in'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

## The subject sources helper-scripts' check_runtime.bsh (live-config-dist Depends:
## helper-scripts). Resolve HELPER_SCRIPTS_PATH if the orchestrator did not wire it:
## prefer HELPER_SCRIPTS_REPO, else the helper-scripts sibling of the checkout, else
## the installed tree.
if [ -z "${HELPER_SCRIPTS_PATH:-}" ]; then
   if [ -n "${HELPER_SCRIPTS_REPO:-}" ]; then
      export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
   elif [ -n "${LIVE_CONFIG_DIST_REPO}" ] \
      && [ -r "${LIVE_CONFIG_DIST_REPO}/../helper-scripts/usr/libexec/helper-scripts/check_runtime.bsh" ]; then
      export HELPER_SCRIPTS_PATH="${LIVE_CONFIG_DIST_REPO}/../helper-scripts"
   else
      ## Installed tree: the subject sources "${HELPER_SCRIPTS_PATH:-}"/usr/..., so
      ## the root must be EMPTY (-> /usr/libexec/...), NOT '/usr' (that would double
      ## to /usr/usr/libexec/... both here and in the subject).
      export HELPER_SCRIPTS_PATH=''
   fi
fi
if [ ! -r "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: helper-scripts check_runtime.bsh not readable under '${HELPER_SCRIPTS_PATH}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO (or HELPER_SCRIPTS_PATH) to a helper-scripts checkout" >&2
   exit 1
fi

## Drift-guard: the log markers and the mok-ok filename this test keys on.
for sentinel in \
   'skip: MOK_ENROLL unset' \
   'skip: not EFI' \
   'run: creating MOK + signing DKMS and VirtualBox GA modules' \
   'done: mok.pub' \
   'skip mok-ok' \
   'mok-ok'; do
   if ! grep --quiet --fixed-strings -- "${sentinel}" "${subject}"; then
      printf '%s\n' "FATAL: sentinel '${sentinel}' not found in '${subject}'; it drifted -- update this test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090,SC1091
source "${subject}"
if [ "$(type -t mok_enroll_opt_in)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'mok_enroll_opt_in' function" >&2
   exit 1
fi
# shellcheck disable=SC1090,SC1091
source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/has.bsh"
if ! has safe-rm; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

base_path="${PATH}"
work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

logfile="${work}/mok-enroll-opt-in.log"
do_once="${work}/legacy-dist/do_once"
efi="${work}/efi"
dkms_pub="${work}/dkms/mok.pub"
dkms_key="${work}/dkms/mok.key"
bindir="${work}/bin"
mkdir --parents -- "${bindir}" "${work}/dkms"

## Stubs for the three external signing commands; each records that it ran.
for tool in shim-signed-mok-setup rebuild-dkms-modules rebuild-vbox-ga-modules; do
   cat > "${bindir}/${tool}" <<STUB
#!/bin/bash
printf '%s\n' invoked > "${work}/${tool}.invoked" 2>/dev/null || true
exit 0
STUB
   chmod +x -- "${bindir}/${tool}"
done

## Point the REAL script's path globals at the temp tree.
mok_enroll_log_file="${logfile}"
efi_sysfs_dir="${efi}"
legacy_dist_do_once_dir="${do_once}"
dkms_mok_public_file="${dkms_pub}"
dkms_mok_private_file="${dkms_key}"

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

externals_invoked() {
   local any='no' tool
   for tool in shim-signed-mok-setup rebuild-dkms-modules rebuild-vbox-ga-modules; do
      if [ -e "${work}/${tool}.invoked" ]; then
         any='yes'
      fi
   done
   printf '%s' "${any}"
}
all_externals_invoked() {
   local all='yes' tool
   for tool in shim-signed-mok-setup rebuild-dkms-modules rebuild-vbox-ga-modules; do
      if [ ! -e "${work}/${tool}.invoked" ]; then
         all='no'
      fi
   done
   printf '%s' "${all}"
}
log_has() {
   if [ -r "${logfile}" ] && grep --quiet --fixed-strings -- "$1" "${logfile}"; then
      printf 'yes'
   else
      printf 'no'
   fi
}

## $1 = 'uefi' creates the efi dir. Resets externals, marker and log first.
reset_state() {
   safe-rm --recursive --force -- "${do_once}" "${efi}" "${logfile}"
   safe-rm --force -- "${work}"/shim-signed-mok-setup.invoked \
      "${work}"/rebuild-dkms-modules.invoked "${work}"/rebuild-vbox-ga-modules.invoked
   safe-rm --force -- "${dkms_pub}" "${dkms_key}"
   if [ "${1:-}" = 'uefi' ]; then
      mkdir --parents -- "${efi}"
   fi
}

run_enroll() {
   local rc=0
   PATH="${bindir}:${base_path}" mok_enroll_opt_in >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## --- MOK_ENROLL unset -> skip (no externals, no marker) ---------------------
reset_state uefi
unset MOK_ENROLL
rc="$(run_enroll)"
marker='absent'
[ -e "${do_once}/mok-ok" ] && marker='present'
check "MOK_ENROLL unset -> rc 0"                "${rc}"                 "0"
check "MOK_ENROLL unset -> no externals invoked" "$(externals_invoked)" "no"
check "MOK_ENROLL unset -> no mok-ok marker"     "${marker}"            "absent"
check "MOK_ENROLL unset -> logs 'skip: MOK_ENROLL unset'" "$(log_has 'skip: MOK_ENROLL unset')" "yes"

## --- MOK_ENROLL set but NOT EFI -> skip -------------------------------------
reset_state
export MOK_ENROLL=1
rc="$(run_enroll)"
marker='absent'
[ -e "${do_once}/mok-ok" ] && marker='present'
check "set + not-EFI -> rc 0"                "${rc}"                 "0"
check "set + not-EFI -> no externals invoked" "$(externals_invoked)" "no"
check "set + not-EFI -> no mok-ok marker"     "${marker}"            "absent"
check "set + not-EFI -> logs 'skip: not EFI'" "$(log_has 'skip: not EFI')" "yes"

## --- MOK_ENROLL set + EFI + freshly GENERATED key -> run all three, bless ----
## No pre-existing keypair, so shim-signed-mok-setup generates a fresh per-machine
## key and it IS blessed with mok-ok.
reset_state uefi
export MOK_ENROLL=1
rc="$(run_enroll)"
marker='absent'
[ -e "${do_once}/mok-ok" ] && marker='present'
check "set + EFI, generated -> rc 0"                     "${rc}"                     "0"
check "set + EFI, generated -> all three externals invoked" "$(all_externals_invoked)"  "yes"
check "set + EFI, generated -> mok-ok marker written"    "${marker}"                 "present"
check "set + EFI, generated -> logs 'run: ...'"          "$(log_has 'run: creating MOK + signing DKMS and VirtualBox GA modules')" "yes"
check "set + EFI, generated -> logs 'done: mok.pub'"     "$(log_has 'done: mok.pub')" "yes"

## --- MOK_ENROLL set + EFI + REUSED pre-existing key -> run but do NOT bless ---
## REGRESSION (dev868 security finding): a pre-existing DKMS keypair on a fresh
## install is the image-builtin/untrusted shared key. shim-signed-mok-setup reuses
## it, and blessing it with mok-ok would make legacy-dist's scrub and
## check-image-builtin-mok skip a shared key. The externals still run; only the
## marker is withheld. RED on pre-fix code (which touched mok-ok unconditionally).
reset_state uefi
export MOK_ENROLL=1
touch -- "${dkms_pub}" "${dkms_key}"
rc="$(run_enroll)"
marker='absent'
[ -e "${do_once}/mok-ok" ] && marker='present'
check "reused key -> rc 0"                        "${rc}"                    "0"
check "reused key -> externals still invoked"      "$(all_externals_invoked)" "yes"
check "reused key -> mok-ok marker NOT written"    "${marker}"                "absent"
check "reused key -> logs 'skip mok-ok'"           "$(log_has 'skip mok-ok')" "yes"

printf '%s\n' ""
printf '%s\n' "===== mok_enroll_opt_in: ${pass} pass, ${fail} fail, 0 skip ====="
[ "${fail}" -eq 0 ]
