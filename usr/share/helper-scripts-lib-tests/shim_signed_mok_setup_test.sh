#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## shim-signed-mok-setup provisions the per-machine DKMS MOK and the shim-signed
## symlinks. Drives the REAL source-able script (the `sourceable` skill): sourcing
## defines dkms_mok_variables_set + shim_signed_mok_setup WITHOUT running them. The
## test redirects the base-dir globals to a temp tree, requires the real log/has
## helpers, and stubs the external 'dkms' plus the root check.
##
## Covered: (1) dkms_mok_variables_set derives the six paths from the base-dir
## globals; (2) keys-already-present short-circuits WITHOUT calling 'dkms
## generate_mok'; (3) the generate path runs 'dkms generate_mok' and links the
## shim MOK; canary: a failing 'dkms generate_mok' returns 1.
##
## A missing subject/dep is an ENVIRONMENT BUG -> exit 1 (FATAL), never a skip.

## The base-dir globals this test sets, and the six path vars the sourced
## dkms_mok_variables_set assigns, cross a boundary shellcheck does not follow --
## so its unused (SC2034) and unassigned (SC2154) warnings are false here.
# shellcheck disable=SC2034,SC2154
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/shim-signed-mok-setup"
   libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
   export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
else
   subject='/usr/sbin/shim-signed-mok-setup'
   libdir='/usr/libexec/helper-scripts'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
for lib in log_run_die.sh as_root.sh has.bsh; do
   if [ ! -r "${libdir}/${lib}" ]; then
      printf '%s\n' "FATAL: helper-scripts lib '${lib}' not readable under '${libdir}'" >&2
      exit 1
   fi
done

## Drift-guard: the log lines this test keys the short-circuit vs generate paths on.
for sentinel in \
   'Key files already exist: yes' \
   'dkms generate_mok' \
   'Key files created: yes'; do
   if ! grep --quiet --fixed-strings -- "${sentinel}" "${subject}"; then
      printf '%s\n' "FATAL: sentinel '${sentinel}' not found in '${subject}'; it drifted -- update this test." >&2
      exit 1
   fi
done

## shim-signed-mok-setup is the sentinel-variant source-able form: sourcing it does
## NOT pull in log/has/as_root (those sources are gated behind 'executed'), so the
## test provides them -- the REAL log/has, and a no-op root check (a root action is
## a legitimate stub). as_root.sh pulls in get_colors + log_run_die.
# shellcheck disable=SC1090,SC1091
source "${libdir}/as_root.sh"
# shellcheck disable=SC1090,SC1091
source "${libdir}/has.bsh"
# shellcheck disable=SC1090,SC1091
source "${subject}"
if [ "$(type -t shim_signed_mok_setup)" != 'function' ] \
   || [ "$(type -t dkms_mok_variables_set)" != 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' did not define the expected functions" >&2
   exit 1
fi
if ! has safe-rm; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
## Not root in the test: the root check is stubbed to a no-op.
as_root() { :; }

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

dkms_base="${work}/dkms"
shim_base="${work}/shim/mok"
bindir="${work}/bin"
gen_sentinel="${work}/dkms.generate_mok.invoked"
mkdir --parents -- "${bindir}"

## dkms stub: records a 'generate_mok' invocation, optionally fails, and (on success)
## creates the key files in DKMS_STUB_MOK_DIR to emulate the real tool.
cat > "${bindir}/dkms" <<'STUB'
#!/bin/bash
if [ "${1:-}" = 'generate_mok' ]; then
   printf '%s\n' invoked > "${DKMS_GENMOK_SENTINEL:-/dev/null}" 2>/dev/null || true
   if [ "${DKMS_GENMOK_MODE:-ok}" = 'fail' ]; then
      exit 1
   fi
   if [ -n "${DKMS_STUB_MOK_DIR:-}" ]; then
      mkdir --parents -- "${DKMS_STUB_MOK_DIR}"
      touch -- "${DKMS_STUB_MOK_DIR}/mok.pub" "${DKMS_STUB_MOK_DIR}/mok.key"
   fi
fi
exit 0
STUB
chmod +x -- "${bindir}/dkms"
export PATH="${bindir}:${PATH}"
export DKMS_GENMOK_SENTINEL="${gen_sentinel}"
export DKMS_STUB_MOK_DIR="${dkms_base}"

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

reset_state() {
   safe-rm --recursive --force -- "${dkms_base}" "${shim_base}" "${gen_sentinel}"
   mkdir --parents -- "${dkms_base}"
   export DKMS_GENMOK_MODE='ok'
}

run_setup() {
   local rc=0
   shim_signed_mok_setup >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## --- (1) dkms_mok_variables_set derives the six paths from the base dirs -----
reset_state
dkms_mok_dir="${dkms_base}"
shim_mok_dir="${shim_base}"
dkms_mok_variables_set
check "dkms_mok_public_file"  "${dkms_mok_public_file}"  "${dkms_base}/mok.pub"
check "dkms_mok_private_file" "${dkms_mok_private_file}" "${dkms_base}/mok.key"
check "shim_mok_public_file"  "${shim_mok_public_file}"  "${shim_base}/MOK.der"
check "shim_mok_private_file" "${shim_mok_private_file}" "${shim_base}/MOK.priv"

## --- (2) keys already present -> short-circuit, generate_mok NOT invoked -----
reset_state
dkms_mok_dir="${dkms_base}"
shim_mok_dir="${shim_base}"
touch -- "${dkms_base}/mok.pub" "${dkms_base}/mok.key"
rc="$(run_setup)"
gen='no'
if [ -e "${gen_sentinel}" ]; then
   gen='yes'
fi
link='no'
if [ -L "${shim_base}/MOK.der" ] && [ -L "${shim_base}/MOK.priv" ]; then
   link='yes'
fi
check "keys present -> rc 0"                    "${rc}"  "0"
check "keys present -> generate_mok NOT invoked" "${gen}" "no"
check "keys present -> shim MOK symlinks created" "${link}" "yes"

## --- (3) no keys -> 'dkms generate_mok' creates them, shim links made --------
reset_state
dkms_mok_dir="${dkms_base}"
shim_mok_dir="${shim_base}"
rc="$(run_setup)"
gen='no'
if [ -e "${gen_sentinel}" ]; then
   gen='yes'
fi
keys='no'
if [ -f "${dkms_base}/mok.pub" ] && [ -f "${dkms_base}/mok.key" ]; then
   keys='yes'
fi
link='no'
if [ -L "${shim_base}/MOK.der" ] && [ -L "${shim_base}/MOK.priv" ]; then
   link='yes'
fi
check "no keys -> rc 0"                    "${rc}"  "0"
check "no keys -> generate_mok invoked"    "${gen}" "yes"
check "no keys -> keys created by generate" "${keys}" "yes"
check "no keys -> shim MOK symlinks created" "${link}" "yes"

## --- CANARY: a failing 'dkms generate_mok' must return 1 --------------------
## If the generate branch did not check the result, this would be 0 -- so rc 1
## proves the failure path is live.
reset_state
dkms_mok_dir="${dkms_base}"
shim_mok_dir="${shim_base}"
export DKMS_GENMOK_MODE='fail'
check "canary: dkms generate_mok fails -> rc 1" "$(run_setup)" "1"

printf '%s\n' ""
printf '%s\n' "===== shim_signed_mok_setup: ${pass} pass, ${fail} fail, 0 skip ====="
[ "${fail}" -eq 0 ]
