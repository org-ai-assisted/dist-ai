#!/bin/bash

## These globals cross the sourced-subject boundary: the test SETS has_*/encrypt/
## filesystem/key material that provision_persistence_fs + plan_encryption read.
## shellcheck cannot follow the dynamic HELPER_SCRIPTS_PATH source, so it mis-sees
## them as unused/unassigned.
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests persistence-setup's provision_persistence_fs(): a key-type SELECTION
## must TRANSLATE into the correct cryptsetup / systemd-cryptenroll invocations. The
## sibling persistence_setup_plan_encryption_test.sh proves the DECISION
## (plan_encryption's globals); this proves the decision is carried into the right
## commands -- above all the NEGATIVE cases a globals test cannot catch: no
## luksAddKey without a keyfile extra, no TPM enroll on a non-tpm overlay, no crypto
## at all on a plaintext overlay.
##
## cryptsetup / systemd-cryptenroll / wipefs / mkfs.* are invoked by BARE NAME, so a
## PATH-prepended recording shim (a spy -- the subject-under-test is still the REAL
## function) captures each argv. seed_overlay_dirs mounts a real fs, so it is
## overridden to a no-op recorder. A FAKE partition path is used; no shim ever
## touches a real device, and the shim dir is isolated to this test's PATH and torn
## down on EXIT, so it can never leak into a real install path. No root, no device.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""
if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   subject="${LIVE_CONFIG_DIST_REPO}/usr/bin/persistence-setup"
else
   subject='/usr/bin/persistence-setup'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not found: ${subject}" >&2
   printf '%s\n' "set LIVE_CONFIG_DIST_REPO to a live-config-dist checkout, or install live-config-dist" >&2
   exit 1
fi

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
if [ -z "${HELPER_SCRIPTS_PATH}" ] && [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   HELPER_SCRIPTS_PATH="$(dirname -- "${LIVE_CONFIG_DIST_REPO}")/helper-scripts"
fi
export HELPER_SCRIPTS_PATH

# shellcheck disable=SC1090
source "${subject}"

work="$(mktemp --directory --tmpdir persistence-setup-provision.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## One recording spy, symlinked under each intercepted command name: it appends
## "<command> <args>" to PS_RECORD and succeeds. These are exactly the external
## binaries provision_persistence_fs invokes by bare name.
shimdir="${work}/bin"
mkdir --parents -- "${shimdir}"
export PS_RECORD="${work}/record"
recorder="${shimdir}/recorder"
# shellcheck disable=SC2016  ## ${0##*/} / $* are literal in the emitted shim, expanded when it runs
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "${0##*/} $*" >> "${PS_RECORD}"'
   printf '%s\n' 'exit 0'
} > "${recorder}"
chmod 0770 -- "${recorder}"
for cmd in cryptsetup systemd-cryptenroll wipefs mkfs.ext4; do
   ln --symbolic -- recorder "${shimdir}/${cmd}"
done
export PATH="${shimdir}:${PATH}"

## seed_overlay_dirs mounts the freshly-made filesystem; override it to a recording
## no-op so the unit needs no real device.
# shellcheck disable=SC2317  ## called indirectly by provision_persistence_fs
seed_overlay_dirs() { printf '%s\n' "seed_overlay_dirs $*" >> "${PS_RECORD}"; }

fake_part='/dev/fake-persist'

pass_count=0
fail_count=0
check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: $1"
   fi
}

## Fixed-string presence of a recorded command line; prints 'true'/'false'.
has_line() {
   if grep --quiet --fixed-strings -- "$1" "${PS_RECORD}"; then
      printf '%s' true
   else
      printf '%s' false
   fi
}
## 'true' iff the presence of a recorded line matches the expectation (the
## negative-case workhorse: want=false asserts the command did NOT run).
expect_match() {
   if [ "$(has_line "$2")" = "$1" ]; then printf '%s' true; else printf '%s' false; fi
}

## desc hp hk ht expect_addkey expect_tpm
run_case() {
   local desc="$1"
   true > "${PS_RECORD}"
   has_password="$2"
   has_keyfile="$3"
   has_tpm="$4"
   primary_key_kind=''
   enroll_keyfile_extra=''
   enroll_tpm=''
   plan_encryption
   encrypt='true'
   luks_uuid="${default_luks_uuid}"
   filesystem='ext4'
   keyfile="${work}/keyfile"
   primary_key_file="${work}/primarykey"
   true > "${keyfile}"
   true > "${primary_key_file}"
   open_mapper=''
   provision_persistence_fs "${fake_part}"
   check "${desc}: wipefs ran" "$(has_line 'wipefs --all')"
   check "${desc}: luksFormat ran" "$(has_line 'cryptsetup luksFormat')"
   check "${desc}: luksOpen ran" "$(has_line 'cryptsetup luksOpen')"
   check "${desc}: luksClose ran" "$(has_line 'cryptsetup luksClose')"
   check "${desc}: mkfs on the opened mapper" "$(has_line 'mkfs.ext4 -L persistence /dev/mapper/')"
   check "${desc}: luksAddKey=${5}" "$(expect_match "$5" 'cryptsetup luksAddKey')"
   check "${desc}: tpm-enroll=${6}" "$(expect_match "$6" '--tpm2-device=auto')"
}

## --- key-type -> command mapping (encrypt=true) ----------------------------
## primary always luksFormat; luksAddKey iff password AND keyfile; TPM enroll iff tpm.
run_case 'password'              true  false false  false false
run_case 'keyfile'              false  true  false  false false
run_case 'password+keyfile'      true  true  false  true  false
run_case 'password+tpm'          true  false true   false true
run_case 'keyfile+tpm'          false  true  true   false true
run_case 'password+keyfile+tpm'  true  true  true   true  true

## --- plaintext overlay: no crypto at all -----------------------------------
true > "${PS_RECORD}"
encrypt='false'
filesystem='ext4'
open_mapper=''
provision_persistence_fs "${fake_part}"
check 'plaintext: wipefs ran' "$(has_line 'wipefs --all')"
check 'plaintext: NO cryptsetup' "$(expect_match false 'cryptsetup')"
check 'plaintext: NO tpm enroll' "$(expect_match false 'systemd-cryptenroll')"
check 'plaintext: mkfs on the bare partition' "$(has_line "mkfs.ext4 -L persistence ${fake_part}")"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup provision encrypt: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
