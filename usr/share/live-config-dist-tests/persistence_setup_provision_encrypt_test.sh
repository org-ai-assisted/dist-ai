#!/bin/bash

## These globals cross the sourced-subject boundary: the test SETS do_encrypt/
## passphrase/keyfile/use_tpm/luks_uuid/filesystem/persistence_partition that
## setup_persistence_fs reads. shellcheck cannot follow the dynamic
## HELPER_SCRIPTS_PATH source, so it mis-sees them as unused/unassigned.
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests persistence-setup's setup_persistence_fs(): an encryption key-type
## selection must TRANSLATE into the correct cryptsetup / systemd-cryptenroll
## invocations. cryptsetup / systemd-cryptenroll / mkfs.* / mount / umount are
## invoked by BARE NAME, so a PATH-prepended recording spy captures each argv (the
## subject-under-test is still the REAL function); mkdir / rmdir / shred are
## no-op-shimmed so the seed-dir dance needs no real mount. A FAKE partition path
## is used; no shim ever touches a real device. Regressions covered:
##   * org-ai-assisted/live-config-dist#3 (h8w): the TPM-enroll and keyfile-luksOpen
##     paths ran "${crypt_msg[@]}" -- an UNSET array that expands to nothing under
##     set -u, so the real command never ran. The array built is crypt_cmd.
##   * org-ai-assisted/live-config-dist#3 (h81): TPM enrollment with a passphrase
##     fed the passphrase on a stdin pipe to systemd-cryptenroll, which may prompt
##     on the tty instead. The fix enrolls via --unlock-key-file pointing at a
##     transient keyfile holding the passphrase with NO trailing newline.
## No root, no device, no network.

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

if [ ! "$(type -t setup_persistence_fs)" = 'function' ]; then
   printf '%s\n' "FATAL: sourcing '${subject}' defined no 'setup_persistence_fs'" >&2
   exit 1
fi

work="$(mktemp --directory --tmpdir persistence-setup-provision.XXXXXX)"
export TMPDIR="${work}"   ## keep the subject's own mktemp inside the work dir
# shellcheck disable=SC2317  ## EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Recording spy. Appends "<command> <args>" to PS_RECORD. For systemd-cryptenroll
## it ALSO records the byte content (hex) of the --unlock-key-file it is handed, so
## the test can prove the passphrase keyfile carries NO trailing newline.
shimdir="${work}/bin"
mkdir --parents -- "${shimdir}"
export PS_RECORD="${work}/record"
recorder="${shimdir}/recorder"
# shellcheck disable=SC2016  ## literal in the emitted shim, expanded when it runs
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "${0##*/} $*" >> "${PS_RECORD}"'
   printf '%s\n' 'for a in "$@"; do'
   printf '%s\n' '  case "$a" in'
   printf '%s\n' '    --unlock-key-file=*)'
   printf '%s\n' '      f="${a#--unlock-key-file=}"'
   printf '%s\n' '      if [ -r "$f" ]; then'
   printf '%s\n' '        printf "UKF_HEX %s\n" "$(od -An -v -tx1 -- "$f" | tr -d " \n")" >> "${PS_RECORD}"'
   printf '%s\n' '      fi'
   printf '%s\n' '      ;;'
   printf '%s\n' '  esac'
   printf '%s\n' 'done'
   printf '%s\n' 'exit 0'
} > "${recorder}"
chmod 0770 -- "${recorder}"
for cmd in cryptsetup systemd-cryptenroll mkfs.ext4 mkfs.btrfs mount umount mkdir rmdir shred; do
   ln --symbolic -- recorder "${shimdir}/${cmd}"
done
export PATH="${shimdir}:${PATH}"

fake_part='/dev/fake-persist'
mapper="persistence_setup-$$"
mapper_dev="/dev/mapper/${mapper}"
test_pass='swordfish'
pass_hex="$(printf '%s' "${test_pass}" | od -An -v -tx1 | tr -d ' \n')"

pass_count=0
fail_count=0
check() {
   if [ "$2" = 'true' ]; then
      pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $1"
   else
      fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1"
   fi
}

## Does SOME recorded line contain EVERY needle as a complete space-delimited
## token? (argv-order independent; token-boundary exact). "$1" = expected presence.
line_has() {
   local want="$1" hay needle found='false' line_ok
   shift
   while IFS= read -r hay; do
      line_ok='true'
      for needle in "$@"; do
         if [[ " ${hay} " != *" ${needle} "* ]]; then
            line_ok='false'
            break
         fi
      done
      if [ "${line_ok}" = 'true' ]; then
         found='true'
         break
      fi
   done < "${PS_RECORD}"
   if [ "${found}" = "${want}" ]; then printf '%s' true; else printf '%s' false; fi
}

## desc do_encrypt pass keyfile tpm expect_addkey expect_tpm
run_case() {
   local desc="$1" rc=0
   true > "${PS_RECORD}"
   do_encrypt="$2"; passphrase="$3"
   keyfile="$5"; use_tpm="$6"
   luks_uuid="${default_luks_uuid}"; filesystem='ext4'
   persistence_partition="${fake_part}"; open_mapper=''; transient_keyfile=''
   ( setup_persistence_fs ) || rc=$?
   check "${desc}: setup_persistence_fs returned 0" "$( [ "${rc}" -eq 0 ] && printf '%s' true || printf '%s' false )"
   if [ "${do_encrypt}" = 'true' ]; then
      check "${desc}: luksFormat on the partition" "$(line_has true 'cryptsetup' 'luksFormat' "${fake_part}")"
      check "${desc}: luksOpen the partition onto the mapper" "$(line_has true 'cryptsetup' 'luksOpen' "${fake_part}" "${mapper}")"
      check "${desc}: luksClose closes the mapper" "$(line_has true 'cryptsetup' 'luksClose' "${mapper}")"
      check "${desc}: mkfs -L persistence on the opened mapper" "$(line_has true 'mkfs.ext4' '-L' 'persistence' "${mapper_dev}")"
   else
      ## plaintext: no LUKS at all, mkfs straight onto the bare partition.
      check "${desc}: no luksFormat" "$(line_has false 'cryptsetup' 'luksFormat')"
      check "${desc}: mkfs -L persistence on the BARE partition" "$(line_has true 'mkfs.ext4' '-L' 'persistence' "${fake_part}")"
   fi
   ## $7 addkey, $8 tpm presence
   if [ "$7" = 'true' ]; then
      check "${desc}: luksAddKey on the partition" "$(line_has true 'cryptsetup' 'luksAddKey' "${fake_part}")"
   else
      check "${desc}: no luksAddKey" "$(line_has false 'cryptsetup' 'luksAddKey')"
   fi
   if [ "$8" = 'true' ]; then
      ## h8w: the enroll command must ACTUALLY run against the partition (the
      ## crypt_msg bug made it run nothing).
      check "${desc}: tpm enroll runs on the partition" "$(line_has true 'systemd-cryptenroll' "${fake_part}")"
   else
      check "${desc}: no tpm enroll" "$(line_has false 'systemd-cryptenroll')"
   fi
}

##               desc                    enc   pass          _  keyfile          tpm    addkey tpm
run_case 'password'             true  "${test_pass}" x ''               false  false  false
keyfile_a="${work}/keyfile_a"; head --bytes=64 /dev/zero | tr '\0' 'k' > "${keyfile_a}"
run_case 'keyfile'             true  ''             x "${keyfile_a}"   false  false  false
run_case 'password+keyfile'     true  "${test_pass}" x "${keyfile_a}"   false  true   false
run_case 'password+tpm'         true  "${test_pass}" x ''               true   false  true
run_case 'keyfile+tpm'         true  ''             x "${keyfile_a}"   true   false  true
run_case 'password+keyfile+tpm' true  "${test_pass}" x "${keyfile_a}"   true   true   true
run_case 'plaintext'            false ''             x ''               false  false  false

## --- h8w: keyfile+tpm enroll uses the keyfile (crypt_cmd ran, not crypt_msg) --
true > "${PS_RECORD}"
do_encrypt='true'; passphrase=''; keyfile="${keyfile_a}"; use_tpm='true'
luks_uuid="${default_luks_uuid}"; filesystem='ext4'; persistence_partition="${fake_part}"
open_mapper=''; transient_keyfile=''
( setup_persistence_fs ) || true
check "h8w: keyfile+tpm enroll passes --unlock-key-file=<keyfile>" \
   "$(line_has true 'systemd-cryptenroll' "--unlock-key-file=${keyfile_a}" "${fake_part}")"
check "h8w: keyfile luksOpen passes --key-file <keyfile>" \
   "$(line_has true 'cryptsetup' 'luksOpen' '--key-file' "${keyfile_a}" "${fake_part}")"

## --- h81: password+tpm enroll uses a transient keyfile with NO trailing newline -
true > "${PS_RECORD}"
do_encrypt='true'; passphrase="${test_pass}"; keyfile=''; use_tpm='true'
luks_uuid="${default_luks_uuid}"; filesystem='ext4'; persistence_partition="${fake_part}"
open_mapper=''; transient_keyfile=''
( setup_persistence_fs ) || true
check "h81: password+tpm enroll is via --unlock-key-file (not a stdin prompt)" \
   "$(line_has true 'systemd-cryptenroll' '--tpm2-device=auto' "${fake_part}")"
## The recorded keyfile bytes must equal the passphrase with NO trailing 0a.
check "h81: the transient keyfile holds the passphrase with NO trailing newline" \
   "$(line_has true 'UKF_HEX' "${pass_hex}")"

printf '%s\n' ""
printf '%s\n' "===== persistence-setup provision encrypt: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
