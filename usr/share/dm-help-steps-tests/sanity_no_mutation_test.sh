#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: 'build-steps.d/1100_sanity-tests' is a SANITY TEST, not a
## machine-mutating step.
##
## THE BUG IT GUARDS: 1100 used to install packages, write /etc/hostname and
## /etc/mailname, and mkdir ~/.gnupg -- a step named "sanity-tests" silently
## changing the host. Those mutations were moved to where they belong:
##   - package install  -> build-steps.d/1050_early-build-setup
##   - /etc/hostname, /etc/mailname -> build-steps.d/1200_prepare-build-machine
##   - ~/.gnupg (Qubes split-gpg-2) -> help-steps/signing-key-create and
##     help-steps/signing-key-test, co-located with the 'sq' signing calls that
##     need it, before those calls run.
## 1100 keeps only read-only checks plus the self-cleaning mount-test /
## check-build-primitives self-tests.
##
## Static assertions over the SHIPPED scripts (no eval): the suite also runs
## against branches and forks. Each absence assertion has a positive control so a
## broken matcher cannot pass everything. Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

## Resolve a checkout file (build step or help-step): env override, staged copy,
## then the checkout. 'subpath' is relative to the derivative-maker root.
locate_file() {
   local subpath env_override base candidate
   subpath="$1"
   env_override="${2:-}"
   base="$(basename -- "${subpath}")"

   for candidate in \
      "${env_override}" \
      "${test_dir}/${base}" \
      "${dm_checkout}/${subpath}"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}" ]; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

require_file() {
   local subpath env_override resolved
   subpath="$1"
   env_override="${2:-}"
   if ! resolved="$(locate_file "${subpath}" "${env_override}")"; then
      printf '%s\n' "FATAL: ${subpath} not found." >&2
      exit 1
   fi
   printf '%s\n' "${resolved}"
}

early_setup="$(require_file build-steps.d/1050_early-build-setup "${DM_EARLY_SETUP:-}")"
sanity_tests="$(require_file build-steps.d/1100_sanity-tests "${DM_SANITY_TESTS:-}")"
prepare_machine="$(require_file build-steps.d/1200_prepare-build-machine "${DM_PREPARE_BUILD_MACHINE:-}")"
signing_key_create="$(require_file help-steps/signing-key-create "${DM_SIGNING_KEY_CREATE:-}")"
signing_key_test="$(require_file help-steps/signing-key-test "${DM_SIGNING_KEY_TEST:-}")"

## absent EXPR FILE DESC: PASS when FILE has no line matching the ERE EXPR.
absent() {
   if grep --quiet --extended-regexp -- "$1" "$2"; then
      fail "$3"
   else
      pass "$3"
   fi
}

## present EXPR FILE DESC: PASS when FILE has a line matching the ERE EXPR.
## Used as the positive control for each 'absent' matcher.
present() {
   if grep --quiet --extended-regexp -- "$1" "$2"; then
      pass "$3"
   else
      fail "$3"
   fi
}

## --- 1100 is read-only ---

absent 'install_required_packages|apt-get'     "${sanity_tests}" "1100 does not install packages"
absent 'check-hostname|/etc/hostname'          "${sanity_tests}" "1100 does not touch /etc/hostname"
absent 'check-mailname|/etc/mailname'          "${sanity_tests}" "1100 does not touch /etc/mailname"
absent 'mkdir .*[.]gnupg'                      "${sanity_tests}" "1100 does not create ~/.gnupg"

## Positive control: the same matchers DO fire where the behaviour now lives, so a
## broken matcher cannot make the four assertions above pass vacuously.
present 'install_required_packages'            "${early_setup}"  "control: install_required_packages present in 1050"
present '/etc/hostname'                        "${prepare_machine}" "control: /etc/hostname handled in 1200"
present '/etc/mailname'                        "${prepare_machine}" "control: /etc/mailname handled in 1200"
present 'mkdir .*[.]gnupg'                     "${signing_key_create}" "control: ~/.gnupg created in signing-key-create"

## 1100 still performs its self-tests (not stripped along with the mutations).
present 'mount-test'                           "${sanity_tests}" "1100 still runs mount-test"
present 'check-build-primitives'               "${sanity_tests}" "1100 still runs check-build-primitives"

## --- 1200 performs the hostname/mailname prep (defined AND dispatched) ---

present 'check-hostname\(\)'                    "${prepare_machine}" "1200 defines check-hostname"
present 'check-mailname\(\)'                    "${prepare_machine}" "1200 defines check-mailname"
if grep --quiet --extended-regexp 'check-hostname|check-mailname' \
   <<< "$(sed -n '/^main()/,/^}/p' -- "${prepare_machine}")"; then
   pass "1200 calls hostname/mailname prep from main"
else
   fail "1200 defines hostname/mailname prep but never calls it from main"
fi

## --- ~/.gnupg is created before the sq keystore/signing calls that need it ---

## first_match ERE FILE -> 1-indexed line number of the first match, or empty.
first_match() {
   grep --line-number --extended-regexp --max-count=1 -- "$1" "$2" 2>/dev/null | cut -d: -f1
}

gnupg_before_sq() {
   local file label mkdir_line sqop_line
   file="$1"
   label="$2"

   mkdir_line="$(first_match 'mkdir .*[.]gnupg' "${file}")"
   ## The stateful keystore/signing operations (not 'has sq', not a comment's
   ## bare 'sq'): these route through gpg-agent under split-gpg-2 and need
   ## ~/.gnupg to exist first.
   sqop_line="$(first_match 'sq (cert|key|sign|inspect|verify)' "${file}")"

   if [ -z "${mkdir_line}" ]; then
      fail "${label}: no 'mkdir ~/.gnupg'"
      return
   fi
   if [ -z "${sqop_line}" ]; then
      fail "${label}: no sq keystore/signing call found (test precondition)"
      return
   fi
   if [ "${mkdir_line}" -lt "${sqop_line}" ]; then
      pass "${label}: ~/.gnupg created (line ${mkdir_line}) before first sq op (line ${sqop_line})"
   else
      fail "${label}: ~/.gnupg mkdir (line ${mkdir_line}) is NOT before first sq op (line ${sqop_line})"
   fi
}

gnupg_before_sq "${signing_key_create}" "signing-key-create"
gnupg_before_sq "${signing_key_test}"   "signing-key-test"

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: 1100 is a read-only sanity test; mutations relocated."
