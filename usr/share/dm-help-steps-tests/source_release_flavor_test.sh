#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official-one'
## Phase 4: the source release, and why images need no dm-prepare-release call
## there.
##
## TWO THINGS IT GUARDS:
##
## 1. The source-release flavor was the literal 'kicksecure-lxqt', inside an
##    'if flavor_built' guard. A reduced flavors_list that excluded that name --
##    a CI smoke build on kicksecure-cli, say -- therefore skipped the source
##    release silently: images published, no source archive, no error.
##
## 2. Phase 4 runs dm-prepare-release for '--target source' ONLY. That reads like
##    a gap (where does the per-image buildinfo come from?) and the tempting
##    'fix' is to add a per-image call here, which would re-run and re-sign work
##    already done. Every '<image>.dm-buildinfo' comes from
##    build-steps.d/5200_prepare-release, which runs inside each per-flavor
##    './derivative-maker' invocation. This pins the two facts that make the
##    asymmetry correct, so the invariant cannot quietly stop holding.
##
## Needs no root, no network, no build.

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

subject=""
for candidate in "${DM_BUILD_OFFICIAL_ONE:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/help-steps/dm-build-official-one" \
   "${dm_checkout}/help-steps/dm-build-official-one"; do
   case "${candidate}" in
      ''|'/help-steps/dm-build-official-one')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-build-official-one not found (set DM_BUILD_OFFICIAL_ONE)." >&2
   exit 1
fi

repo_root="$(dirname -- "$(dirname -- "${subject}")")"

## --- 1. the source-release flavor is configurable --------------------------
if grep --quiet --fixed-strings -- 'dist_build_source_release_flavor' "${subject}"; then
   pass "the source-release flavor is a variable"
else
   fail "the source-release flavor is still hardcoded; a flavors_list without it skips the source release silently"
fi

## The dm-prepare-release call must USE the variable, not merely define it.
release_line="$(grep -- 'dm-prepare-release --target source' "${subject}" || true)"
if [ -z "${release_line}" ]; then
   fail "no 'dm-prepare-release --target source' call found"
else
   case "${release_line}" in
      *dist_build_source_release_flavor*)
         pass "the source release is invoked with the configurable flavor"
         ;;
      *)
         fail "the source release still passes a literal flavor: ${release_line}"
         ;;
   esac
fi

## CANARY: it must still DEFAULT, or a plain build would publish no source.
if grep --quiet --extended-regexp -- "dist_build_source_release_flavor.*=.*'kicksecure-lxqt'" "${subject}"; then
   pass "canary: it defaults to kicksecure-lxqt, so an unconfigured build still releases source"
else
   fail "canary: no default; an unconfigured build would publish no source archive"
fi

## A skipped source release must SAY so rather than vanish.
if grep --quiet --fixed-strings -- 'no source release' "${subject}"; then
   pass "a skipped source release is reported"
else
   fail "a skipped source release is silent, which is how this went unnoticed"
fi

## --- 2. the per-image buildinfo invariant ----------------------------------
## Phase 4 is only correct because 5200 already ran per flavor and target.
step_5200="${repo_root}/build-steps.d/5200_prepare-release"
if [ ! -r "${step_5200}" ]; then
   fail "build-steps.d/5200_prepare-release is gone; nothing else emits a per-image buildinfo"
elif grep --quiet --fixed-strings -- 'dm-prepare-release' "${step_5200}"; then
   pass "5200_prepare-release still invokes dm-prepare-release, which is what emits the per-image buildinfo"
else
   fail "5200_prepare-release no longer invokes dm-prepare-release; per-image buildinfo would silently stop being produced"
fi

## Phase 3's skip list must never grow to include the release step, or images
## would be built and uploaded with no provenance at all.
skip_block="$(sed -n '/^skip_shared_args=(/,/^)/p' -- "${subject}")"
if [ -z "${skip_block}" ]; then
   fail "could not extract skip_shared_args; the assertion below would prove nothing"
else
   case "${skip_block}" in
      *prepare-release*)
         fail "Phase 3 now skips the release step, so images would ship with no buildinfo: ${skip_block}"
         ;;
      *)
         pass "Phase 3 does not skip the release step, so every per-flavor build emits its buildinfo"
         ;;
   esac
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: source release flavor + per-image buildinfo invariant."
