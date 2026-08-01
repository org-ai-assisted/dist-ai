#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker
## 'docker/derivative-maker-docker-image-ref'.
##
## THE BUG IT GUARDS: three places have to name the SAME container image --
## docker/derivative-maker-docker-run (builds and runs it),
## ci/dm-docker-image-cache (saves and loads it) and the CI workflows (start a
## systemd container from it). The dry-run workflow spelled the reference out
## with the architecture baked in ('...:x86_64'). That does not fail loudly when
## it drifts: docker just builds or pulls a DIFFERENT image, so the lane silently
## runs the wrong container, and on a non-x86_64 runner it names an image that
## was never built.
##
## The fix is one definition every consumer calls, so this test asserts the
## definition exists, that it is arch-derived, and that NO consumer spells a
## tagged reference out again.
##
## Needs no root, no network, no docker.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

repo_root=""
locate_subject() {
   local candidate

   for candidate in "${DM_SANITY_TESTS:-}" \
      "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/1100_sanity-tests" \
      "${HOME}/derivative-maker/build-steps.d/1100_sanity-tests"; do
      case "${candidate}" in
         ''|'/build-steps.d/1100_sanity-tests')
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         repo_root="$(dirname -- "$(dirname -- "${candidate}")")"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: no derivative-maker checkout found (set DM_SANITY_TESTS)." >&2
   exit 77
fi

image_ref_helper="${repo_root}/docker/derivative-maker-docker-image-ref"
if [ -x "${image_ref_helper}" ]; then
   pass "docker/derivative-maker-docker-image-ref exists and is executable"
else
   fail "docker/derivative-maker-docker-image-ref is missing or not executable; there is no single definition"
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi

## It must PRINT a reference and nothing else -- callers substitute its whole
## stdout into a docker argument.
emitted_ref="$("${image_ref_helper}")"
case "${emitted_ref}" in
   kicksecure/derivative-maker-docker:?*)
      pass "helper prints a tagged reference (${emitted_ref})"
      ;;
   *)
      fail "helper printed '${emitted_ref}', which is not a tagged image reference"
      ;;
esac
if [ "$(printf '%s\n' "${emitted_ref}" | wc --lines)" -eq 1 ]; then
   pass "helper prints exactly one line"
else
   fail "helper prints more than one line; callers substitute its whole stdout"
fi

## Arch-derived, not fixed: an amd64 and an arm64 image must not collide in a
## shared docker store or image cache.
if [ "${emitted_ref##*:}" = "$(uname --machine)" ]; then
   pass "the tag is this machine's architecture"
else
   fail "the tag '${emitted_ref##*:}' is not '$(uname --machine)'; it is not arch-derived"
fi

## Every consumer must CALL the helper rather than repeat the reference. Checked
## by content, because a stale copy is exactly what does not fail at runtime.
for consumer_rel in \
   docker/derivative-maker-docker-run \
   ci/dm-docker-image-cache \
   .github/workflows/local-build-dry-run.yml ; do
   consumer_abs="${repo_root}/${consumer_rel}"
   if [ ! -r "${consumer_abs}" ]; then
      fail "${consumer_rel}: not found"
      continue
   fi

   if grep --quiet --fixed-strings -- 'derivative-maker-docker-image-ref' "${consumer_abs}"; then
      pass "${consumer_rel}: calls the shared helper"
   else
      fail "${consumer_rel}: does not call docker/derivative-maker-docker-image-ref"
   fi

   ## A TAGGED literal is the defect. The bare untagged name is fine -- the
   ## helper itself contains it, and prose may mention it.
   if grep --quiet --extended-regexp -- 'kicksecure/derivative-maker-docker:' "${consumer_abs}"; then
      fail "${consumer_rel}: still spells out a tagged image reference -- $(grep --extended-regexp --max-count=1 -- 'kicksecure/derivative-maker-docker:' "${consumer_abs}")"
   else
      pass "${consumer_rel}: no hardcoded tagged reference"
   fi
done

## CANARY: the "no hardcoded reference" grep must be able to FIRE. The helper is
## the one file that legitimately contains the tagged form, so it is the natural
## positive control.
if grep --quiet --extended-regexp -- 'kicksecure/derivative-maker-docker:' "${image_ref_helper}"; then
   pass "canary: the hardcoded-reference grep matches when the pattern is present"
else
   fail "canary broken: the grep found nothing even in the helper that defines the reference"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: docker image reference."
