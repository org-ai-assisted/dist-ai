#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/parse-cmd': every target that
## builds a VM disk image must imply '--type vm'.
##
## THE BUG IT GUARDS: '--target raw' set dist_build_raw=true and implied no type,
## while '--target utm' -- which sets that SAME flag -- implied vm. A caller
## passing '--target raw' without an explicit '--type' therefore reached
## build-steps.d/1100_sanity-tests with no type and died on
##   You must add either: '--type vm' '--type host'
## a message that never mentions '--target raw', after the whole package phase
## had already run. The CI dry-run lane hit exactly this.
##
## Structural rather than behavioural: parse-cmd is sourced into a build
## environment with a large amount of state, so driving it standalone would test
## the harness. The case arms are unambiguous, and the canaries below pin that
## this test can still tell the arms apart.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

parse_cmd=""
for candidate in "${DM_PARSE_CMD:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/help-steps/parse-cmd" \
   "${HOME}/derivative-maker/help-steps/parse-cmd"; do
   case "${candidate}" in
      ''|'/help-steps/parse-cmd')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      parse_cmd="${candidate}"
      break
   fi
done
if [ -z "${parse_cmd}" ]; then
   printf '%s\n' "SKIP: parse-cmd not found (set DM_PARSE_CMD)." >&2
   exit 77
fi

## The body of one '--target <name>' arm: from its test to the next 'elif'.
target_arm() {
   local name="$1"

   sed -n "/\[ \"\${2:-}\" = \"${name}\" \]/,/elif \[ \"\${2:-}\"/p" -- "${parse_cmd}"
}

## --- every VM-image target implies a type ----------------------------------
for target in virtualbox qcow2 utm raw; do
   arm="$(target_arm "${target}")"
   if [ -z "${arm}" ]; then
      fail "could not extract the '--target ${target}' arm; the test is wrong, not the code"
      continue
   fi
   case "${arm}" in
      *implicit_dist_type_vm*)
         pass "--target ${target} implies '--type vm'"
         ;;
      *)
         fail "--target ${target} implies no type; it reaches 1100_sanity-tests and dies on \"You must add either '--type vm'\""
         ;;
   esac
done

## --- iso is a HOST build, and must stay that way ---------------------------
## Also a canary: if this test just matched 'implicit_dist_type' anywhere, iso
## would pass the vm assertions above too.
iso_arm="$(target_arm iso)"
case "${iso_arm}" in
   *implicit_dist_type_host*)
     pass "--target iso still implies '--type host'"
      ;;
   *)
      fail "--target iso no longer implies '--type host'"
      ;;
esac
case "${iso_arm}" in
   *implicit_dist_type_vm*)
      fail "--target iso implies '--type vm'; the arms are being confused for one another"
      ;;
   *)
      pass "canary: --target iso does NOT imply vm, so the arms are told apart"
      ;;
esac

## --- CANARY: a target that legitimately implies NOTHING ---------------------
## '--target root' installs onto the running system: neither a vm image nor a
## host build. If it ever matched, the assertions above would be satisfied by a
## parse-cmd that implied vm everywhere.
root_arm="$(target_arm root)"
case "${root_arm}" in
   *implicit_dist_type*)
      fail "canary broken: --target root now implies a type, so 'implies a type' no longer distinguishes anything"
      ;;
   *)
      pass "canary: --target root implies no type, as an install-to-root build should"
      ;;
esac

## The helper must keep honouring an explicit '--type', or this change would
## override a caller that asked for something else.
helper="$(sed -n '/^implicit_dist_type_vm()/,/^}/p' -- "${parse_cmd}")"
case "${helper}" in
   *'"--type"'*)
      pass "implicit_dist_type_vm still returns early when '--type' was passed"
      ;;
   *)
      fail "implicit_dist_type_vm no longer checks for an explicit '--type'; implying a type would override the caller"
      ;;
esac

## --- '--type' must be matched as a whole ARGUMENT ---------------------------
## The helper greps the argument list for '--type' to decide whether the caller
## already chose one. As a plain substring match, any value merely CONTAINING the
## text (e.g. '--conffile /tmp/build--type.conf') suppressed the inference, and
## the build then failed the later "You must add either '--type vm'" check for a
## reason nothing in the command line suggested.
helper_matches="$(sed -n '/^implicit_dist_type_vm()/,/^}/p' -- "${parse_cmd}" | grep -- 'grep --fixed-strings' || true)"
if [ -z "${helper_matches}" ]; then
   fail "implicit_dist_type_vm no longer greps the argument list; this assertion is stale"
else
   case "${helper_matches}" in
      *--line-regexp*)
         pass "'--type' is matched as a whole argument (--line-regexp)"
         ;;
      *)
         fail "'--type' is matched as a SUBSTRING; an unrelated argument containing it suppresses the inference"
         ;;
   esac
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: target implies type."
