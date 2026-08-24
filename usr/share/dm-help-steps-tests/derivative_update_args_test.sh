#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official': the
## caller's tolerances must reach 'derivative-update'.
##
## THE BUG IT GUARDS: under CI=true the script runs
##     ./derivative-update --update-only
## which sources help-steps/variables -> dist_build_one_parse_cmd, then runs
## git_sanity_test. The dry-run lane passes '--allow-uncommitted true', but that
## was not forwarded, so the check ran with the default and rejected the tree:
##     ERROR: Uncommitted changes in: main repo
## The rejected state is LEGITIMATE and transient -- help-steps/sign-and-tag
## amends the parent to absorb the staged submodule gitlinks, so the tree is
## momentarily dirty at exactly that point.
##
## Not visible before: the branch runs only under CI=true, and CI never reached
## the build until the dry-run lane began exporting it.
##
## SELECTIVE forwarding is the other half of the contract. derivative-update
## rejects '--tag' and '--ref' alongside '--update-only' as mutually exclusive,
## and dm-build-official receives the whole build argument set -- so forwarding
## "$@" wholesale would turn a tolerated dirty tree into a usage error.
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
for candidate in "${DM_BUILD_OFFICIAL:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/help-steps/dm-build-official" \
   "${dm_checkout}/help-steps/dm-build-official"; do
   case "${candidate}" in
      ''|'/help-steps/dm-build-official')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-build-official not found (set DM_BUILD_OFFICIAL)." >&2
   exit 1
fi

## Drive the REAL forwarding block: extract the CI branch and run it with a
## 'derivative-update' stub that records the argv it was handed. Extraction
## rather than a whole-script run, which would need a git checkout and a build.
workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

branch_body="$(sed -n '/^if \[ "${CI:-}" = "true" \]; then$/,/^fi$/p' -- "${subject}")"
if [ -z "${branch_body}" ]; then
   printf '%s\n' "FAILED: could not extract the CI branch from ${subject}." >&2
   exit 1
fi

## A stub that writes its argv, one per line, so a case can assert on it.
mkdir --parents -- "${workdir}/bin"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" "$@" > "${ARGV_OUT}"'
} > "${workdir}/bin/derivative-update"
chmod 0755 -- "${workdir}/bin/derivative-update"

run_branch() {
   local argv_out="${workdir}/argv.txt"

   true > "${argv_out}"
   (
      cd -- "${workdir}/bin" || exit 1
      CI=true ARGV_OUT="${argv_out}" bash -c "
         set -o nounset
         PATH=\"${workdir}/bin:\${PATH}\"
         ${branch_body}
      " -- "$@"
   ) >/dev/null 2>&1 || true
   cat -- "${argv_out}"
}

## --- the tolerance is forwarded --------------------------------------------
out="$(run_branch --allow-uncommitted true --freshness frozen)"
case "${out}" in
   *--allow-uncommitted*)
      pass "'--allow-uncommitted' reaches derivative-update"
      ;;
   *)
      fail "'--allow-uncommitted' was NOT forwarded; git_sanity_test rejects the transient dirty tree -- got: $(printf '%s' "${out}" | tr '\n' ' ')"
      ;;
esac
case "${out}" in
   *--allow-untagged*)
      fail "'--allow-untagged' was forwarded although the caller never passed it"
      ;;
   *)
      pass "a tolerance the caller did NOT pass is not invented"
      ;;
esac

out="$(run_branch --allow-untagged true)"
case "${out}" in
   *--allow-untagged*)
      pass "'--allow-untagged' reaches derivative-update"
      ;;
   *)
      fail "'--allow-untagged' was NOT forwarded"
      ;;
esac

## --- SELECTIVE: mutually exclusive options must NOT be forwarded -----------
## derivative-update rejects --tag/--ref alongside --update-only, so forwarding
## the whole argument set turns a tolerated dirty tree into a usage error.
out="$(run_branch --allow-uncommitted true --target qcow2 --flavor kicksecure-debug --freshness frozen)"
for forbidden in --target --flavor --freshness; do
   case "${out}" in
      *"${forbidden}"*)
         fail "'${forbidden}' was forwarded to derivative-update; it does not accept the full build argument set"
         ;;
      *)
         pass "'${forbidden}' is not forwarded"
         ;;
   esac
done

## --- CANARY: --update-only is always there ---------------------------------
## Without this, an empty argv would satisfy every negative assertion above.
case "${out}" in
   *--update-only*)
      pass "canary: derivative-update is still invoked with --update-only"
      ;;
   *)
      fail "canary broken: the stub recorded no --update-only, so these assertions prove nothing"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: derivative-update argument forwarding."
