#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/dm-build-official-one': a
## 'flavors_list' arriving as a space-separated SCALAR (an env var, e.g. from CI
## selecting 'whonix-gateway-lxqt whonix-workstation-lxqt') must be split into the
## bash ARRAY the per-flavor loops iterate.
##
## THE BUG: the resolution was 'flavors_list=( ... )' guarded only by
## '[ -n "${flavors_list:-}" ] ||', so a set scalar env var was left as-is and
## "${flavors_list[@]}" iterated it as ONE element -- passing the whole string as a
## single '--flavor', which parse-cmd rejects. Building the Whonix VirtualBox pair
## (gateway first, then workstation, for the unified .ova export) was therefore
## impossible from a single env-driven invocation.
##
## Behavioral: extracts the real resolution block from the shipped script (no
## drift) and evaluates it per input. No root, no network, no build.

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

subject="$(locate_help_step dm-build-official-one "${DM_BUILD_OFFICIAL_ONE:-}" "${test_dir}")" \
   || exit 1

## The whole flavors_list resolution: the 'if [ -n ... ]' through its closing 'fi'.
## '${flavors_list:-}' here is a LITERAL in the sed regex matching the script text,
## not a shell expansion.
# shellcheck disable=SC2016
block="$(sed -n '/^if \[ -n "${flavors_list:-}" \]; then$/,/^fi$/p' -- "${subject}")"
if [ -z "${block}" ]; then
   fail "could not extract the flavors_list resolution; the assertions below would prove nothing"
   printf '%s\n' "FAILED: extraction" >&2
   exit 1
fi

## Guard against sed over-reading past the block's closing 'fi' (the '^fi$' end
## anchor only matches a column-0 'fi', so an indented one would extend the range
## to the next column-0 'fi' and pull in later code the driver would then source).
## The 'flavor_built' helper is the construct immediately after the block, so its
## presence means the extraction over-read.
case "${block}" in
   *flavor_built*)
      fail "extraction over-read past the flavors_list block (indented 'fi'?); tighten the sed range"
      printf '%s\n' "FAILED: over-read" >&2
      exit 1
      ;;
esac

## Guard the guard: a silent revert that dropped the split would restore the
## '[ -n ] ||' one-liner and lose the 'read -r -a'. The behavioral case below
## catches it too, but pin it structurally so the intent is explicit.
case "${block}" in
   *'read -r -a flavors_list'*)
      true
      ;;
   *)
      fail "the resolution no longer splits a scalar flavors_list (no 'read -r -a'); a space-separated env value would be treated as one flavor"
      ;;
esac

work="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup_handler EXIT

printf '%s\n' "${block}" > "${work}/block.bash"
## HERMETIC driver: sets ONLY the one input the block reads (flavors_list), from
## its arg, or UNSETS it for the default-set case. Prints the resolved array's
## element count and its space-joined values so a caller asserts both.
cat > "${work}/driver.bash" <<'DRIVER'
set -o nounset
block="$1"
if [ "$2" = "__UNSET__" ]; then
   unset flavors_list 2>/dev/null || true
else
   flavors_list="$2"
fi
# shellcheck disable=SC1090
source "${block}"
printf '%s\n' "${#flavors_list[@]}"
printf '%s\n' "${flavors_list[*]}"
DRIVER

## $1 label, $2 expected count, $3 expected joined values, $4 input (omit -> unset).
check_case() {
   local label="$1" want_count="$2" want_values="$3" input="${4:-__UNSET__}"
   local out got_count got_values
   ## stdin from /dev/null: a malformed subject whose then-branch did a BARE
   ## 'read -r -a flavors_list' (no here-string) would otherwise consume the
   ## test's stdin instead of splitting the scalar, masking the bug.
   out="$(bash "${work}/driver.bash" "${work}/block.bash" "${input}" < /dev/null)"
   got_count="$(printf '%s\n' "${out}" | sed -n '1p')"
   got_values="$(printf '%s\n' "${out}" | sed -n '2p')"
   if [ "${got_count}" = "${want_count}" ] && [ "${got_values}" = "${want_values}" ]; then
      pass "${label}: ${got_count} item(s) [${got_values}]"
   else
      fail "${label}: got ${got_count} item(s) [${got_values}], want ${want_count} [${want_values}]"
   fi
}

## THE REGRESSION: a two-flavor scalar splits into two elements (old code: one).
check_case 'gateway+workstation pair splits into two flavors' \
   2 'whonix-gateway-lxqt whonix-workstation-lxqt' \
   'whonix-gateway-lxqt whonix-workstation-lxqt'

## A single flavor stays a single element.
check_case 'single flavor stays one flavor' \
   1 'kicksecure-ci-tiny-do-not-use' \
   'kicksecure-ci-tiny-do-not-use'

## CANARY: unset input must still fall back to the full default set, or a plain
## build would build nothing.
check_case 'unset falls back to the full default flavor set' \
   6 'kicksecure-lxqt kicksecure-cli whonix-gateway-lxqt whonix-workstation-lxqt whonix-gateway-cli whonix-workstation-cli'

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-build-official-one splits a scalar flavors_list into the flavor array."
