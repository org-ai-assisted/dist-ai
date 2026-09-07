#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drift test for the derivative-maker variable snapshots: regenerate them from
## the live derivative-maker checkout and require the result to match the
## committed 'varname-snapshots/' byte-for-byte. It is the safety net for a large
## 'help-steps/variables' refactoring -- if the refactor drops, renames, or
## changes any variable a build command sets (or changes which combos are valid),
## the regenerated snapshot diverges and this test fails with the exact diff.
##
## Because every machine-, clock-, and checkout-varying value is normalized to a
## placeholder (see varname_snapshot_lib.bsh), a match is meaningful: only a real
## change to what 'variables' sets can move the output.
##
## It drives the real generator ('dm-varname-snapshot') into a temp directory and
## diffs, so the test cannot drift from how the snapshots are produced.
##
## Needs a derivative-maker checkout (DERIVATIVE_MAKER_DIR, else ~/derivative-maker);
## no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

committed_dir="${test_dir}/varname-snapshots"
if [ ! -d "${committed_dir}" ]; then
   printf '%s\n' "FATAL: committed snapshots not found at '${committed_dir}'." >&2
   exit 1
fi

## Locate the generator: checkout layout (usr/bin beside usr/share), then the
## installed tree.
generator=""
for candidate in \
   "${test_dir}/../../bin/dm-varname-snapshot" \
   "/usr/bin/dm-varname-snapshot"; do
   if [ -x "${candidate}" ]; then
      generator="${candidate}"
      break
   fi
done
if [ -z "${generator}" ]; then
   printf '%s\n' "FATAL: dm-varname-snapshot generator not found." >&2
   exit 1
fi

## Resolve the derivative-maker checkout the same way the generator does; a
## missing checkout is a hard error, not a skip (a test that cannot run has
## verified nothing).
dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
if [ ! -r "${dm_checkout}/help-steps/variables" ]; then
   printf '%s\n' "FATAL: derivative-maker checkout not found at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

fresh_dir="$(mktemp -d)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${fresh_dir}"
}
trap cleanup EXIT

printf '%s\n' "INFO: regenerating snapshots from '${dm_checkout}' into a temp dir ..."
if ! DERIVATIVE_MAKER_DIR="${dm_checkout}" "${generator}" "${fresh_dir}" >/dev/null; then
   printf '%s\n' "FAIL: dm-varname-snapshot failed to regenerate (see its output above)." >&2
   exit 1
fi

## The single assertion: committed == freshly regenerated. Any difference -- a
## changed value, an added/removed variable, a combo that flipped between valid
## and rejected, or a hand-edited snapshot -- shows up here as a unified diff.
if diff --recursive --unified -- "${committed_dir}" "${fresh_dir}"; then
   printf '%s\n' "PASS: committed variable snapshots match the live derivative-maker checkout."
   exit 0
fi

printf '%s\n' "" >&2
printf '%s\n' "FAIL: the committed variable snapshots no longer match derivative-maker's" >&2
printf '%s\n' "      'help-steps/variables'. If this change is intended, regenerate them with:" >&2
printf '%s\n' "        DERIVATIVE_MAKER_DIR='${dm_checkout}' dm-varname-snapshot" >&2
printf '%s\n' "      and commit the updated varname-snapshots/ files. Otherwise the refactor" >&2
printf '%s\n' "      changed which variables a build command sets -- investigate the diff above." >&2
exit 1
