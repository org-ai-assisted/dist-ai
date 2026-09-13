#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-varname-snapshot's FINAL swap: publishing the staged baseline into
## out_dir must never leave out_dir in a removed-but-not-replaced state.
##
## THE BUG IT GUARDS: the swap did 'safe-rm out_dir/*' THEN 'mv stage/* out_dir/'.
## An interruption between the two -- or any swap that cannot complete -- left the
## committed baseline deleted and not yet replaced, i.e. destroyed. The fix renames
## each staged file OVER its counterpart (rename(2) replaces atomically, no rm
## first) and prunes stale combos only AFTER the new set is fully in place.
##
## Method: extract the SHIPPED swap block and drive it with a pre-seeded out_dir
## baseline and a stage dir that is missing one output (functions.snapshot), so the
## swap cannot fully complete -- exactly the interrupted-swap case. A correct
## (replace-in-place) swap leaves every not-yet-replaced baseline file intact; the
## old rm-then-mv wipes the baseline up front and loses it.
##
## No root, no network, no derivative-maker checkout.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

## Locate the generator: checkout layout (usr/bin beside usr/share), then installed.
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

workdir="$(mktemp -d)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT

## Extract the swap block: every line AFTER the functions.snapshot write, UP TO the
## closing INFO line. That is the whole "publish the staged set into out_dir" logic,
## and nothing else. Drives the SHIPPED code so a regression fails here.
slice_file="${workdir}/swap.bash"
awk '
   /> "\${stage_dir}\/functions.snapshot"/ { grab = 1; next }
   /INFO: wrote / { grab = 0 }
   grab { print }
' "${generator}" > "${slice_file}"
if ! grep --quiet 'stage_dir' "${slice_file}" || ! grep --quiet 'out_dir' "${slice_file}"; then
   printf '%s\n' "FATAL: could not extract the swap block; the slice is wrong, not the code" >&2
   exit 1
fi

## Pre-seed out_dir with a committed baseline (one obsolete combo + _rejected +
## functions.snapshot). stage holds a NEW set but is MISSING functions.snapshot, so
## the swap cannot complete -- the interrupted-swap case.
out_dir="${workdir}/varname-snapshots"
stage_dir="${workdir}/stage"
mkdir --parents -- "${out_dir}" "${stage_dir}"
printf 'OLD-vars\n'      > "${out_dir}/kicksecure-cli__raw.vars"
printf 'OLD-rejected\n'  > "${out_dir}/_rejected.txt"
printf 'OLD-functions\n' > "${out_dir}/functions.snapshot"
printf 'NEW-vars\n'      > "${stage_dir}/kicksecure-cli__raw.vars"
printf 'NEW-rejected\n'  > "${stage_dir}/_rejected.txt"
## functions.snapshot deliberately absent from stage.

## Run the shipped swap block; it is expected to fail (incomplete stage). The
## point is what it leaves behind, not its exit status.
## out_dir and stage_dir are inherited by this subshell from the parent above.
swap_rc=0
(
   # shellcheck disable=SC1090  # sourcing an extracted slice by design
   source "${slice_file}"
) >/dev/null 2>&1 || swap_rc=$?

failures=0

## The invariant: functions.snapshot never got its replacement, so the OLD baseline
## copy must still be there -- an atomic replace-in-place never removes it. The old
## rm-then-mv deletes it up front and never restores it.
if [ -f "${out_dir}/functions.snapshot" ]; then
   printf 'PASS: baseline functions.snapshot survived the incomplete swap (swap rc %s)\n' "${swap_rc}"
else
   printf 'FAIL: functions.snapshot was removed-but-not-replaced by the swap (swap rc %s)\n' "${swap_rc}" >&2
   failures=$((failures + 1))
fi

## Sanity: the files that DID have a staged replacement were updated (proves the
## swap actually ran, so the survival above is not a vacuous no-op).
if [ "$(cat -- "${out_dir}/kicksecure-cli__raw.vars" 2>/dev/null)" = "NEW-vars" ]; then
   printf 'PASS: the swap replaced the files it had staged\n'
else
   printf 'FAIL: the swap did not replace .vars from the stage (extraction wrong?)\n' >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
   printf 'varname_snapshot_atomic_swap_test: %s assertion(s) FAILED.\n' "${failures}" >&2
   exit 1
fi
printf 'varname_snapshot_atomic_swap_test: OK\n'
