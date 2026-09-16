#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Neutrality gate for a 'help-steps/variables' PRODUCER rewrite (file split,
## helper reuse, declaration block, effect relocation): such a refactor
## legitimately changes internal temporaries and non-consumed function bodies, so
## the full 'declare -p' snapshot (varname_snapshot_test.sh) is not its gate. THIS
## is: the EXPORTED contract -- every exported variable (name + normalized value)
## per build command, plus the bodies of the functions build steps actually call,
## plus the flavor x target validity matrix. Frozen from the pre-refactor tree; a
## rewrite is contract-neutral iff this stays byte-identical.
##
## Also asserts the hand-maintained consumed-function list has not silently drifted
## from the set of functions actually called outside the resolution machinery.
##
## Drives the real generator + shared derivation library, so it cannot drift from
## how the contract is produced. Needs a derivative-maker checkout
## (DERIVATIVE_MAKER_DIR, else ~/derivative-maker); no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

## Host/local-only, same rationale as varname_snapshot_test.sh: the committed
## goldens are dev-generated and CI's environment (workspace path != $HOME/checkout,
## absent ~/buildconfig.d, CI-only vars, cowbuilder config) cannot match a
## dev-generated snapshot after normalization.
if [ "${CI:-}" = "true" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
   printf '%s\n' "SKIP: contract_snapshot is host/local-only -- run it on a dev checkout to validate a 'variables' producer refactor; CI's environment cannot match a dev-generated snapshot." >&2
   ## style-ok: allow-skip: host/local-only -- committed goldens are dev-generated and CI's environment diverges (workspace paths, absent ~/buildconfig.d, CI vars); same authorization as varname_snapshot_test.sh, operator 2026-09-15
   exit 77
fi

# shellcheck source=./varname_snapshot_lib.bsh
source "${test_dir}/varname_snapshot_lib.bsh"

committed_dir="${test_dir}/varname-contract-snapshots"
if [ ! -d "${committed_dir}" ]; then
   printf '%s\n' "FATAL: committed contract goldens not found at '${committed_dir}'." >&2
   exit 1
fi

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

dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
if [ ! -r "${dm_checkout}/help-steps/variables" ]; then
   printf '%s\n' "FATAL: derivative-maker checkout not found at '${dm_checkout}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

full_dir="$(mktemp -d)"
contract_dir="$(mktemp -d)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${full_dir}" "${contract_dir}"
}
trap cleanup EXIT

printf '%s\n' "INFO: regenerating snapshots from '${dm_checkout}' into a temp dir ..."
if ! DERIVATIVE_MAKER_DIR="${dm_checkout}" "${generator}" "${full_dir}" >/dev/null; then
   printf '%s\n' "FAIL: dm-varname-snapshot failed to regenerate (see its output above)." >&2
   exit 1
fi

## Guard the hand-maintained consumed-function list against silent drift BEFORE the
## contract diff, so a gained/lost external caller is reported as its own actionable
## failure rather than as a puzzling body diff.
if ! vs_assert_consumed_complete "${dm_checkout}" "${full_dir}/functions.snapshot"; then
   printf '%s\n' "" >&2
   printf '%s\n' "FAIL: vs_consumed_funcs in varname_snapshot_lib.bsh no longer matches the" >&2
   printf '%s\n' "      functions called outside the resolution machinery (diff above). Update" >&2
   printf '%s\n' "      the list and re-freeze the contract goldens (dm-varname-snapshot --contract)." >&2
   exit 1
fi

vs_derive_contract "${full_dir}" "${contract_dir}"

## The single assertion: committed contract == freshly derived contract.
if diff --recursive --unified -- "${committed_dir}" "${contract_dir}"; then
   printf '%s\n' "PASS: the exported contract matches the live derivative-maker checkout."
   exit 0
fi

printf '%s\n' "" >&2
printf '%s\n' "FAIL: the committed exported contract no longer matches derivative-maker's" >&2
printf '%s\n' "      'help-steps/variables'. An exported variable, a consumed-function body, or" >&2
printf '%s\n' "      a combo's validity changed -- i.e. the build-facing contract moved, which a" >&2
printf '%s\n' "      producer refactor must NOT do. Investigate the diff above. If the change is" >&2
printf '%s\n' "      genuinely intended, re-freeze with:" >&2
printf '%s\n' "        DERIVATIVE_MAKER_DIR='${dm_checkout}' dm-varname-snapshot --contract" >&2
exit 1
