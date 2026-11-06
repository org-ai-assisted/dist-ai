#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## #5: the functional lane's dm-vm-lock TTL must cover the full numbered battery (per-check
## budgets sum to ~2430s, check 3 alone is 1800s), so it exceeds the lighter leak default.
## Canary: the pre-fix code has no lock_ttl_default (a single hard-coded 2400s for both modes).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## DM_WHONIX_PAIR_BIN overrides the subject (the canary points it at a pre-fix export).
tool="${DM_WHONIX_PAIR_BIN:-${here}/../../bin/dm-whonix-pair}"
[ -x "${tool}" ] || { printf '%s\n' "FATAL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
assert() { local label="$1"; shift; if "$@"; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${label}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${label}"; fi; }

func_ttl="$(lock_ttl_default functional)"
leak_ttl="$(lock_ttl_default leak)"
assert "functional TTL > leak TTL" test "${func_ttl}" -gt "${leak_ttl}"
## >= the battery budget sum (2430s at writing); the headroom makes it strictly larger.
assert "functional TTL covers the battery budget (>=2430)" test "${func_ttl}" -ge 2430
assert "leak TTL stays the lighter 2400" test "${leak_ttl}" -eq 2400

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
