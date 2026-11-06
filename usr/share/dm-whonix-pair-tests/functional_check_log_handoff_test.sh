#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## #1/#3: the functional lane's forensic check-log is CALLER-owned (dm-release-test creates,
## reads + reclaims it), mirroring the kicksecure lane. dm-whonix-pair must (a) accept
## --check-log and (b) NOT unlink it in on_exit. Canary: the pre-fix code rejects --check-log
## (die SETUP_RC) and on_exit deletes the file.

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

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## on_exit issues best-effort VBoxManage calls; stub them to no-ops.
cat > "${work}/VBoxManage" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x "${work}/VBoxManage"
export VBOXMANAGE="${work}/VBoxManage"

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
assert() { local label="$1"; shift; if "$@"; then pass=$(( pass + 1 )); printf '%s\n' "PASS: ${label}"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${label}"; fi; }

## (a) --check-log is accepted and sets the global.
mode='leak'
parse_args --mode functional --check-log "${work}/cl.log"
assert "--check-log sets check_log" test "${check_log}" = "${work}/cl.log"

## (b) on_exit must NOT unlink a caller-provided check_log. Nothing was started; empty the
## other reclaimable globals so on_exit's guards skip them.
keep="${work}/keep.log"
printf '%s\n' 'failed check output' > "${keep}"
ws_started='false'
gw_started='false'
share_dir=''
nictrace_pcap=''
gw_relay_cache=''
check_log="${keep}"
( on_exit ) >/dev/null 2>&1 || true
assert "on_exit does not unlink the caller-owned check_log" test -f "${keep}"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
