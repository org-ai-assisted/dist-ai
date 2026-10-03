#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-whonix-pair pure-logic unit tests (no VM): the fail-closed GW-trace canary (a leak MUST
## turn it red, a blind/missing capture MUST NOT read as a no-leak) and the battery run-command
## assembly (one short command on /mnt/shared under sudo -S, no inline script). Sources the real
## dm-whonix-pair (its source-guard keeps main() from running) with stubbed tcpdump/vbox-exec-local.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf 'FAIL: dm-whonix-pair not found at %s\n' "${tool}" >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Stub tcpdump: a "dst host" filter arg -> emit as many lines as STUB_DIR/hits; else (full
## read) STUB_DIR/total. Counts come from FILES (not subshell env) so canary can run in a
## die-catching subshell with no lost-subshell-var warning.
cat > "${work}/tcpdump" <<'STUB'
#!/bin/bash
has_filter=0
for a in "$@"; do case "$a" in *"dst host"*) has_filter=1 ;; esac; done
f="${STUB_DIR}/total"
[ "${has_filter}" = 1 ] && f="${STUB_DIR}/hits"
n="$(cat -- "${f}" 2>/dev/null || printf 0)"
i=0
while [ "${i}" -lt "${n}" ]; do
   printf 'pkt\n'
   i=$(( i + 1 ))
done
STUB
chmod +x "${work}/tcpdump"
export STUB_DIR="${work}"

## Stub vbox-exec-local: echo its args so ws_battery's assembled --cmd is captured.
cat > "${work}/vbe" <<'STUB'
#!/bin/bash
printf '%s\n' "$*"
STUB
chmod +x "${work}/vbe"

## Override the tool's externals BEFORE sourcing; the source-guard keeps main() from running.
export TCPDUMP="${work}/tcpdump"
export VBOX_EXEC_LOCAL="${work}/vbe"
# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf 'PASS: %s\n' "$1"; else fail=$(( fail + 1 )); printf 'FAIL: %s\n' "$1"; fi }
check_fail() { if [ "$2" -ne 0 ]; then pass=$(( pass + 1 )); printf 'PASS: %s\n' "$1"; else fail=$(( fail + 1 )); printf 'FAIL: %s (rc=0, wanted nonzero)\n' "$1"; fi }
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## --- canary_gateway_pcap: fail-closed ------------------------------------------------------
nictrace_pcap="${work}/pcap"
printf 'x\n' > "${nictrace_pcap}"   ## non-empty so the [ -s ] guard passes

set_counts() { printf '%s\n' "$1" > "${work}/total"; printf '%s\n' "$2" > "${work}/hits"; }

set_counts 7 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check 'canary clean (traffic present, 0 hits to any probe target) -> PASS' "${rc}"

set_counts 7 3
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check_fail 'canary CATCHES a leak (a probe target on the wire) -> nonzero (NO silent green)' "${rc}"

set_counts 0 0
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check_fail 'canary blind capture (pcap empty of traffic) -> nonzero (not a false no-leak)' "${rc}"

nictrace_pcap="${work}/does-not-exist"
rc=0; ( canary_gateway_pcap ) >/dev/null 2>&1 || rc=$?
check_fail 'canary missing pcap -> nonzero (fail-closed)' "${rc}"
nictrace_pcap="${work}/pcap"

## --- ws_battery: one short command on /mnt/shared, no inline script -------------------------
out="$(ws_battery '--probe tor-confirm')"
rc=0; has "sudo -S -p '' python3 -Bsu ${GUEST_SHARE_MOUNT}/anon-leak-test --probe tor-confirm --json" "${out}" || rc=$?
check 'ws_battery: runs the battery on /mnt/shared under sudo -S (no copyto, no inline script)' "${rc}"
rc=0; has '| sudo -S' "${out}" || rc=$?
check 'ws_battery: pipes the password to sudo -S' "${rc}"

printf '\n%s: %s pass, %s fail\n' "$(basename -- "$0")" "${pass}" "${fail}"
[ "${fail}" -eq 0 ] || exit 1
exit 0
