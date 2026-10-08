#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Contract test for helper-scripts try-wait-for-privleap-socket-ready.
##
## The novel logic is the wait LOOP, which must:
##  - re-probe EVERY iteration (never trust a cached verdict), so a socket that
##    becomes connectable only on a later attempt is still detected -- this is
##    the whole point: privleapd's per-user comm socket is created out of band by
##    leapctl@<uid>.service and can appear a beat after systemcheck starts;
##  - return 0 as soon as use_leaprun flips to 'yes';
##  - be bounded by privleap_socket_wait_max_ctr and still return 0 (best-effort)
##    when the socket never becomes reachable, so the consumer falls through to
##    its own privleap-unusable diagnosis.
##
## Drives the REAL script by SOURCING it (the was_executed guard suppresses its
## main, so sourcing only defines the pure function), then exercises
## try_wait_for_privleap_socket_ready with the readiness oracle
## (leaprun_useable_test, whose real [ -S ] + socat connect probe is already
## covered by the use_leaprun_* suites) and time (light_sleep, covered by its own
## suite) stubbed. No root, no socket, no systemd.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/try-wait-for-privleap-socket-ready"
else
   subject='/usr/libexec/helper-scripts/try-wait-for-privleap-socket-ready'
fi
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}' (set HELPER_SCRIPTS_REPO)." >&2
   exit 1
fi

## The subject resolves check_runtime.bsh (provides was_executed) through
## HELPER_SCRIPTS_PATH; empty -> the installed /usr/libexec, same as production.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

pass_count=0
fail_count=0
pass() { pass_count=$((pass_count + 1)); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$((fail_count + 1)); printf '%s\n' "FAIL: $*" >&2; }

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## Sourcing defines the pure function without running main: was_executed sees
## BASH_SOURCE[0] (the subject) != $0 (this test), so main is skipped.
# shellcheck disable=SC1090
source "${subject}"

if ! declare -F try_wait_for_privleap_socket_ready >/dev/null; then
   printf '%s\n' "FATAL: sourcing the subject did not define try_wait_for_privleap_socket_ready" >&2
   exit 1
fi

## Readiness oracle stub: use_leaprun flips to 'yes' once probe_calls reaches
## leaprun_ready_on_call (0 = never). probe_calls counts the re-probes, so a
## consumer that stopped re-probing would be caught by the call-count assert.
## use_leaprun is read by the sourced subject across the 'source' boundary
## (dynamic scope), so the consumer is not visible in this file; export marks it
## used (and silences SC2034) without a blanket disable.
export use_leaprun='no'
leaprun_ready_on_call=0
probe_calls=0
leaprun_useable_test() {
   probe_calls=$((probe_calls + 1))
   if [ "${leaprun_ready_on_call}" -ne 0 ] \
      && [ "${probe_calls}" -ge "${leaprun_ready_on_call}" ]; then
      use_leaprun='yes'
   else
      use_leaprun='no'
   fi
}
## Use the REAL light_sleep (skipped), not a stub: a stub returning 0 could hide
## a subject that misuses light_sleep (the real one returns non-zero on a missing
## duration, which under production errexit would abort the wait).
# shellcheck disable=SC1090,SC1091
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/light_sleep.bsh
export light_sleep_skip='true'

## Reachable on the first probe -> returns 0 after exactly one probe.
use_leaprun='no'
probe_calls=0
leaprun_ready_on_call=1
rc=0
privleap_socket_wait_max_ctr=5 try_wait_for_privleap_socket_ready || rc="$?"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '1' ]; then
   pass "reachable immediately -> exit 0 after 1 probe"
else
   fail "reachable immediately -> rc=${rc}, probes=${probe_calls} (want 0, 1)"
fi

## Becomes reachable only on the 3rd probe -> returns 0 after exactly 3 probes.
## REGRESSION: code that checked a cached use_leaprun once (no re-probe) would
## never see the flip and would bound out instead -> probes != 3.
use_leaprun='no'
probe_calls=0
leaprun_ready_on_call=3
rc=0
privleap_socket_wait_max_ctr=10 try_wait_for_privleap_socket_ready || rc="$?"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '3' ]; then
   pass "reachable on 3rd probe -> exit 0 after exactly 3 probes (re-probes each iteration)"
else
   fail "re-probe -> rc=${rc}, probes=${probe_calls} (want 0, 3)"
fi

## Never reachable -> returns 0 (best-effort) after exactly max_ctr probes.
use_leaprun='no'
probe_calls=0
leaprun_ready_on_call=0
rc=0
privleap_socket_wait_max_ctr=4 try_wait_for_privleap_socket_ready || rc="$?"
if [ "${rc}" = '0' ] && [ "${probe_calls}" = '4' ]; then
   pass "never reachable -> exit 0 after max_ctr (4) probes (bounded best-effort)"
else
   fail "bound-out -> rc=${rc}, probes=${probe_calls} (want 0, 4)"
fi

## Errexit contract: the standalone main() calls this under 'set -o errexit', so
## a never-ready run must RETURN (0), not abort on an internal command (an
## unguarded (( )) or a failing probe/sleep). errexit is IGNORED inside a
## compound used as an if-condition (or in a '&&'/'||' list), so an in-process
## 'if ( set -o errexit; ... )' would assert NOTHING -- the inner set has no
## effect there and any internal abort is masked. Assert the contract in a real
## child 'bash' where errexit is set at top level and the function runs as a
## plain command. Mirror main()'s full preamble and use the REAL light_sleep
## (skipped): a sleep STUB would hide a subject that misuses light_sleep (the
## real one returns non-zero on a missing duration -> errexit abort).
errexit_probe="${work_dir}/errexit-probe.bash"
cat > "${errexit_probe}" <<'PROBE'
#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C
source "${SUBJECT}"
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/light_sleep.bsh
export light_sleep_skip='true'
## Never-ready readiness oracle (the real one needs a live socket).
export use_leaprun='no'
leaprun_useable_test() { use_leaprun='no'; }
privleap_socket_wait_max_ctr=3 try_wait_for_privleap_socket_ready
PROBE
rc=0
SUBJECT="${subject}" bash "${errexit_probe}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" = '0' ]; then
   pass "never-ready run returns cleanly under errexit (child process, does not abort)"
else
   fail "aborted under errexit (rc=${rc})"
fi

printf '%s\n' ""
printf '%s\n' "===== try_wait_for_privleap_socket_ready: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
