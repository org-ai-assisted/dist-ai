#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY: the shots harness must reap EVERY throwaway privileged
## remote_control drop-in THIS run created, and ONLY those -- marker-scoped, the same way
## shots_reap_run reaps process groups. Each drop-in filename embeds the run's marker tag;
## cleanup() sweeps by that tag.
##
## THE BUG IT GUARDS: demo_shots_capture (and zoom_verify_capture) declared the drop-in path
## in a LOCAL `rc_dropin`, shadowing the global the EXIT-trap cleanup() read, so their
## drop-ins were NEVER removed -- leaving root-owned `demo-shots-rc.*.conf`
## (remote_control=true) in /usr/local/etc/secure-terminal.d, which forced remote_control on
## for every later local ST run and spuriously failed test_modules / test_widget2. The fix
## drops the fragile per-lane path threading entirely and reaps by marker, so no lane can leak.
##
## Drives the SHIPPED functions: sources comparison-capture.sh source-safely, points its
## drop-in dir at a throwaway tree (SECURE_TERMINAL_SHOT_RC_DIR), stubs sudo to a passthrough,
## creates this-run + a FOREIGN-tagged drop-in, runs the reaper, and asserts only this run's
## drop-in died. FAILS if the reaper stops removing this run's drop-in (regression) or starts
## removing a concurrent run's (too-broad).
##
## No root, no network: it only ever touches its OWN mktemp tree. Run it in the sandbox.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## safe-rm (ships with private-ai-config) is the reaper's removal primitive; find enumerates
## the dir. Absent -> exit 1 (FATAL, R-220): a required tool is an environment bug, not a skip.
for dep in safe-rm find; do
   if ! type -P "${dep}" >/dev/null 2>&1; then
      printf '%s\n' "FATAL: rc_dropin_reap_test: required tool '${dep}' not found" >&2
      exit 1
   fi
done

## Resolve the subject (comparison-capture.sh) from the env override, a checkout sibling, or
## the installed path. Absent -> exit 1 (FATAL, R-220).
subject=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/comparison-capture.sh" \
   "${script_dir}/../secure-terminal-shots/comparison-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/comparison-capture.sh" \
   '/usr/share/secure-terminal-shots/comparison-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      subject="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' 'FATAL: comparison-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

workdir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup_test() { safe-rm --recursive --force -- "${workdir}" 2>/dev/null || true; }
trap cleanup_test EXIT

## Route the subject's drop-in dir at a throwaway tree, and neuter sudo (the drop-ins are
## root-owned in production; here the tree is ours, so sudo is an unprivileged passthrough).
export SECURE_TERMINAL_SHOT_RC_DIR="${workdir}/rc.d"
# shellcheck disable=SC2317  # invoked indirectly by the sourced subject functions
sudo() { "$@"; }

## Source the subject source-safely: its `was_executed ... || return 0` boundary stops before
## any capture set-up runs, leaving only the functions defined. run_marker_tag is NOT set by a
## sourced run (it is a direct-execution global), so the test provides it -- exactly the seam
## production sets at startup.
# shellcheck source=../secure-terminal-shots/comparison-capture.sh
source "${subject}"

run_marker_tag="reaptest-$$-${RANDOM}${RANDOM}"

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf 'PASS: %s\n' "$3"
      pass=$(( pass + 1 ))
   else
      printf 'FAIL: %s (got %s, want %s)\n' "$3" "$1" "$2" >&2
      fail=$(( fail + 1 ))
   fi
}

## 1. A lane creates its drop-in (demo-shots is the leak the bug was observed on). It must land
##    in the routed dir, carry this run's tag, and end in .conf (settings.py's glob).
shots_rc_dropin_create demo-shots-rc >/dev/null \
   || { printf '%s\n' 'FATAL: shots_rc_dropin_create failed under the sudo passthrough' >&2; exit 1; }
mine_count="$(find "${SECURE_TERMINAL_SHOT_RC_DIR}" -maxdepth 1 -type f \
   -name "demo-shots-rc.${run_marker_tag}.*.conf" 2>/dev/null | wc -l)"
check "${mine_count}" 1 "drop-in created, marker-tagged, .conf-suffixed in the routed dir"

## 2. A CONCURRENT run's drop-in: same dir, a DIFFERENT tag. The reaper must not touch it.
foreign="${SECURE_TERMINAL_SHOT_RC_DIR}/comparison-rc.otherrun-tag.ABCDEF.conf"
printf 'remote_control=true\n' > "${foreign}"

## 3. Reap THIS run (marker-scoped), exactly as cleanup() does.
shots_rc_dropin_reap_marked "${run_marker_tag}" || true

## THE REGRESSION: this run's drop-in must be GONE.
gone_count="$(find "${SECURE_TERMINAL_SHOT_RC_DIR}" -maxdepth 1 -type f \
   -name "demo-shots-rc.${run_marker_tag}.*.conf" 2>/dev/null | wc -l)"
check "${gone_count}" 0 "reaper removed THIS run's drop-in (no leaked remote_control=true)"

## THE MARKER SCOPE: the foreign-tagged drop-in must SURVIVE.
foreign_state='gone'
[ -f "${foreign}" ] && foreign_state='present'
check "${foreign_state}" present "reaper spared a concurrent run's differently-tagged drop-in"

if [ "${fail}" -gt 0 ]; then
   printf 'rc_dropin_reap_test: %s assertion(s) FAILED.\n' "${fail}" >&2
   exit 1
fi
printf 'rc_dropin_reap_test: OK (%s passed)\n' "${pass}"
