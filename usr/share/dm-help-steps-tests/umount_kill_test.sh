#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for derivative-maker 'help-steps/umount_kill.sh' (the
## /proc-based process reaper that runs after cowbuilder chroot sessions and
## before unmounts).
##
## Asserts BOTH directions:
##
##   kills what it is supposed to kill -- one victim per detection channel:
##     - cwd inside a subdirectory of the target tree
##     - an open file descriptor under the tree
##     - an mmap-only user (file mapped, descriptor closed afterwards)
##     - an executable image run from inside the tree ('exe' link)
##     - a process chrooted INTO the tree ('root' link; the production case:
##       a lingering 'VBoxSVC' of a cowbuilder chroot session)
##     - a SIGTERM-ignoring process (must fall through the grace period to
##       the SIGKILL escalation)
##
##   does NOT kill anything else:
##     - an unrelated process (cwd outside the tree)
##     - a process using a SIBLING tree whose name is a string-prefix
##       collision of the target ('<target>2'), holding cwd + fd + mmap
##       there (regression test for the maps prefix-collision finding)
##
##   guards:
##     - nonexistent target path: exit 0, no scan
##     - '/': refused, exit 1
##     - skip-list basename (e.g. 'proc'): exit 0, no scan
##
## Every process this test starts is tracked and cleaned up on exit; the
## reaper only ever runs against freshly created 'mktemp' trees, so a bug in
## the test cannot direct it at real system paths. Nevertheless: this test
## MUST run as root (umount_kill.sh refuses otherwise) and it exercises a
## process KILLER -- run it in a sandbox VM, not on the operator's machine:
##
##   sandbox-run --dir <staged-dir> -- sudo ./umount_kill_test.sh
##
## Subject selection (first that exists):
##   $UMOUNT_KILL_SH  ->  ./umount_kill.sh next to this test (staged copy)
##   ->  ~/derivative-maker/help-steps/umount_kill.sh (source checkout)

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_failures=0
test_pid_list=()

pass() {
   printf '%s\n' "PASS: $*"
}

fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## Kill every process this test started (victims that were supposed to die
## are already gone; bystanders and leftovers from a failed assertion are
## not). SIGKILL is fine here: these are the test's own throwaway 'sleep'
## style processes.
cleanup_test_processes() {
   local cleanup_pid

   for cleanup_pid in "${test_pid_list[@]}"; do
      kill -s KILL -- "${cleanup_pid}" 2>/dev/null || true
   done
}

trap cleanup_test_processes EXIT

locate_subject() {
   local test_dir checkout

   if [ -n "${UMOUNT_KILL_SH:-}" ]; then
      printf '%s\n' "${UMOUNT_KILL_SH}"
      return 0
   fi
   test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
   if [ -r "${test_dir}/umount_kill.sh" ]; then
      printf '%s\n' "${test_dir}/umount_kill.sh"
      return 0
   fi
   checkout="${HOME}/derivative-maker/help-steps/umount_kill.sh"
   if [ -r "${checkout}" ]; then
      printf '%s\n' "${checkout}"
      return 0
   fi
   ## 77 = SKIP by dist-ai suite convention (target not found, not a failure).
   printf '%s\n' "SKIP: umount_kill.sh not found (set UMOUNT_KILL_SH)." >&2
   exit 77
}

## Copy a dynamically linked binary plus every library 'ldd' resolves for it
## into the tree, preserving absolute paths, so 'chroot <tree> <binary>'
## works. Used to create the chrooted victim.
stage_chroot_binary() {
   local tree binary ldd_output ldd_line ldd_word

   tree="$1"
   binary="$2"
   mkdir --parents -- "${tree}$(dirname -- "${binary}")"
   cp -- "${binary}" "${tree}${binary}"
   ldd_output="$(ldd -- "${binary}")"
   while IFS="" read -r ldd_line; do
      for ldd_word in ${ldd_line}; do
         case "${ldd_word}" in
            /*)
               mkdir --parents -- "${tree}$(dirname -- "${ldd_word}")"
               cp -- "${ldd_word}" "${tree}${ldd_word}"
               ;;
         esac
      done
   done <<< "${ldd_output}"
}

require_alive() {
   local check_pid description

   check_pid="$1"
   description="$2"
   if kill -0 -- "${check_pid}" 2>/dev/null; then
      pass "still alive (must survive): ${description}"
   else
      fail "was killed but must survive: ${description}"
   fi
}

require_dead() {
   local check_pid description

   check_pid="$1"
   description="$2"
   if kill -0 -- "${check_pid}" 2>/dev/null; then
      fail "still alive but must be killed: ${description}"
   else
      pass "killed as required: ${description}"
   fi
}

main() {
   local subject scratch_base target_tree sibling_tree run_output
   local victim_cwd_pid victim_fd_pid victim_mmap_pid victim_exe_pid
   local victim_chroot_pid victim_stubborn_pid
   local bystander_unrelated_pid bystander_sibling_pid
   local guard_exit_code quiet_attempt quiet_reached

   ## 77 = SKIP by dist-ai suite convention: an unprivileged or
   ## tooling-incomplete environment is not a test failure. CI runs this
   ## suite as the container's root.
   if [ ! "${EUID}" = "0" ]; then
      printf '%s\n' "SKIP: this test must run as root (umount_kill.sh requires it)." >&2
      exit 77
   fi

   subject="$(locate_subject)"
   printf '%s\n' "INFO: subject: ${subject}"

   ## python3 presence check for the mmap-only victim. Use 'type -P' (a bash
   ## builtin) rather than helper-scripts 'has': this suite also runs where
   ## helper-scripts is not installed (e.g. the CI container), so sourcing
   ## /usr/libexec/helper-scripts/has.sh would abort the test under errexit
   ## instead of SKIPping. 'type -P' is not 'command -v', so R-090 is satisfied.
   if ! type -P python3 >/dev/null; then
      printf '%s\n' "SKIP: python3 is required (mmap-only victim)." >&2
      exit 77
   fi

   scratch_base="$(mktemp --directory)"
   ## '<target>2' is a deliberate string-prefix collision of the target.
   target_tree="${scratch_base}/umk-target"
   sibling_tree="${scratch_base}/umk-target2"
   mkdir --parents -- "${target_tree}/sub" "${sibling_tree}/sub"
   dd if=/dev/zero of="${target_tree}/sub/mapme.bin" bs=4096 count=1 status=none
   dd if=/dev/zero of="${sibling_tree}/sub/mapme.bin" bs=4096 count=1 status=none

   ## ---- victims (must die) ----

   ( cd -- "${target_tree}/sub" && sleep 300 ) &
   victim_cwd_pid="$!"

   sleep 300 > "${target_tree}/sub/held.log" &
   victim_fd_pid="$!"

   python3 -c "
import mmap, os, time, sys
f = open(sys.argv[1], 'r+b')
m = mmap.mmap(f.fileno(), 4096)
f.close()
os.chdir('/')
time.sleep(300)" "${target_tree}/sub/mapme.bin" &
   victim_mmap_pid="$!"

   ## 'exe' channel: run a binary copied INTO the tree, cwd outside. The tracked
   ## pid is the subshell (cwd '/', exe /bin/bash -- both outside the tree, so the
   ## reaper does not match it directly); the reaper matches its child sleep-copy
   ## by exe-inside-tree and kills it, after which the subshell exits too. The
   ## require_dead assertion below still holds.
   mkdir --parents -- "${target_tree}/bin"
   cp -- "$(type -P sleep)" "${target_tree}/bin/sleep-copy"
   ( cd / && "${target_tree}/bin/sleep-copy" 300 ) &
   victim_exe_pid="$!"

   ## 'root' channel: the production case, a process chrooted into the tree.
   stage_chroot_binary "${target_tree}" "$(type -P sleep)"
   chroot -- "${target_tree}" "$(type -P sleep)" 300 &
   victim_chroot_pid="$!"

   ## SIGTERM-ignoring victim: must survive the grace period and die only
   ## by the SIGKILL escalation.
   bash -c "cd -- '${target_tree}/sub'; trap '' TERM; while true; do sleep 1; done" &
   victim_stubborn_pid="$!"

   ## ---- bystanders (must survive) ----

   ( cd / && sleep 300 ) &
   bystander_unrelated_pid="$!"

   python3 -c "
import mmap, os, time, sys
f = open(sys.argv[1], 'r+b')
m = mmap.mmap(f.fileno(), 4096)
os.chdir(os.path.dirname(sys.argv[1]))
time.sleep(300)" "${sibling_tree}/sub/mapme.bin" &
   bystander_sibling_pid="$!"

   test_pid_list=(
      "${victim_cwd_pid}" "${victim_fd_pid}" "${victim_mmap_pid}"
      "${victim_exe_pid}" "${victim_chroot_pid}" "${victim_stubborn_pid}"
      "${bystander_unrelated_pid}" "${bystander_sibling_pid}"
   )

   ## Drop the background jobs from job control so bash does not print an
   ## asynchronous 'Killed' notice when the reaper takes a victim down;
   ## cleanup and the assertions address them by stored PID, not by job.
   disown -a

   ## Let every process reach its steady state (python needs to finish the
   ## mmap + close; the chroot needs to exec).
   sleep 2

   ## ---- run the subject against the target tree ----

   run_output="$(bash "${subject}" "${target_tree}" 2>&1)" || {
      fail "umount_kill.sh exited non-zero against '${target_tree}'"
      printf '%s\n' "${run_output}"
   }

   ## The kernel needs a moment to reap the SIGKILLed stubborn victim.
   sleep 1

   require_dead "${victim_cwd_pid}"      "cwd-in-subdirectory victim"
   require_dead "${victim_fd_pid}"       "open-fd-under-tree victim"
   require_dead "${victim_mmap_pid}"     "mmap-only victim (fd closed)"
   require_dead "${victim_exe_pid}"      "exe-image-inside-tree victim"
   require_dead "${victim_chroot_pid}"   "chrooted-into-tree victim (root link)"
   require_dead "${victim_stubborn_pid}" "SIGTERM-ignoring victim (SIGKILL escalation)"

   require_alive "${bystander_unrelated_pid}" "unrelated bystander"
   require_alive "${bystander_sibling_pid}"   "sibling string-prefix tree bystander (cwd + fd + mmap)"

   if printf '%s\n' "${run_output}" | grep --quiet --fixed-strings -- "survived SIGTERM"; then
      pass "SIGKILL escalation path was exercised (stubborn victim reported)"
   else
      fail "expected the 'survived SIGTERM' escalation report in the output"
   fi

   ## ---- follow-up runs: tree must converge to quiet ----

   ## The stubborn victim's loop respawns short-lived 'sleep 1' children; an
   ## orphan spawned between the reaper's re-detection and its kill can
   ## straggle for up to a second (and is then correctly reported by the
   ## next run). Assert convergence rather than instant quiet. A quiet run
   ## exits 0 and prints NO kill report (its "no pids still running" line is
   ## a 'true' xtrace-only message, so quiet output is empty).
   quiet_reached=false
   for quiet_attempt in 1 2 3; do
      run_output="$(bash "${subject}" "${target_tree}" 2>&1)" || {
         fail "follow-up run ${quiet_attempt} exited non-zero"
      }
      if ! printf '%s\n' "${run_output}" | grep --quiet --fixed-strings -- "will now be killed"; then
         quiet_reached=true
         break
      fi
      sleep 2
   done
   if [ "${quiet_reached}" = "true" ]; then
      pass "tree converged to quiet (no kill report, attempt ${quiet_attempt})"
   else
      fail "tree did not converge to quiet within 3 runs"
      printf '%s\n' "DEBUG: last follow-up run output follows:"
      printf '%s\n' "${run_output}"
   fi

   ## ---- guards ----

   guard_exit_code=0
   bash "${subject}" "${scratch_base}/does-not-exist" >/dev/null 2>&1 || guard_exit_code="$?"
   if [ "${guard_exit_code}" = "0" ]; then
      pass "nonexistent target: exit 0 (skip)"
   else
      fail "nonexistent target: expected exit 0, got ${guard_exit_code}"
   fi

   guard_exit_code=0
   bash "${subject}" "/" >/dev/null 2>&1 || guard_exit_code="$?"
   if [ ! "${guard_exit_code}" = "0" ]; then
      pass "target '/': refused (exit ${guard_exit_code})"
   else
      fail "target '/': expected refusal, got exit 0"
   fi

   mkdir --parents -- "${scratch_base}/proc"
   guard_exit_code=0
   bash "${subject}" "${scratch_base}/proc" >/dev/null 2>&1 || guard_exit_code="$?"
   if [ "${guard_exit_code}" = "0" ]; then
      pass "skip-list basename 'proc': exit 0 (skip)"
   else
      fail "skip-list basename 'proc': expected exit 0, got ${guard_exit_code}"
   fi

   ## ---- summary ----

   safe-rm --recursive --force -- "${scratch_base}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all umount_kill.sh assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
