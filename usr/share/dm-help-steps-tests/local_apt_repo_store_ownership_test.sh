#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/local-apt-repo-store.bsh'
## local_apt_repo_store_ensure (sourced + called by
## build-steps.d/1200_prepare-build-machine's local_apt_repo_store_setup).
##
## CONTRACT. For EVERY input state the store (local_apt_repository_base, default
## /srv/derivative-maker) must end up:
##   - a REAL directory, NEVER a symlink and never a non-directory -- reprepro
##     writes the store UNPRIVILEGED; a symlink redirects those writes THROUGH it
##     (e.g. into /etc) and a regular file makes reprepro fail "Not a directory";
##   - owned by the build user, matched by NUMERIC uid:gid (an account whose
##     primary group is not a user-private group named after the login, e.g. '_apt'
##     -> 'nogroup', must still be handled);
##   - mode EXACTLY 0755 -- 0700 blocks _apt's sandbox traversal; a world-writable
##     mode (e.g. 0777) lets any local user drop a .deb the root build installs
##     (local privilege escalation on a multi-account host).
## assert_store_ok enforces all of that (real dir, not symlink, numeric owner:group,
## exact 0755) on every success case.
##
## SECURITY. The function runs a privileged (SUDO_TO_ROOT) chown/chmod, so it must
## REFUSE to act on anything but an in-tree real directory it created or owns:
##   - a build-user-owned regular file or a symlink at the store path (the owner
##     check derefs and 'install -d' swallows "Not a directory"): must FAIL LOUD;
##   - a symlink AT or ABOVE the store pointing at a sensitive target (install -d /
##     chown / chmod would FOLLOW it and chmod/chown the TARGET -- an LPE): must
##     FAIL LOUD and leave the target UNTOUCHED;
##   - a '..'/'.' path component (traversal): must FAIL LOUD before any fs action.
## The repair of a root-owned store must route through SUDO_TO_ROOT (real builds
## run UNPRIVILEGED and elevate via sudo), while the $HOME fast path (store already
## owned) must use NO sudo. The suite runs as root (it asserts real on-disk
## ownership, which fakeroot only fakes) and cannot drop privileges to observe
## that directly, so it PROVES the routing: a recording stub stands in for
## SUDO_TO_ROOT, repair cases assert the stub fired, the fast path asserts it
## did not.
##
## Cases: (a) fresh root-run store; (b) pre-existing root:root 0755; (0700)
## pre-existing root:root 0700; ($HOME fast path) already build-user-owned but
## WRONG mode -> repaired to 0755 with NO sudo; (non-UPG) a build user whose
## primary group differs from the login name; (regfile) / (symlink) / (traversal)
## stores the helper must REJECT.
##
## Sources the REAL shipped '.bsh' fragment (no copy, no body extraction) and
## drives the shipped function directly. Needs REAL root; a non-root run is a HARD
## ERROR, not a skip. Throwaway mktemp trees; no network.

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

## The setup step that must source + call the fragment.
prepare=""
for candidate in "${DM_PREPARE_BUILD_MACHINE:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/1200_prepare-build-machine" \
   "${dm_checkout}/build-steps.d/1200_prepare-build-machine"; do
   case "${candidate}" in
      ''|'/build-steps.d/1200_prepare-build-machine')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      prepare="${candidate}"
      break
   fi
done
if [ -z "${prepare}" ]; then
   printf '%s\n' "FATAL: no derivative-maker build-steps.d/1200_prepare-build-machine found." >&2
   exit 1
fi

## The sourceable fragment under test.
helper=""
for candidate in "${DM_LOCAL_APT_REPO_STORE_BSH:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/help-steps/local-apt-repo-store.bsh" \
   "${dm_checkout}/help-steps/local-apt-repo-store.bsh"; do
   case "${candidate}" in
      ''|'/help-steps/local-apt-repo-store.bsh')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      helper="${candidate}"
      break
   fi
done
if [ -z "${helper}" ]; then
   printf '%s\n' "FATAL: no derivative-maker help-steps/local-apt-repo-store.bsh found." >&2
   exit 1
fi

if [ ! "${EUID}" = "0" ]; then
   printf '%s\n' \
      "FATAL: not root; local_apt_repo_store_ensure's ownership guarantee asserts on-disk" \
      "  ownership, which only real root can create and verify. Run this suite as root" \
      "  (CI does), or in the sandbox VM." >&2
   exit 1
fi

## A non-root build user WITH a matching primary group, so 'root != X' is a clean
## signal. 'daemon:daemon' (base-passwd, uid/gid 1) exists on every Debian/
## Kicksecure host and CI container -- no throwaway account to create or clean up.
build_user="daemon"
if ! getent passwd "${build_user}" >/dev/null || ! getent group "${build_user}" >/dev/null; then
   printf '%s\n' "FATAL: fixture account '${build_user}:${build_user}' absent (base-passwd gap?)." >&2
   exit 1
fi

## A build user whose PRIMARY GROUP is NOT a user-private group named after the
## login -- '_apt' has primary group 'nogroup' and there is no group named '_apt'.
## Present wherever apt is (every Debian/Kicksecure host + CI container). Exercises
## the numeric-gid path: 'install -g _apt' would fail 'invalid group'.
nonupg_user="_apt"
if ! getent passwd "${nonupg_user}" >/dev/null; then
   printf '%s\n' "FATAL: fixture account '${nonupg_user}' absent (apt not installed?)." >&2
   exit 1
fi

## --- static guards: fragment defines the function; 1200 sources + calls it ----
if grep --quiet --fixed-strings 'local_apt_repo_store_ensure()' "${helper}"; then
   pass "fragment defines local_apt_repo_store_ensure()"
else
   fail "fragment does not define local_apt_repo_store_ensure() (regressed?)"
fi

if grep --quiet --extended-regexp '^source .*local-apt-repo-store\.bsh"?$' "${prepare}"; then
   pass "1200 sources the local-apt-repo-store.bsh fragment"
else
   fail "1200 does not source local-apt-repo-store.bsh (dead fragment?)"
fi

if grep --quiet --extended-regexp '^ +local_apt_repo_store_ensure$' "${prepare}"; then
   pass "local_apt_repo_store_ensure is called from local_apt_repo_store_setup"
else
   fail "local_apt_repo_store_ensure is defined but never called"
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

owner_of() {
   stat -c '%U' -- "$1" 2>/dev/null || true
}
mode_of() {
   stat -c '%a' -- "$1" 2>/dev/null || true
}
## Never-failing describer for assertion diagnostics (errexit-safe).
describe_store() {
   local p="$1"
   if [ -L "${p}" ]; then
      printf '%s' "symlink->$(readlink -- "${p}" 2>/dev/null || true)"
   elif [ -d "${p}" ]; then
      printf '%s' "dir $(owner_of "${p}"):$(stat -c '%G' -- "${p}" 2>/dev/null || true) $(mode_of "${p}")"
   elif [ -e "${p}" ]; then
      printf '%s' "non-dir $(owner_of "${p}") $(mode_of "${p}")"
   else
      printf '%s' "absent"
   fi
}

## The full on-disk contract, asserted for every SUCCESS case: a REAL directory
## (not a symlink), owned by '$2' matched by NUMERIC uid:gid (so a non-user-private
## group resolves correctly), mode EXACTLY 0755.
assert_store_ok() {
   local base="$1" owner="$2" label="$3"
   local want_uid want_gid
   want_uid="$(id --user "${owner}")"
   want_gid="$(id --group "${owner}")"
   if [ -d "${base}" ] && [ ! -L "${base}" ] \
      && [ "$(stat -c '%u' -- "${base}" 2>/dev/null)" = "${want_uid}" ] \
      && [ "$(stat -c '%g' -- "${base}" 2>/dev/null)" = "${want_gid}" ] \
      && [ "$(mode_of "${base}")" = "755" ]; then
      pass "${label}: real dir, owned ${owner} (${want_uid}:${want_gid}), mode 0755, not a symlink"
   else
      fail "${label}: expected real dir owned ${owner} (${want_uid}:${want_gid}) mode 0755 not-symlink; got $(describe_store "${base}")"
   fi
}

## Drive the SHIPPED function against a controlled store path, owner and
## SUDO_TO_ROOT. A fresh subshell per call keeps strict mode and the sourced
## definition out of this shell. The subshell defines the stand-ins the fragment
## would otherwise inherit from the build:
##   error           -- derivative-maker's fail-loud handler (help-steps/pre),
##                       stubbed to abort, so a REJECT case can assert the helper
##                       failed loud (non-zero) instead of returning success;
##   sudo_record_run -- records the SUDO_TO_ROOT invocation AND runs the real
##                       privileged command (so a correct repair both leaves the
##                       sentinel and takes effect; an ambient-root / EUID-0-only
##                       direct chown leaves NO sentinel);
##   sudo_recorder   -- records only; the $HOME fast path must NEVER invoke it.
run_ensure() {
   local base="$1" owner="$2" sudo_cmd="$3"
   (
      set -o errexit
      set -o nounset
      set -o pipefail
      # shellcheck disable=SC2034  # consumed by the sourced function
      local_apt_repository_base="${base}"
      # shellcheck disable=SC2034
      user_name="${owner}"
      # shellcheck disable=SC2317  # invoked from the sourced fragment
      error() {
         printf '%s\n' "stub error: $*" >&2
         exit 1
      }
      ## style-ok: R-120 -- test stubs standing in for SUDO_TO_ROOT, not wrappers.
      # shellcheck disable=SC2317  # invoked indirectly via ${SUDO_TO_ROOT}
      sudo_record_run() {
         touch -- "${sentinel}"
         "$@"
      }
      # shellcheck disable=SC2317  # invoked indirectly via ${SUDO_TO_ROOT}
      sudo_recorder() {
         touch -- "${sentinel}"
      }
      # shellcheck disable=SC2034
      SUDO_TO_ROOT="${sudo_cmd}"
      # shellcheck disable=SC1090  # helper path is resolved at runtime
      source "${helper}"
      local_apt_repo_store_ensure
   )
}

## Assert SUDO_TO_ROOT was / was not invoked during the last run (via the
## sentinel the recorder stubs drop).
assert_sudo_used() {
   if [ -e "${sentinel}" ]; then
      pass "$1: repair routed through SUDO_TO_ROOT"
   else
      fail "$1: repair did NOT use SUDO_TO_ROOT (ambient-root / EUID-0 chown?)"
   fi
}
assert_sudo_not_used() {
   if [ ! -e "${sentinel}" ]; then
      pass "$1: no sudo (store already correctly owned)"
   else
      fail "$1: SUDO_TO_ROOT was invoked for an already-owned store"
   fi
}

## --- case (a): fresh store, created by a root-run build -----------------------
base_a="${workdir}/case_a/store"
sentinel="${workdir}/case_a.sudo"
if [ ! -e "${base_a}" ]; then
   pass "canary (a): store absent before ensure"
else
   fail "canary (a): store unexpectedly present before ensure"
fi
run_ensure "${base_a}" "${build_user}" "sudo_record_run"
assert_store_ok "${base_a}" "${build_user}" "(a) root-run fresh store"
assert_sudo_used "(a)"

## --- case (b): pre-existing root:root 0755 store ------------------------------
base_b="${workdir}/case_b/store"
sentinel="${workdir}/case_b.sudo"
install -d -m 0755 -o root -g root -- "${base_b}"
if [ "$(owner_of "${base_b}")" = "root" ] && [ "$(mode_of "${base_b}")" = "755" ]; then
   pass "canary (b): store pre-exists root:root 0755"
else
   fail "canary (b): could not stage a root:root 0755 store"
fi
run_ensure "${base_b}" "${build_user}" "sudo_record_run"
assert_store_ok "${base_b}" "${build_user}" "(b) pre-existing root:root 0755 store"
assert_sudo_used "(b)"

## --- pre-existing root:root 0700 (wrong mode) ---------------------------------
base_c="${workdir}/case_c/store"
sentinel="${workdir}/case_c.sudo"
install -d -m 0700 -o root -g root -- "${base_c}"
if [ "$(mode_of "${base_c}")" = "700" ]; then
   pass "canary (0700): store pre-exists root:root 0700"
else
   fail "canary (0700): could not stage a root:root 0700 store"
fi
run_ensure "${base_c}" "${build_user}" "sudo_record_run"
assert_store_ok "${base_c}" "${build_user}" "(0700) pre-existing root:root 0700 store"
assert_sudo_used "(0700)"

## --- $HOME fast path: already owned by the build user, NO sudo ----------------
## Owned but at the WRONG mode (0700): must be repaired to 0755 (not left 0700,
## not made world-writable) WITHOUT invoking SUDO_TO_ROOT.
base_d="${workdir}/case_d/store"
sentinel="${workdir}/case_d.sudo"
install -d -m 0700 -o "${build_user}" -g "${build_user}" -- "${base_d}"
if [ "$(owner_of "${base_d}")" = "${build_user}" ] && [ "$(mode_of "${base_d}")" = "700" ]; then
   pass "canary (\$HOME): store pre-exists ${build_user}:${build_user} 0700 (owned, wrong mode)"
else
   fail "canary (\$HOME): could not stage a ${build_user}:${build_user} 0700 store"
fi
run_ensure "${base_d}" "${build_user}" "sudo_recorder"
assert_store_ok "${base_d}" "${build_user}" "(\$HOME fast path) already-owned store"
assert_sudo_not_used "(\$HOME fast path)"

## --- non-user-private-group build user ----------------------------------------
## '-g <login>' would fail 'invalid group' for '_apt' (primary group 'nogroup').
## The store must end owned by _apt's real uid:gid at 0755.
base_g="${workdir}/case_g/store"
sentinel="${workdir}/case_g.sudo"
run_ensure "${base_g}" "${nonupg_user}" "sudo_record_run"
assert_store_ok "${base_g}" "${nonupg_user}" "(non-UPG) fresh store for ${nonupg_user}"
assert_sudo_used "(non-UPG)"

## --- non-directory store: helper must FAIL loud, not return success -----------
## A build-user-owned REGULAR FILE: 'install -d || true' swallows "Not a
## directory" and the owner check (deref) matches, so an owner-only helper returns
## success -- then reprepro fails "Not a directory". 'run_ensure' is in an 'if' so
## its non-zero exit (the helper's fail-loud) is the asserted PASS.
base_e="${workdir}/case_e/store"
sentinel="${workdir}/case_e.sudo"
install -d -m 0755 -o "${build_user}" -g "${build_user}" -- "${workdir}/case_e"
install -m 0644 -o "${build_user}" -g "${build_user}" -- /dev/null "${base_e}"
if [ -f "${base_e}" ] && [ ! -d "${base_e}" ] && [ "$(owner_of "${base_e}")" = "${build_user}" ]; then
   pass "canary (regfile): store pre-exists as a ${build_user}-owned regular file"
else
   fail "canary (regfile): could not stage a ${build_user}-owned regular file store"
fi
if run_ensure "${base_e}" "${build_user}" "sudo_record_run"; then
   fail "(regfile) helper returned SUCCESS for a non-directory store (reprepro would fail Not a directory)"
else
   pass "(regfile) helper rejects a non-directory store (fails loud)"
fi
if [ -f "${base_e}" ] && [ ! -d "${base_e}" ]; then
   pass "(regfile) the regular file was left in place, not clobbered into a dir"
else
   fail "(regfile) the store path was altered: $(describe_store "${base_e}")"
fi

## --- symlinked store: helper must FAIL loud and NOT follow the link -----------
## A symlink at the store pointing at a sensitive target (here a root:root 0700
## dir standing in for /etc): 'install -d' / chown / chmod would FOLLOW it and
## chmod the target 0755 (and chown it to the build user) -- an LPE. The helper
## must reject the symlink and leave the TARGET untouched.
base_f="${workdir}/case_f/store"
target_f="${workdir}/case_f/sensitive_target"
sentinel="${workdir}/case_f.sudo"
install -d -m 0755 -o root -g root -- "${workdir}/case_f"
install -d -m 0700 -o root -g root -- "${target_f}"
ln -s -- "${target_f}" "${base_f}"
if [ -L "${base_f}" ] && [ -d "${base_f}" ] && [ "$(mode_of "${target_f}")" = "700" ]; then
   pass "canary (symlink): store is a symlink to a root:root 0700 target"
else
   fail "canary (symlink): could not stage a symlink store"
fi
if run_ensure "${base_f}" "${build_user}" "sudo_record_run"; then
   fail "(symlink) helper returned SUCCESS for a symlinked store (reprepro would write through it)"
else
   pass "(symlink) helper rejects a symlinked store (fails loud)"
fi
if [ -L "${base_f}" ] && [ "$(owner_of "${target_f}")" = "root" ] && [ "$(mode_of "${target_f}")" = "700" ]; then
   pass "(symlink) the target was left untouched (not chmod'd/chowned through the link)"
else
   fail "(symlink) link or target was modified: store=$(describe_store "${base_f}"), target=$(describe_store "${target_f}")"
fi

## --- traversal store: helper must FAIL loud before any fs action --------------
## A '..' component could point the privileged chown/chmod out of tree.
base_t="${workdir}/case_t/sub/../escaped"
sentinel="${workdir}/case_t.sudo"
if run_ensure "${base_t}" "${build_user}" "sudo_record_run"; then
   fail "(traversal) helper returned SUCCESS for a '..' store path (out-of-tree chown risk)"
else
   pass "(traversal) helper rejects a '..' store path (fails loud)"
fi
if [ ! -e "${workdir}/case_t/escaped" ]; then
   pass "(traversal) nothing was created at the traversed-to path"
else
   fail "(traversal) a directory was created at the traversed-to path"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: local_apt_repo_store_ensure ownership + security."
