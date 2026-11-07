#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/local-apt-repo-store.bsh'
## local_apt_repo_store_ensure (sourced + called by
## build-steps.d/1200_prepare-build-machine's local_apt_repo_store_setup).
##
## WHAT IT GUARDS: the LOCAL apt repo store (local_apt_repository_base, default
## /srv/derivative-maker) must end up owned by the build user at mode 0755, so
## reprepro -- which writes it UNPRIVILEGED -- can. An earlier version only
## chowned to the build user when the unprivileged 'install -d' FAILED, i.e. it
## checked CREATION, not final OWNERSHIP, and left the store root:root in two
## cases that later broke reprepro with Permission denied:
##   (a) a root-run build (dist_build_allow_root=true, CI, containers): the plain
##       'install -d' succeeds as root and creates the dir root:root, so the
##       owned fallback was skipped;
##   (b) a root:root 0755 dir already existed: the unprivileged 'install -d'
##       succeeded trivially (dir exists, mode already matches, coreutils skips
##       the chmod), so the fallback was skipped and ownership stayed root:root.
## It also guards the already-safe root:root-0700 case (install -d fails EPERM ->
## fallback fires) against regressing, and the $HOME fast path (a store the build
## user already owns is fixed with NO sudo).
##
## Sources the REAL shipped '.bsh' fragment (no copy, no body extraction) and
## drives the shipped function directly.
##
## Needs REAL root: it asserts on-disk ownership (what reprepro actually hits),
## which fakeroot only fakes. The suite elevates to root; CI runs as container
## root. A non-root run is a HARD ERROR, not a skip -- a test that cannot run has
## verified nothing. Throwaway mktemp trees; no network.

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

## A non-root build user WITH a matching primary group, so 'install -o X -g X'
## (exactly what the function runs) resolves, and 'root != X' is a clean signal.
## 'daemon:daemon' (base-passwd, uid/gid 1) exists on every Debian/Kicksecure
## host and CI container -- no throwaway account to create or clean up.
build_user="daemon"
if ! getent passwd "${build_user}" >/dev/null || ! getent group "${build_user}" >/dev/null; then
   printf '%s\n' "FATAL: fixture account '${build_user}:${build_user}' absent (base-passwd gap?)." >&2
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

## Drive the SHIPPED function against a controlled store path, owner and
## SUDO_TO_ROOT. A fresh subshell per call keeps strict mode and the sourced
## definition out of this shell.
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
      # shellcheck disable=SC2034
      SUDO_TO_ROOT="${sudo_cmd}"
      # shellcheck disable=SC1090  # helper path is resolved at runtime
      source "${helper}"
      local_apt_repo_store_ensure
   )
}

owner_of() {
   stat -c '%U' -- "$1"
}
mode_of() {
   stat -c '%a' -- "$1"
}

## --- case (a): fresh store, created by a root-run build -----------------------
## Base absent; the plain 'install -d' inside the function runs as root (the
## suite elevated) and creates it root:root -- exactly a root-run build. The fix
## must then chown it to the build user.
base_a="${workdir}/case_a/store"
if [ ! -e "${base_a}" ]; then
   pass "canary (a): store absent before ensure"
else
   fail "canary (a): store unexpectedly present before ensure"
fi
run_ensure "${base_a}" "${build_user}" "sudo --non-interactive"
if [ "$(owner_of "${base_a}")" = "${build_user}" ] && [ "$(mode_of "${base_a}")" = "755" ]; then
   pass "(a) root-run fresh store ends owned by build user at 0755"
else
   fail "(a) root-run fresh store is $(owner_of "${base_a}"):$(mode_of "${base_a}"), expected ${build_user}:755"
fi

## --- case (b): pre-existing root:root 0755 store ------------------------------
## install -d then succeeds trivially (no chmod) and must NOT be allowed to leave
## ownership at root:root.
base_b="${workdir}/case_b/store"
install -d -m 0755 -o root -g root -- "${base_b}"
if [ "$(owner_of "${base_b}")" = "root" ] && [ "$(mode_of "${base_b}")" = "755" ]; then
   pass "canary (b): store pre-exists root:root 0755"
else
   fail "canary (b): could not stage a root:root 0755 store"
fi
run_ensure "${base_b}" "${build_user}" "sudo --non-interactive"
if [ "$(owner_of "${base_b}")" = "${build_user}" ]; then
   pass "(b) pre-existing root:root 0755 store is chowned to the build user"
else
   fail "(b) pre-existing root:root store left owned by $(owner_of "${base_b}"), expected ${build_user}"
fi

## --- pre-existing root:root 0700 (wrong mode) ---------------------------------
## Unprivileged, install -d's chmod fails EPERM so the old fallback fired; but a
## root-run build's install -d succeeds (root may chmod) and the old probe then
## left it root:root. The fix corrects BOTH owner and mode either way.
base_c="${workdir}/case_c/store"
install -d -m 0700 -o root -g root -- "${base_c}"
if [ "$(mode_of "${base_c}")" = "700" ]; then
   pass "canary (0700): store pre-exists root:root 0700"
else
   fail "canary (0700): could not stage a root:root 0700 store"
fi
run_ensure "${base_c}" "${build_user}" "sudo --non-interactive"
if [ "$(owner_of "${base_c}")" = "${build_user}" ] && [ "$(mode_of "${base_c}")" = "755" ]; then
   pass "(0700) store ends owned by build user at 0755"
else
   fail "(0700) store is $(owner_of "${base_c}"):$(mode_of "${base_c}"), expected ${build_user}:755"
fi

## --- $HOME fast path: already owned by the build user, NO sudo ----------------
## The optimization: when the store is already owned by the build user, the
## function must NOT invoke SUDO_TO_ROOT. Stub it with a recorder that drops a
## sentinel; assert the sentinel is absent afterwards.
base_d="${workdir}/case_d/store"
install -d -m 0755 -o "${build_user}" -g "${build_user}" -- "${base_d}"
sentinel="${workdir}/sudo_was_invoked"
(
   set -o errexit
   set -o nounset
   set -o pipefail
   # shellcheck disable=SC2034
   local_apt_repository_base="${base_d}"
   # shellcheck disable=SC2034
   user_name="${build_user}"
   ## style-ok: R-120 -- a test stub standing in for SUDO_TO_ROOT, not a wrapper.
   # shellcheck disable=SC2317
   sudo_recorder() {
      touch -- "${sentinel}"
   }
   # shellcheck disable=SC2034
   SUDO_TO_ROOT="sudo_recorder"
   # shellcheck disable=SC1090  # helper path is resolved at runtime
   source "${helper}"
   local_apt_repo_store_ensure
)
if [ -e "${sentinel}" ]; then
   sudo_invoked="yes"
else
   sudo_invoked="no"
fi
if [ "${sudo_invoked}" = "no" ] && [ "$(owner_of "${base_d}")" = "${build_user}" ]; then
   pass "(\$HOME fast path) store already owned by build user is left alone with NO sudo"
else
   fail "(\$HOME fast path) sudo invoked=${sudo_invoked}, owner=$(owner_of "${base_d}"), expected ${build_user} with no sudo"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: local_apt_repo_store_ensure ownership."
