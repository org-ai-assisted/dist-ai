#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'help-steps/mount-cleanup': after killing
## any stragglers it hands off to 'unmount-tree' to detach the submounts under
## the tree. 'unmount-tree' REQUIRES the tree as its argument (it dies "no
## parameter given!" without one), so mount-cleanup must forward its own
## already-validated target -- as its two sibling callers (1300_cowbuilder-setup,
## unmount-lb) do.
##
## The bug this pins: mount-cleanup called 'unmount-tree' with NO argument, so
## every invocation died at the handoff. Where a caller wrapped it in '|| true'
## the failure was swallowed (submounts silently NOT cleaned); where it did not
## (2100_create-debian-packages' get_newer_packages_from_third_party_repositories)
## the whole build died ~30 min in.
##
## Runs the REAL mount-cleanup against an EMPTY tree: no submounts, so it needs no
## mount capability -- it only has to pass the root gate and reach the unmount-tree
## handoff. mount-cleanup refuses a non-root EUID, so it runs under 'fakeroot'
## when the suite is unprivileged (EUID 0 for the '${EUID}' check; the checkout
## stays readable, so '${MYDIR}/unmount-tree' and its 'unmount-helper' resolve
## from the real tree). Real root is used directly when present.
##
## Subject selection (first that exists):
##   $MOUNT_CLEANUP  ->  ./mount-cleanup next to this test (staged copy)
##   ->  ~/derivative-maker/help-steps/mount-cleanup (source checkout)

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

main() {
   local subject run_as=() scratch run_output run_rc

   subject="$(locate_help_step mount-cleanup "${MOUNT_CLEANUP:-}" "${test_dir}")"
   printf '%s\n' "INFO: subject: ${subject}"

   ## mount-cleanup refuses a non-root EUID. Fake it when unprivileged; a missing
   ## fakeroot there is a required-tooling gap (FATAL), not a reason to skip and
   ## report a false green.
   if [ "${EUID}" = "0" ]; then
      run_as=()
   elif type -P fakeroot >/dev/null; then
      run_as=( fakeroot )
   else
      printf '%s\n' "FATAL: not root and 'fakeroot' is absent; mount-cleanup's root gate cannot be satisfied." >&2
      return 1
   fi

   ## An EMPTY tree: mount-cleanup finds no stragglers and reaches the unmount-tree
   ## handoff, which finds no submounts and exits 0 -- IFF the argument was
   ## forwarded. The pre-fix bare call makes unmount-tree die "no parameter
   ## given!" and mount-cleanup exit 1, which is exactly what these two assertions
   ## catch.
   scratch="$(mktemp --directory)"

   run_rc=0
   run_output="$( "${run_as[@]}" bash "${subject}" -- "${scratch}" 2>&1 )" || run_rc="$?"

   if [ "${run_rc}" = "0" ]; then
      pass "mount-cleanup on an empty tree completes (exit 0)"
   else
      fail "mount-cleanup exited ${run_rc}; the unmount-tree handoff failed"
      printf '%s\n' "DEBUG: mount-cleanup output follows:" >&2
      printf '%s\n' "${run_output}" >&2
   fi

   ## The specific failure signature of the bug: unmount-tree got no tree.
   if printf '%s\n' "${run_output}" | grep --fixed-strings -- 'no parameter given' >/dev/null 2>&1; then
      fail "mount-cleanup did not forward its target to unmount-tree ('no parameter given!')"
   else
      pass "mount-cleanup forwards its target to unmount-tree (no 'no parameter given!')"
   fi

   safe-rm --recursive --force -- "${scratch}"

   ## Caller audit: mount-cleanup refuses a non-root EUID, so EVERY invocation
   ## must run it as root via ${SUDO_TO_ROOT}. A missing prefix makes it die
   ## "MUST be run as root" mid-teardown -- exactly what broke the CI image build
   ## at 3500_install-packages (unmount-raw + unchroot-raw each called it bare).
   local caller_hits bad_callers="" hit body trimmed
   caller_hits="$(grep -rInE '/mount-cleanup"?[[:space:]]+--[[:space:]]' \
      "${dm_checkout}/help-steps" "${dm_checkout}/build-steps.d" 2>/dev/null || true)"
   while IFS= read -r hit; do
      [ -n "${hit}" ] || continue
      body="${hit#*:}"; body="${body#*:}"                 ## strip 'path:line:'
      trimmed="${body#"${body%%[![:space:]]*}"}"          ## strip leading space
      case "${trimmed}" in '#'*) continue ;; esac         ## skip comments
      case "${body}" in
         *'${SUDO_TO_ROOT}'*mount-cleanup*)
            : ## runs as root: ok
            ;;
         *)
            bad_callers="${bad_callers}
          ${hit}"
            ;;
      esac
   done <<< "${caller_hits}"
   if [ -z "${caller_hits}" ]; then
      fail "found NO mount-cleanup callers to audit; the grep or the checkout path is wrong"
   elif [ -z "${bad_callers}" ]; then
      pass "every mount-cleanup caller runs it as root (\${SUDO_TO_ROOT})"
   else
      fail "mount-cleanup callers lacking \${SUDO_TO_ROOT} (it will die 'MUST be run as root'):${bad_callers}"
   fi

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: mount-cleanup forwards its target to unmount-tree."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
