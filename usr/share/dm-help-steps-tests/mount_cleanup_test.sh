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

## Audit that every mount-cleanup INVOCATION under the given dirs runs it as root
## via ${SUDO_TO_ROOT}. Single-LINE by design (no bash parser): it matches every
## path-form invocation -- INCLUDING one whose '--'/args wrap to the next line,
## which it cannot verify on one line and therefore reports as a problem
## ("inspect it") rather than passing silently. Sets:
##   AUDIT_REPORT -- one tagged line per problem caller (empty == all clean)
##   AUDIT_HITS   -- count of non-comment invocations seen (0 == scan found none)
## Runs in the CURRENT shell (here-string, no subshell) so both globals survive.
AUDIT_REPORT=""
AUDIT_HITS=0
audit_mount_cleanup_callers() {
   local hits hit body trimmed between
   AUDIT_REPORT=""
   AUDIT_HITS=0
   ## Match the path-form invocation only ('<path>/mount-cleanup' + quote/space/
   ## end); the script's own '$0'-based error strings carry no '/mount-cleanup',
   ## so they never match. Crucially NOT requiring '--' on the same line: a call
   ## whose args wrap would otherwise be invisible and silently pass.
   hits="$(grep -rInE '/mount-cleanup"?([[:space:]]|$)' "$@" 2>/dev/null || true)"
   while IFS= read -r hit; do
      [ -n "${hit}" ] || continue
      body="${hit#*:}"; body="${body#*:}"                 ## strip 'path:line:'
      trimmed="${body#"${body%%[![:space:]]*}"}"          ## strip leading space
      case "${trimmed}" in '#'*) continue ;; esac         ## skip comments
      AUDIT_HITS=$(( AUDIT_HITS + 1 ))
      case "${body}" in
         *'${SUDO_TO_ROOT}'*mount-cleanup*)
            ## ${SUDO_TO_ROOT} appears before mount-cleanup, but only its being
            ## the IMMEDIATE prefix makes the call privileged. A command
            ## separator between the last ${SUDO_TO_ROOT} and mount-cleanup means
            ## sudo applies to a DIFFERENT command and mount-cleanup runs bare.
            ## Fail closed on any separator (no bash parser -- just "is there a
            ## separator in the gap").
            between="${body##*'${SUDO_TO_ROOT}'}"   ## after the LAST SUDO_TO_ROOT
            between="${between%%mount-cleanup*}"     ## ... and before mount-cleanup
            case "${between}" in
               *';'*|*'&'*|*'|'*)
                  AUDIT_REPORT="${AUDIT_REPORT}          UNAUDITABLE-SEPARATOR ${hit}
"
                  ;;
               *)
                  : ## sudo is the immediate prefix: privileged, ok
                  ;;
            esac
            ;;
         *mount-cleanup*[[:space:]]--[[:space:]]*)
            ## complete single-line call, no ${SUDO_TO_ROOT}: genuinely bare.
            AUDIT_REPORT="${AUDIT_REPORT}          MISSING-SUDO ${hit}
"
            ;;
         *)
            ## no '--' on this line: the call wraps and this single-line audit
            ## cannot verify it. Fail closed -- inspect it, never pass silently.
            AUDIT_REPORT="${AUDIT_REPORT}          UNAUDITABLE-MULTILINE ${hit}
"
            ;;
      esac
   done <<< "${hits}"
}

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
   audit_mount_cleanup_callers "${dm_checkout}/help-steps" "${dm_checkout}/build-steps.d"
   if [ "${AUDIT_HITS}" -eq 0 ]; then
      fail "found NO mount-cleanup callers to audit; the grep or the checkout path is wrong"
   elif [ -z "${AUDIT_REPORT}" ]; then
      pass "every mount-cleanup caller runs it as root (\${SUDO_TO_ROOT})"
   else
      fail "mount-cleanup callers not verifiably root (MISSING-SUDO = bare; UNAUDITABLE-MULTILINE = wraps lines, inspect):
${AUDIT_REPORT}"
   fi

   ## The audit must not silently pass a call it cannot verify. Exercise its two
   ## problem shapes against synthetic caller snippets (fixtures for the audit
   ## LOGIC, not copies of any script): a bare single-line call, and -- the
   ## silent-green case -- a call whose args wrap to the NEXT line.
   local fix="${scratch}-audit"
   mkdir --parents -- "${fix}/help-steps" "${fix}/build-steps.d"
   printf '%s\n' '      "${dist_source_help_steps_folder}/mount-cleanup" -- "${CHROOT_FOLDER}"' \
      > "${fix}/help-steps/bare-single-line"
   audit_mount_cleanup_callers "${fix}/help-steps"
   case "${AUDIT_REPORT}" in
      *MISSING-SUDO*)
         pass "a bare single-line mount-cleanup call is flagged MISSING-SUDO"
         ;;
      *)
         fail "a bare single-line mount-cleanup call was NOT flagged: '${AUDIT_REPORT}'"
         ;;
   esac
   ## The invocation and its '--' on SEPARATE lines: the mount-cleanup line then
   ## carries no '--', which is what a wrapped call looks like to a line scan.
   ## (A trailing continuation backslash is not needed -- and would trip SC1003
   ## inside single quotes -- the audit only sees that this line lacks '--'.)
   printf '%s\n' \
      '      "${dist_source_help_steps_folder}/mount-cleanup"' \
      '         -- "${CHROOT_FOLDER}"' \
      > "${fix}/help-steps/bare-multi-line"
   safe-rm --force -- "${fix}/help-steps/bare-single-line"
   audit_mount_cleanup_callers "${fix}/help-steps"
   case "${AUDIT_REPORT}" in
      *UNAUDITABLE-MULTILINE*)
         pass "a wrapped (multi-line) mount-cleanup call is flagged, not silently passed"
         ;;
      *)
         fail "a wrapped multi-line mount-cleanup call slipped the audit: '${AUDIT_REPORT}'"
         ;;
   esac
   safe-rm --force -- "${fix}/help-steps/bare-multi-line"
   ## ${SUDO_TO_ROOT} on the line but on a DIFFERENT command (separated by ';'),
   ## with mount-cleanup bare after it: the sudo is NOT its prefix. Must be
   ## flagged, not read as privileged.
   printf '%s\n' '      ${SUDO_TO_ROOT} prep_step ; "${dist_source_help_steps_folder}/mount-cleanup" -- "${CHROOT_FOLDER}"' \
      > "${fix}/help-steps/sudo-on-other-command"
   audit_mount_cleanup_callers "${fix}/help-steps"
   case "${AUDIT_REPORT}" in
      *UNAUDITABLE-SEPARATOR*)
         pass "sudo on a different command (';' then bare mount-cleanup) is flagged, not passed"
         ;;
      *)
         fail "a ';'-separated bare mount-cleanup with sudo on another command slipped: '${AUDIT_REPORT}'"
         ;;
   esac
   safe-rm --recursive --force -- "${fix}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: mount-cleanup forwards its target to unmount-tree."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
