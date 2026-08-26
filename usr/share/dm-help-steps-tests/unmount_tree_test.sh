#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for derivative-maker 'help-steps/unmount-tree', the
## deepest-first sweep of the mount points under a build tree.
##
## Asserts the contract callers depend on before a recursive delete:
##
##   sweeps what is UNDER the tree:
##     - a submount at a subdirectory
##     - a nested chain ('deep/er/est'), which only comes out if the
##       ordering is deepest-first
##     - a mount point containing a SPACE, and one containing a TAB
##       (a findmnt-based sweep escapes these to '\x20' / '\x09' and
##       silently leaves them mounted)
##     - a tree named through a SYMLINK
##     - a dash-leading relative tree passed after '--'
##
##   leaves alone what is NOT under the tree:
##     - the tree's OWN root mount (unchroot-raw sweeps '$CHROOT_FOLDER'
##       while the ext4 root mount-raw placed there must stay)
##     - a SIBLING tree whose name is a string-prefix collision ('<tree>2')
##
##   fails CLOSED:
##     - unmounts that report success without detaching -> non-zero exit,
##       so a caller never proceeds to 'safe-rm --recursive' across a live
##       mount
##
##   guards:
##     - no argument: exit 1
##     - '/': refused, exit 1
##     - nonexistent tree: exit 0
##
## Mount capability comes from 'unshare --user --map-root-user --mount', so
## this needs no real privilege. Run it in a sandbox VM, not on the
## operator's machine:
##
##   sandbox-run --dir <staged-dir> -- ./unmount_tree_test.sh
##
## Subject selection (first that exists):
##   $UNMOUNT_TREE  ->  ./unmount-tree next to this test (staged copy)
##   ->  ~/derivative-maker/help-steps/unmount-tree (source checkout)

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

require_exit_code() {
   local actual_code wanted_code description

   actual_code="$1"
   wanted_code="$2"
   description="$3"

   if [ "${actual_code}" = "${wanted_code}" ]; then
      pass "${description} (exit ${actual_code})"
   else
      fail "${description}: expected exit ${wanted_code}, got ${actual_code}"
   fi
}

main() {
   local subject scratch_base run_output run_rc guard_exit_code

   subject="$(locate_help_step unmount-tree "${UNMOUNT_TREE:-}" "${test_dir}")"
   printf '%s\n' "INFO: subject: ${subject}"

   ## The mount fixtures ARE this test; without a mount namespace it would
   ## report green having exercised only the argument guards.
   if ! mount_namespace_available; then
      printf '%s\n' "ERROR: user namespaces unavailable; the mount assertions cannot run here." >&2
      return 1
   fi

   scratch_base="$(mktemp --directory)"

   run_rc=0
   run_output="$(run_in_mount_namespace \
      "${test_dir}/unmount_tree_test_inner.sh" "${subject}" "${scratch_base}")" || run_rc="$?"

   ## Without this the assertions below would each fail with a confusing
   ## 'missing marker' instead of naming the real problem.
   require_result "${run_output}" "RESULT inner DONE" "mount-namespace fixture ran to completion"

   require_result "${run_output}" "RESULT exit 0"            "clean sweep exits 0"
   require_result "${run_output}" "RESULT sub UNMOUNTED"     "submount under tree unmounted"
   require_result "${run_output}" "RESULT deepest UNMOUNTED" "deepest nested mount unmounted"
   require_result "${run_output}" "RESULT deepmid UNMOUNTED" "middle nested mount unmounted"
   require_result "${run_output}" "RESULT deeproot UNMOUNTED" "outer nested mount unmounted"
   require_result "${run_output}" "RESULT space UNMOUNTED"   "mount point containing a SPACE unmounted"
   require_result "${run_output}" "RESULT tab UNMOUNTED"     "mount point containing a TAB unmounted"
   require_result "${run_output}" "RESULT symlink UNMOUNTED" "symlinked tree argument resolved and swept"
   require_result "${run_output}" "RESULT dash UNMOUNTED"    "dash-leading tree after '--' swept"

   require_result "${run_output}" "RESULT root MOUNTED"      "tree's own root mount preserved"
   require_result "${run_output}" "RESULT sibling MOUNTED"   "sibling string-prefix tree left alone"

   require_result "${run_output}" "RESULT failclosed EXIT_NONZERO" \
      "fails closed when unmounts do not detach"
   require_result "${run_output}" "RESULT order DEEPEST_FIRST" \
      "umount calls ordered deepest-first"
   require_result "${run_output}" "RESULT shadow REMAINING=0" \
      "shadowed over-mount cleared (re-read until stable)"
   require_result "${run_output}" "RESULT hostile REMAINING=0" \
      "backslash and newline in mount point names handled"
   require_result "${run_output}" "RESULT peer OUTSIDE_SURVIVED" \
      "shared-mount peer outside the tree not disturbed"
   require_result "${run_output}" "RESULT sharedtree REMAINING=0" \
      "shared mount under the tree still swept"

   if [ ! "${run_rc}" = "0" ]; then
      printf '%s\n' "NOTE: mount-namespace run exited ${run_rc}." >&2
   fi

   ## ---- guards (no mount capability needed) ----

   guard_exit_code=0
   bash "${subject}" >/dev/null 2>&1 || guard_exit_code="$?"
   require_exit_code "${guard_exit_code}" "1" "no argument: refused"

   guard_exit_code=0
   bash "${subject}" "/" >/dev/null 2>&1 || guard_exit_code="$?"
   require_exit_code "${guard_exit_code}" "1" "target '/': refused"

   guard_exit_code=0
   bash "${subject}" "${scratch_base}/does-not-exist" >/dev/null 2>&1 || guard_exit_code="$?"
   require_exit_code "${guard_exit_code}" "0" "nonexistent tree: nothing to do"

   safe-rm --recursive --force -- "${scratch_base}"

   if [ "${test_failures}" = "0" ]; then
      printf '%s\n' "OK: all unmount-tree assertions passed."
      return 0
   fi
   printf '%s\n' "ERROR: ${test_failures} assertion(s) failed." >&2
   return 1
}

main "$@"
