#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_lintian builds the default DEBUILD_LINTIAN_OPTS. Our bash style (R-010)
## mandates 'set -o errexit', but lintian's matcher only recognizes 'set -e'
## (and shebang '-e'), so every maintainer script using the strict preamble
## falsely trips 'maintainer-script-ignores-errors'. The default opts must
## suppress that tag globally; dropping the suppression turns every such build
## red on a false positive. This asserts the suppression is present.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Reached only via the ERR trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
error_handler() {
   local exit_code="$?"
   printf '%s\n' "ERROR: exit_code: ${exit_code} | BASH_COMMAND: ${BASH_COMMAND}"
   exit 1
}

trap error_handler ERR

## Shared genmkfile library discovery + checkout capability gate (sibling suites
## source the same helper, so they cannot drift to different subjects/skips).
_common_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../dist-ai-tests-common"
[ -r "${_common_dir}/genmkfile-locate.bash" ] || _common_dir="/usr/share/dist-ai-tests-common"
# shellcheck source=../dist-ai-tests-common/genmkfile-locate.bash
source "${_common_dir}/genmkfile-locate.bash"
genmkfile_require_helper
# shellcheck disable=SC2154  ## set by genmkfile_require_helper in the sourced helper
helper_file="${genmkfile_helper_file}"

test_root="$(mktemp --directory)"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}

trap cleanup_handler EXIT

## Extract the function under test rather than sourcing the whole library, matching
## version_parse_test.sh. '^make_lintian()' does not match 'make_lintian_on_warning()'.
sed -n '/^make_lintian()/,/^}/p' -- "${helper_file}" \
   > "${test_root}/function_under_test.sh"

if ! test -s "${test_root}/function_under_test.sh" ; then
   printf '%s\n' "ERROR: could not extract make_lintian." >&2
   exit 1
fi

## The extracted file is generated at runtime, so there is no path for a source=
## directive to point at.
# shellcheck disable=SC1091
source "${test_root}/function_under_test.sh"

## Stub everything make_lintian reaches after it builds the opts, so the real
## opts-building code runs but nothing else does. lintian is stubbed to a
## no-op producing empty output, so the reporting/failure paths are skipped.
## Each is called indirectly by the sourced make_lintian; shellcheck cannot
## see that path (SC2317).
# shellcheck disable=SC2317
make_output_info() { return 0 ; }
# shellcheck disable=SC2317
make_lintian_on_warning() { return 0 ; }
# shellcheck disable=SC2317
exit_with_error() { printf '%s\n' "unexpected exit_with_error: $*" >&2 ; exit 99 ; }
# shellcheck disable=SC2317
lintian() { return 0 ; }

## make_lintian only builds the default opts when DEBUILD_LINTIAN_OPTS is empty.
unset DEBUILD_LINTIAN_OPTS || true
## Exists so the leading 'test -f' guard passes and die is not reached.
make_main_changes_file="${test_root}/fake.changes"
touch -- "${make_main_changes_file}"

tests_total=0
tests_failed=0

make_lintian

## THE REGRESSION: the false-positive suppression must be in the default opts.
tests_total=$(( tests_total + 1 ))
case "${DEBUILD_LINTIAN_OPTS:-}" in
   *'--suppress-tags maintainer-script-ignores-errors'* )
      printf '%s\n' "PASS  default opts suppress maintainer-script-ignores-errors"
      ;;
   * )
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  default opts do NOT suppress maintainer-script-ignores-errors" >&2
      printf '%s\n' "        got: ${DEBUILD_LINTIAN_OPTS:-<unset>}" >&2
      ;;
esac

## A pre-existing suppression stays present: guards against a wholesale rewrite
## of the block silently dropping tags.
tests_total=$(( tests_total + 1 ))
case "${DEBUILD_LINTIAN_OPTS:-}" in
   *'--suppress-tags missing-tests-control'* )
      printf '%s\n' "PASS  default opts retain pre-existing suppressions"
      ;;
   * )
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  default opts lost pre-existing suppressions" >&2
      ;;
esac

printf '%s\n' "" "${tests_total} test(s), ${tests_failed} failed"
if [ "${tests_failed}" -ne 0 ]; then
   exit 1
fi
exit 0
