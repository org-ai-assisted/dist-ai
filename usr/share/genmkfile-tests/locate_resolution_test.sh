#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## genmkfile-locate.bash resolves the subject the genmkfile suites test. An
## explicit GENMKFILE_BIN / GENMKFILE_SHARE must resolve to ONE real checkout:
##   - a RELATIVE selection must become absolute, or a test that changes
##     directory before exec/source loses it (install_modes_test.sh cds, then
##     execs the resolved binary);
##   - a SYMLINKED GENMKFILE_BIN must resolve to the binary's REAL checkout, or
##     the helper is derived lexically from the symlink's directory -- a
##     different checkout, the false-green this locator exists to kill;
##   - a SHARE-only selection must resolve the binary from the SAME checkout,
##     not fall through to the dm checkout and test a different subject.
## The resolvers are a sourced fragment, so this sources the real file and drives
## the functions directly -- no copy, no function extraction.

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

## Source the real locator to get the resolver functions under test.
_common_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../dist-ai-tests-common"
[ -r "${_common_dir}/genmkfile-locate.bash" ] || _common_dir="/usr/share/dist-ai-tests-common"
# shellcheck source=../dist-ai-tests-common/genmkfile-locate.bash
source "${_common_dir}/genmkfile-locate.bash"

## The suite runner exports GENMKFILE_BIN to wire the real subject. Clear both
## selectors so each case below controls the FULL resolver environment -- an
## inherited GENMKFILE_BIN would otherwise win (BIN before SHARE) and mask the
## SHARE-only case.
unset GENMKFILE_BIN GENMKFILE_SHARE

test_root="$(mktemp --directory)"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}

trap cleanup_handler EXIT

## A fake genmkfile checkout: an executable binary and a readable helper, laid
## out as the real package ships them (usr/bin + usr/share/genmkfile).
checkout="${test_root}/checkout"
mkdir --parents -- "${checkout}/usr/bin" "${checkout}/usr/share/genmkfile"
printf '%s\n' '#!/bin/bash' ':' > "${checkout}/usr/bin/genmkfile"
chmod 0755 -- "${checkout}/usr/bin/genmkfile"
printf '%s\n' '#!/bin/bash' ':' > "${checkout}/usr/share/genmkfile/make-helper-one.bsh"

checkout_real="$(readlink --canonicalize -- "${checkout}")"

tests_total=0
tests_failed=0

pass() {
   tests_total=$(( tests_total + 1 ))
   printf '%s\n' "PASS  $1"
}

fail() {
   tests_total=$(( tests_total + 1 ))
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  $1" >&2
}

## Run a resolver in a subshell (it exits on a FATAL and sets a global on
## success) and print the resolved global, or 'FATAL:<code>' if it exited.
## Args: <resolver> <out-global>; reads GENMKFILE_BIN/SHARE/cwd from the caller.
resolve() {
   local resolver="$1" out_global="$2" status=0 value
   value="$( "${resolver}" >/dev/null 2>&1 && printf '%s' "${!out_global}" )" || status=$?
   if [ "${status}" -ne 0 ]; then
      printf '%s' "FATAL:${status}"
      return 0
   fi
   printf '%s' "${value}"
}

## 1. A RELATIVE GENMKFILE_BIN resolves to an absolute path (survives a cd). The
##    relative input is deliberate and doubles as the canary: the assertion below
##    only passes if the resolver absolutizes it.
got="$(
   cd -- "${checkout}" \
   && GENMKFILE_BIN="usr/bin/genmkfile" resolve genmkfile_require_bin genmkfile_bin_path
)"
case "${got}" in
   /*)
      if [ "${got}" = "${checkout_real}/usr/bin/genmkfile" ] && [ -x "${got}" ]; then
         pass "relative GENMKFILE_BIN resolves to the absolute binary"
      else
         fail "relative GENMKFILE_BIN resolved to an unexpected path: ${got}"
      fi
      ;;
   *)
      fail "relative GENMKFILE_BIN was NOT made absolute: ${got}"
      ;;
esac

## 2. A SYMLINKED GENMKFILE_BIN resolves the helper from the binary's REAL
##    checkout, not from the symlink's directory.
ln --symbolic -- "${checkout}/usr/bin/genmkfile" "${test_root}/genmkfile-link"
got="$(
   GENMKFILE_BIN="${test_root}/genmkfile-link" resolve genmkfile_require_helper genmkfile_helper_file
)"
if [ "${got}" = "${checkout_real}/usr/share/genmkfile/make-helper-one.bsh" ]; then
   pass "symlinked GENMKFILE_BIN derives the helper from the real checkout"
else
   fail "symlinked GENMKFILE_BIN resolved the helper off the symlink dir: ${got}"
fi

## 3. A SHARE-only selection resolves the binary from the SAME checkout, instead
##    of falling through to an unrelated (dm/installed) checkout.
got="$(
   GENMKFILE_SHARE="${checkout}/usr/share/genmkfile" resolve genmkfile_require_bin genmkfile_bin_path
)"
if [ "${got}" = "${checkout_real}/usr/bin/genmkfile" ]; then
   pass "GENMKFILE_SHARE-only resolves the binary from the selected checkout"
else
   fail "GENMKFILE_SHARE-only did NOT resolve the binary from its checkout: ${got}"
fi

## 4. An explicit selection naming a non-executable binary FAILS loud; it never
##    falls back to an unrelated checkout.
got="$(
   GENMKFILE_BIN="${checkout}/usr/share/genmkfile/make-helper-one.bsh" \
      resolve genmkfile_require_bin genmkfile_bin_path
)"
case "${got}" in
   FATAL:*)
      pass "a non-executable GENMKFILE_BIN fails loud (no silent fallback)"
      ;;
   *)
      fail "a non-executable GENMKFILE_BIN did not fail loud: ${got}"
      ;;
esac

printf '%s\n' "" "${tests_total} test(s), ${tests_failed} failed, 0 skip"
if [ "${tests_failed}" -ne 0 ]; then
   exit 1
fi
exit 0
