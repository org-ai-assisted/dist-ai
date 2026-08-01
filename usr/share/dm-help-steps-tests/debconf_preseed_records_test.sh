#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Every line feeding 'debconf-set-selections' must emit exactly ONE record.
##
## THE BUG IT GUARDS: a mechanical 'echo' -> 'printf' conversion. The two do NOT
## agree on multiple arguments:
##   echo   a b c d            -> "a b c d"        (one line)
##   printf '%s\n' a b c d     -> "a\nb\nc\nd"     (FOUR lines)
## A debconf record is 'package question type value' on ONE line, so an unquoted
## conversion silently turns one valid preseed into four malformed fragments. The
## preseed then does not apply, exactly like a preseed for a nonexistent choice --
## no error, no effect.
##
## Scanned statically: these run in a dpkg maintainer script, so executing them
## here is neither possible nor desirable.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

preinst=""
for candidate in "${LEGACY_DIST_PREINST:-}" \
   "${LEGACY_DIST_DIR:-}/debian/legacy-dist.preinst" \
   "${DERIVATIVE_MAKER_DIR:-}/packages/kicksecure/legacy-dist/debian/legacy-dist.preinst" \
   "${dm_checkout}/packages/kicksecure/legacy-dist/debian/legacy-dist.preinst"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      preinst="${candidate}"
      break
   fi
done
if [ -z "${preinst}" ]; then
   printf '%s\n' "SKIP: legacy-dist.preinst not found (set LEGACY_DIST_PREINST)." >&2
   exit 77
fi

## Argument counting lives in its own file (R-190): the helper is a real program
## a reader can open and run, not a blob embedded in a quoted heredoc.
report="$(python3 -- "${test_dir}/debconf_record_argcount.py" "${preinst}")"
total="$(printf '%s\n' "${report}" | sed -n '1p')"
bad="$(printf '%s\n' "${report}" | sed -n '2p')"

if [ "${total}" -gt 0 ]; then
   pass "found ${total} debconf-set-selections feed(s) to check"
else
   fail "no debconf-set-selections lines found; this test is asserting nothing"
fi

if [ -z "${bad}" ]; then
   pass "every debconf feed passes exactly ONE argument, so it emits ONE record"
else
   fail "these lines pass multiple arguments, so printf emits one line EACH (line:argcount): ${bad}"
fi

## CANARY: prove the check can actually fail, using the broken form itself.
canary="$(mktemp)"
printf '%s\n' "   printf '%s\\n' pkg pkg/question boolean true | debconf-set-selections" > "${canary}"
canary_bad="$(python3 -- "${test_dir}/debconf_record_argcount.py" "${canary}" | sed -n '2p')"
safe-rm --force -- "${canary}"
if [ -n "${canary_bad}" ]; then
   pass "canary: the unquoted form IS detected"
else
   fail "canary broken: the unquoted form was not detected, so a pass here proves nothing"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: debconf preseed records."
