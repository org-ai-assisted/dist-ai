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
   "${HOME}/derivative-maker/packages/kicksecure/legacy-dist/debian/legacy-dist.preinst"; do
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

## Count the arguments each 'printf ... | debconf-set-selections' passes. python3
## rather than a shell word-split, because the records contain literal TABs and
## quoting that a naive split would mangle -- which is how the defect was missed.
report="$(python3 - "${preinst}" <<'PYEOF'
import shlex, sys
total = 0
bad = []
for number, line in enumerate(open(sys.argv[1], encoding='utf-8'), 1):
    if 'debconf-set-selections' not in line or 'printf' not in line:
        continue
    total += 1
    arguments = shlex.split(line.split('|')[0].strip())[2:]
    if len(arguments) != 1:
        bad.append('%d:%d' % (number, len(arguments)))
print(total)
print(' '.join(bad))
PYEOF
)"
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
canary_bad="$(python3 - "${canary}" <<'PYEOF'
import shlex, sys
bad = []
for number, line in enumerate(open(sys.argv[1], encoding='utf-8'), 1):
    if 'debconf-set-selections' not in line or 'printf' not in line:
        continue
    if len(shlex.split(line.split('|')[0].strip())[2:]) != 1:
        bad.append(str(number))
print(' '.join(bad))
PYEOF
)"
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
