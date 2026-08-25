#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Engine hardening regressions, driven through the shell harness (so the suite
## runner picks them up) against the REAL dist_ai package:
##   * a '## style-ok:' waiver on a CRLF line is honored (fail-closed regression)
##   * the fixer's write refuses a symlink swapped in AFTER the scan (TOCTOU)

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## Prefer the in-tree package (usr/share/<suite>/ -> usr/lib/...), else installed.
LIB="${tool_test_dir}/../../lib/python3/dist-packages"
if [ ! -d "${LIB}/dist_ai" ]; then
   LIB='/usr/lib/python3/dist-packages'
fi
export PYTHONPATH="${LIB}${PYTHONPATH:+:${PYTHONPATH}}"

for prereq in python3 safe-rm; do
   type -P "${prereq}" >/dev/null 2>&1 || {
      printf '%s\n' "FATAL: '${prereq}' not on PATH; this test cannot run." >&2
      exit 1
   }
done

test_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${test_dir}"; }
trap cleanup EXIT

passc=0
fail=0
note_pass() { printf '%s\n' "PASS: ${1}"; passc=$(( passc + 1 )); }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2; fail=$(( fail + 1 )); }

## --- CRLF-terminated style-ok waiver is honored ------------------------------
## Canary: the old '(?:[ \t]|$)' boundary matched '$' before '\n' (i.e. AFTER
## the '\r'), so a CRLF waiver with no space after the tag was dropped and the
## rule fired fail-closed. A real '\r' in the boundary fixes it.
crlf_waiver="$(python3 -c '
from dist_ai import context
src = "#!/bin/bash\r\n## style-ok: allow-non-ascii\r\nx = 1\r\n"
print(context.FileContext("f.sh", src).has_waiver("allow-non-ascii"))
')"
if [ "${crlf_waiver}" = "True" ]; then
   note_pass "CRLF-terminated style-ok waiver is honored"
else
   note_fail "CRLF-terminated style-ok waiver dropped (got '${crlf_waiver}')"
fi

## --- fixer TOCTOU: a symlink swapped in after the scan is not followed --------
## from_disk refuses a symlink when the context is BUILT; apply_fixes must refuse
## to write through one that replaces the path afterwards. Canary: a plain open()
## followed the symlink and overwrote an arbitrary victim file.
victim="${test_dir}/victim.txt"
target="${test_dir}/target.sh"
printf '%s\n' 'VICTIM ORIGINAL' > "${victim}"
## A fixable file (trailing whitespace) so apply_fixes actually wants to write.
printf '%s\n' '#!/bin/bash' 'true   ' > "${target}"
toctou="$(python3 -c '
import os, sys
from dist_ai import context, engine
target, victim = sys.argv[1], sys.argv[2]
ctx = context.FileContext.from_disk(target)     ## built against the regular file
os.remove(target); os.symlink(victim, target)   ## swap in a symlink to the victim
engine.apply_fixes(ctx, check=False)            ## must NOT write through it
with open(victim) as handle:
    print(handle.read().strip())
' "${target}" "${victim}")"
if [ "${toctou}" = "VICTIM ORIGINAL" ]; then
   note_pass "fixer write refuses a symlink swapped in after the scan"
else
   note_fail "fixer followed a swapped-in symlink and clobbered the victim (got '${toctou}')"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-engine-hardening: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "pre-push-engine-hardening: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
