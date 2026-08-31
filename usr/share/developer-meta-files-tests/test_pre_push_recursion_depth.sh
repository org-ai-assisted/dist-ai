#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the dist-ai-style tree walkers must be ITERATIVE, so a deeply nested
## command tree (a ~2000-stage '&&' chain -> a ~2000-deep BinaryCmd tree) does NOT
## exceed Python's recursion limit and crash the linter. Both walkers were recursive
## (bash_ast.iter_nodes, _helpers.statements) and every rule depends on them, so a
## crafted deep file crashed --detect (exit 3, whole-batch abort) and --fix (bare
## traceback). Drives the REAL shipped tool. Also asserts per-file containment: even
## if some other deep recursion remained, --detect/--fix must not abort with an
## uncaught traceback.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

for dep in python3 shfmt safe-rm ; do
   if ! has "${dep}" ; then
      printf '%s\n' "FATAL: '${dep}' not on PATH" >&2
      exit 1
   fi
done

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${tool_dir}/../../bin/dist-ai-style"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
fi
## FATAL, not a vacuous pass: an absent gate would make every 'no crash' assertion pass
## over a command that never ran (rc=127 is not rc=3 and prints no crash marker).
if [ ! -x "${GATE}" ]; then
   printf '%s\n' "FATAL: dist-ai-style not executable at '${GATE}'" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

fail=0

## Two deep shapes, each hitting a DIFFERENT recursive walker (the pre-fix code crashed at
## ~500 nesting levels; each atom is harmless):
##  - a ~2000-stage '&&' chain  -> the statements() / iter_nodes walkers;
##  - a ~2000-deep nested BRACE-GROUP handler on a R-063 guard's '||' -> the _exit_kind walker
##    ('check_variable_name x || { { { ...; return 1; } } }'). _exit_kind runs only for a
##    'check_variable_name ... ||' guard, so the left MUST be that name; a &&-chain never reaches it.
deep_and="${test_dir}/deep-and.sh"
{
   printf '%s\n' '#!/bin/bash'
   python3 -c 'print(" && ".join(["true"] * 2000))'
} > "${deep_and}"
deep_block="${test_dir}/deep-block.sh"
{
   printf '%s\n' '#!/bin/bash'
   python3 -c 'n = 2000; print("check_variable_name x || " + "{ " * n + "return 1; " + "} " * n)'
} > "${deep_block}"

## A crash shows as a Python traceback / RecursionError, the gate's own internal-crash exit 3,
## or a synthesized 'gate-crash' finding. None may appear. $1 file, $2 mode, $3 label.
assert_no_crash() {
   local file="$1" mode="$2" label="$3" out rc=0
   out="$("${GATE}" "${mode}" "${file}" 2>&1)" || rc="$?"
   if grep --quiet --extended-regexp \
      'RecursionError|Traceback \(most recent|gate-crash' <<< "${out}"; then
      printf '%s\n' "FAIL: ${mode} crashed on ${label}:" >&2
      printf '%s\n' "${out}" | tail -5 >&2
      fail=1
   elif [ "${rc}" -eq 3 ]; then
      printf '%s\n' "FAIL: ${mode} exited 3 (internal crash) on ${label}" >&2
      fail=1
   else
      printf '%s\n' "PASS: ${mode} walks ${label} without crashing (rc=${rc})"
   fi
}

assert_no_crash "${deep_and}"   --detect 'a ~2000-deep && chain'
assert_no_crash "${deep_and}"   --fix    'a ~2000-deep && chain'
assert_no_crash "${deep_block}" --detect 'a ~2000-deep nested brace-group'
assert_no_crash "${deep_block}" --fix    'a ~2000-deep nested brace-group'

## --fix must leave the (already-compliant) &&-chain byte-identical, never mangle it.
if [ "$(cksum < "${deep_and}")" = "$(python3 -c 'print("#!/bin/bash"); print(" && ".join(["true"]*2000))' | cksum)" ]; then
   printf '%s\n' 'PASS: --fix left the && chain unmodified'
else
   printf '%s\n' 'FAIL: --fix modified the && chain' >&2
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
