#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for the python-shebang style rule: a file whose FIRST line
## names a python interpreter must carry the hardened '#!/usr/bin/python3 -Bsu'
## (-B no bytecode, -s no user site-packages, -u unbuffered). Asserts, against
## the real shipped dist-ai-style CLI:
##   * --check FLAGS every non-hardened python shebang (env form, bare, a partial
##     flag set '-su'/'-u', a versioned name) and SPARES the canonical form;
##   * --fix REWRITES each to the canonical line and leaves the rest of the file;
##   * a NON-python shebang, a shebang-LESS module, and a file bearing the
##     '## style-ok: allow-python-shebang' waiver are all left untouched.
## Assertions key on the 'python-shebang' rule TAG, never the exit code -- a
## '#!/bin/bash' fixture exits non-zero on unrelated shell rules, so an exit-code
## check would conflate them.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Fail closed: a missing prerequisite is an environment defect, never a skip.
assert_prerequisite() {
   local description
   description="$1"
   shift
   if ! "$@"; then
      printf '%s\n' "FATAL: test_pre_push_static_python_shebang: ${description}" >&2
      exit 1
   fi
}

assert_prerequisite \
   'helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)' \
   test -r '/usr/libexec/helper-scripts/has.sh'
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

assert_prerequisite 'safe-rm not on PATH' has safe-rm

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/),
## in-tree FIRST so a developer edits and tests the same copy; fall back to the
## packaged CLI. PRE_PUSH_STATIC_BIN aims the suite at an alternate copy (e.g. a
## pre-fix canary run).
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
STYLE="${PRE_PUSH_STATIC_BIN:-${gate_test_dir}/../../bin/dist-ai-style}"
if [ ! -x "${STYLE}" ]; then
   STYLE='/usr/bin/dist-ai-style'
fi
[ -x "${STYLE}" ] \
   || { printf '%s\n' "error: gate not executable at '${STYLE}'." >&2; exit 1; }

tmp_root="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${tmp_root}"
}
trap cleanup EXIT

failures=0

## Write CONTENT to a fresh .py fixture and echo its path.
fixture() {
   local content path
   content="$1"
   path="$(mktemp --tmpdir="${tmp_root}" fixture.XXXXXX.py)"
   printf '%s' "${content}" > "${path}"
   printf '%s' "${path}"
}

## expect_flag <label> <content> <present|absent>
## Assert '--check' does / does not report the python-shebang rule for CONTENT.
expect_flag() {
   local label content want path out got
   label="$1"
   content="$2"
   want="$3"
   path="$(fixture "${content}")"
   out="$("${STYLE}" --check -- "${path}" 2>&1 || true)"
   case "${out}" in
      *python-shebang*)
         got='present'
         ;;
      *)
         got='absent'
         ;;
   esac
   if [ "${got}" != "${want}" ]; then
      printf 'FAIL [%s]: python-shebang expected %s, got %s\n' \
         "${label}" "${want}" "${got}" >&2
      failures=$((failures + 1))
   fi
}

## expect_fix <label> <content> <expected-first-line>
## Assert '--fix' rewrites the fixture and its FIRST line equals the expectation.
expect_fix() {
   local label content want path first
   label="$1"
   content="$2"
   want="$3"
   path="$(fixture "${content}")"
   "${STYLE}" --fix -- "${path}" >/dev/null 2>&1 || true
   first="$(head --lines=1 -- "${path}")"
   if [ "${first}" != "${want}" ]; then
      printf 'FAIL [%s]: first line after --fix expected %q, got %q\n' \
         "${label}" "${want}" "${first}" >&2
      failures=$((failures + 1))
   fi
}

canonical='#!/usr/bin/python3 -Bsu'

## --check: every non-hardened python shebang is flagged.
expect_flag 'env form flagged'       '#!/usr/bin/env python3
import os
' present
expect_flag 'bare python3 flagged'   '#!/usr/bin/python3
x = 1
' present
expect_flag 'partial -su flagged'    '#!/usr/bin/python3 -su
x = 1
' present
expect_flag 'only -u flagged'        '#!/usr/bin/python3 -u
x = 1
' present
expect_flag 'versioned flagged'      '#!/usr/bin/python3.11
x = 1
' present

## --check: the canonical line, a non-python shebang, a shebang-less module, and
## a waived file are all spared.
expect_flag 'canonical spared'       "${canonical}"'
x = 1
' absent
expect_flag 'non-python spared'      '#!/bin/bash
true
' absent
expect_flag 'shebang-less spared'    'import os
x = 1
' absent
expect_flag 'waived spared'          '#!/usr/bin/python3
## style-ok: allow-python-shebang
x = 1
' absent

## --fix: each non-hardened python shebang is rewritten to the canonical line.
expect_fix 'env form fixed'          '#!/usr/bin/env python3
import os
' "${canonical}"
expect_fix 'bare fixed'              '#!/usr/bin/python3
x = 1
' "${canonical}"
expect_fix 'partial -su fixed'       '#!/usr/bin/python3 -su
x = 1
' "${canonical}"

## --fix: the untouched cases keep their first line verbatim.
expect_fix 'canonical unchanged'     "${canonical}"'
x = 1
' "${canonical}"
expect_fix 'non-python unchanged'    '#!/bin/bash
true
' '#!/bin/bash'
expect_fix 'shebang-less unchanged'  'import os
x = 1
' 'import os'
expect_fix 'waived unchanged'        '#!/usr/bin/python3
## style-ok: allow-python-shebang
x = 1
' '#!/usr/bin/python3'

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "test_pre_push_static_python_shebang: ${failures} assertion(s) FAILED." >&2
   exit 1
fi

printf '%s\n' "test_pre_push_static_python_shebang: OK -- python-shebang rule flags every non-hardened form (env / bare / -su / -u / versioned), fixes each to '#!/usr/bin/python3 -Bsu', and spares the canonical line, a non-python shebang, a shebang-less module, and a waived file."
