#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for the python-shell-guard style rule, against the real shipped
## dist-ai-style CLI. The rule requires a usr/bin PYTHON ENTRY POINT to carry the
## shell-invocation guard line before its first import (so 'bash <tool>' re-execs
## python3 instead of running its 'import' line as ImageMagick's 'import' ->
## XGrabServer -> whole-GUI freeze). It asserts:
##   * --check FLAGS a usr/bin python entry point lacking the guard (with OR without
##     a module docstring) and SPARES a guarded one, a waived one, a non-python
##     shebang, and a shebang-less module;
##   * SCOPE: a python entry point OUTSIDE usr/bin (usr/libexec, repo root) is NOT
##     flagged -- the rule is scoped to the model-invoked usr/bin surface;
##   * --fix INSERTS the guard into a no-docstring entry point (and the result still
##     COMPILES with the guard BEFORE the first import), but does NOT touch a
##     docstring-bearing file (no __doc__ demotion), which stays flagged for a human.
## Assertions key on the 'python-shell-guard' rule TAG / the guard line, never the
## exit code -- a fixture trips unrelated rules whose exit code would conflate them.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

assert_prerequisite() {
   local description
   description="$1"
   shift
   if ! "$@"; then
      printf '%s\n' "FATAL: test_pre_push_static_python_shell_guard: ${description}" >&2
      exit 1
   fi
}

assert_prerequisite \
   'helper-scripts has.bsh is not installed (/usr/libexec/helper-scripts/has.bsh)' \
   test -r '/usr/libexec/helper-scripts/has.bsh'
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

assert_prerequisite 'safe-rm not on PATH' has safe-rm
assert_prerequisite 'python3 not on PATH' has python3

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/),
## in-tree FIRST; fall back to the packaged CLI. PRE_PUSH_STATIC_BIN aims the suite
## at an alternate copy.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
STYLE="${PRE_PUSH_STATIC_BIN:-${gate_test_dir}/../../bin/dist-ai-style}"
if [ ! -x "${STYLE}" ]; then
   STYLE='/usr/bin/dist-ai-style'
fi
[ -x "${STYLE}" ] \
   || { printf '%s\n' "error: gate not executable at '${STYLE}'." >&2; exit 1; }

guard_line='"exec" "python3" "-Bsu" "$0" "$@"'

tmp_root="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${tmp_root}"
}
trap cleanup EXIT

failures=0

## Write CONTENT to REL (a repo-relative path under tmp_root, e.g. usr/bin/tool),
## creating parent dirs; echo the absolute path. The rule keys on the usr/bin path,
## so a fixture MUST live at its true relative location.
fixture() {
   local rel content path
   rel="$1"
   content="$2"
   path="${tmp_root}/${rel}"
   mkdir --parents -- "$(dirname -- "${path}")"
   printf '%s' "${content}" > "${path}"
   printf '%s' "${path}"
}

## expect_flag <label> <rel> <content> <present|absent>
expect_flag() {
   local label rel content want path out got
   label="$1"
   rel="$2"
   content="$3"
   want="$4"
   path="$(fixture "${rel}" "${content}")"
   out="$("${STYLE}" --check -- "${path}" 2>&1 || true)"
   case "${out}" in
      *python-shell-guard*)
         got='present'
         ;;
      *)
         got='absent'
         ;;
   esac
   if [ "${got}" != "${want}" ]; then
      printf 'FAIL [%s]: python-shell-guard expected %s, got %s\n' \
         "${label}" "${want}" "${got}" >&2
      failures=$((failures + 1))
   fi
}

## expect_guard <label> <rel> <content> <present|absent>
## Assert whether the guard line is in the file AFTER --fix.
expect_guard() {
   local label rel content want path got
   label="$1"
   rel="$2"
   content="$3"
   want="$4"
   path="$(fixture "${rel}" "${content}")"
   "${STYLE}" --fix -- "${path}" >/dev/null 2>&1 || true
   if grep --quiet --fixed-strings -- "${guard_line}" "${path}"; then
      got='present'
   else
      got='absent'
   fi
   if [ "${got}" != "${want}" ]; then
      printf 'FAIL [%s]: guard line after --fix expected %s, got %s\n' \
         "${label}" "${want}" "${got}" >&2
      failures=$((failures + 1))
   fi
}

nodoc='#!/usr/bin/python3 -Bsu

## a tool
import os
print(os.getpid())
'
doc='#!/usr/bin/python3 -Bsu

"""Module docstring some tools pass to argparse."""
import os
'
guarded='#!/usr/bin/python3 -Bsu

'"${guard_line}"'

import os
'
## ai-review canaries (all reproduced against the shipped rule):
## #1 guard text only inside a docstring is inert prose, not the guard statement.
docguard='#!/usr/bin/python3 -Bsu

"""demonstrates the guard pattern:
'"${guard_line}"'
in prose."""
import os
'
## #2 a ;-joined import before the guard still runs first under a shell.
semi='#!/usr/bin/python3 -Bsu

x = 1; import os
'"${guard_line}"'
import sys
'
## #4 a prefixed / parenthesized string is still a module docstring.
udoc='#!/usr/bin/python3 -Bsu

u"""Module docstring."""
import os
'
paren='#!/usr/bin/python3 -Bsu

("""Module docstring.""")
import os
'
## #3 a non-UTF-8 usr/bin entry point (stray 0xff) still needs the guard checked.
badutf8=$'#!/usr/bin/python3 -Bsu\n\n## invalid utf8: \xff\ncmd = 1\nimport os\n'
## grok re-review: a SAME-LINE import before the guard (ast gives both one lineno)
## still runs the import first under a shell -- order must be by statement, not line.
sameline='#!/usr/bin/python3 -Bsu

import os; '"${guard_line}"'
print(os.getpid())
'

## -- --check: flagged / spared -------------------------------------------------
expect_flag 'usr/bin no-guard no-doc flagged' 'usr/bin/tool_a' "${nodoc}" present
expect_flag 'usr/bin no-guard doc flagged'    'usr/bin/tool_b' "${doc}" present
expect_flag 'usr/bin guarded spared'          'usr/bin/tool_c' "${guarded}" absent
expect_flag 'usr/bin non-python spared'       'usr/bin/tool_d' '#!/bin/bash
true
' absent
expect_flag 'usr/bin shebang-less spared'     'usr/bin/tool_e' 'import os
x = 1
' absent
expect_flag 'usr/bin waived spared'           'usr/bin/tool_f' '#!/usr/bin/python3 -Bsu
## style-ok: allow-shell-guard
import os
' absent

## -- SCOPE: only usr/bin entry points ------------------------------------------
expect_flag 'usr/libexec out of scope'        'usr/libexec/dist-ai/helper.py' "${nodoc}" absent
expect_flag 'repo-root out of scope'          'tool_at_root.py' "${nodoc}" absent
expect_flag 'nested (not directly in bin)'    'usr/bin/sub/tool.py' "${nodoc}" absent

## -- --fix: insert only when safe ----------------------------------------------
expect_guard 'no-doc gets the guard'          'usr/bin/fix_a' "${nodoc}" present
expect_guard 'doc file NOT auto-guarded'      'usr/bin/fix_b' "${doc}" absent
expect_guard 'guarded stays guarded'          'usr/bin/fix_c' "${guarded}" present

## a docstring file stays flagged after --fix (detect-only, no __doc__ demotion).
## Capture the output (do NOT pipe --check into grep: --check exits non-zero on any
## finding and pipefail would mask the match).
doc_path="$(fixture 'usr/bin/fix_b_recheck' "${doc}")"
"${STYLE}" --fix -- "${doc_path}" >/dev/null 2>&1 || true
recheck_out="$("${STYLE}" --check -- "${doc_path}" 2>&1 || true)"
## '#*python-shell-guard' strips through the tag; unchanged string == tag ABSENT.
if [ "${recheck_out}" = "${recheck_out#*python-shell-guard}" ]; then
   printf 'FAIL [doc still flagged after --fix]: expected the rule to still report it\n' >&2
   failures=$((failures + 1))
fi

## -- behavioral canary: the fixed no-doc file COMPILES and the guard precedes the
## first import (a fix that produced broken or mis-ordered output must fail here).
canary_path="$(fixture 'usr/bin/canary' "${nodoc}")"
"${STYLE}" --fix -- "${canary_path}" >/dev/null 2>&1 || true
if ! python3 -m py_compile "${canary_path}" 2>/dev/null; then
   printf 'FAIL [canary]: fixed file does not compile as python\n' >&2
   failures=$((failures + 1))
fi
guard_ln="$(grep --line-number --fixed-strings -- "${guard_line}" "${canary_path}" | head --lines=1 | cut -d: -f1 || true)"
import_ln="$(grep --line-number --extended-regexp '^(import|from) ' "${canary_path}" | head --lines=1 | cut -d: -f1 || true)"
if [ -z "${guard_ln}" ] || [ -z "${import_ln}" ] || [ "${guard_ln}" -ge "${import_ln}" ]; then
   printf 'FAIL [canary]: guard (line %s) must precede first import (line %s)\n' \
      "${guard_ln:-none}" "${import_ln:-none}" >&2
   failures=$((failures + 1))
fi

## -- regression canaries for the ai-review findings (must fail on the pre-fix rule) --
expect_flag 'guard only in docstring not counted' 'usr/bin/rf_docguard' "${docguard}" present
expect_flag 'semicolon import before guard flagged' 'usr/bin/rf_semi' "${semi}" present
expect_flag 'same-line import before guard flagged' 'usr/bin/rf_sameline' "${sameline}" present
expect_flag 'non-utf8 missing guard flagged' 'usr/bin/rf_badutf8' "${badutf8}" present
expect_flag 'u-string docstring flagged (no guard)' 'usr/bin/rf_udoc' "${udoc}" present
expect_guard 'u-string docstring NOT auto-guarded' 'usr/bin/rf_udoc_fix' "${udoc}" absent
expect_guard 'parenthesized docstring NOT auto-guarded' 'usr/bin/rf_paren_fix' "${paren}" absent

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "test_pre_push_static_python_shell_guard: ${failures} failure(s)" >&2
   exit 1
fi
printf '%s\n' 'test_pre_push_static_python_shell_guard: PASS'
