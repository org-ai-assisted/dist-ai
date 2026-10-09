#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: a '.bash' file is classified as SHELL by extension, even with
## no shebang. dist-ai-style once recognized only '.sh'/'.bsh' by extension, so a
## shebang-less '.bash' file was classified as non-shell and ALL shell rules were
## silently skipped for it -- a coverage hole. Asserts, against the real shipped
## CLI, that '--check' runs the shell rules on a shebang-less '.bash' file:
##   * a violation (inline python, R-193) IS flagged;
##   * CANARY: a clean, fully-strict '.bash' file is SPARED (not flag-always).
## Keys on the rule TAG, never the exit code.

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
      printf '%s\n' "FATAL: test_pre_push_static_bash_extension: ${description}" >&2
      exit 1
   fi
}
assert_prerequisite 'safe-rm not on PATH' command -v safe-rm

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/),
## in-tree FIRST; fall back to the packaged CLI. PRE_PUSH_STATIC_BIN aims the
## suite at an alternate copy (e.g. a pre-fix canary run).
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
STYLE="${PRE_PUSH_STATIC_BIN:-${gate_test_dir}/../../bin/dist-ai-style}"
if [ ! -x "${STYLE}" ]; then
   STYLE='/usr/bin/dist-ai-style'
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass_count=0
fail_count=0
check() {
   local label="$1" condition="$2"
   if [ "${condition}" = 'yes' ]; then
      pass_count=$(( pass_count + 1 )); printf '%s\n' "ok   - ${label}"
   else
      fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL - ${label}" >&2
   fi
}

## Flags a rule TAG on FILE (a --check run whose output names the tag). Capture
## the output FIRST, then grep: --check exits 1 on findings, so a piped grep under
## pipefail would report the run's rc, not grep's (a false 'no' even on a match).
flags_tag() {
   local file="$1" tag="$2" out
   out="$("${STYLE}" --check -- "${file}" 2>&1 || true)"
   ## Literal substring match ("${tag}" is quoted, so a glob char in it stays
   ## literal) -- no 'cmd | grep -q' pipe (R-161) and no subprocess.
   case "${out}" in
      *"${tag}"*)
         printf '%s\n' "yes"
         ;;
      *)
         printf '%s\n' "no"
         ;;
   esac
}

## Shebang-less .bash with inline python: the shell rule R-193 must fire, which
## proves the file was classified as shell (else no shell rule runs).
violation="${work}/inline.bash"
printf '%s\n' "python3 -c 'print(1)'" > "${violation}"
check "shebang-less .bash: R-193 flagged (classified as shell)" \
   "$(flags_tag "${violation}" 'R-193')"

## CANARY: a clean, fully-strict .bash file is spared, so the classification is
## not flag-always. A shebang-less .bash still needs the strict block (it is a
## shell file now), so the canary carries the full seven directives.
clean="${work}/clean.bash"
{
   printf '%s\n' 'set -o errexit'
   printf '%s\n' 'set -o nounset'
   printf '%s\n' 'set -o pipefail'
   printf '%s\n' 'set -o errtrace'
   printf '%s\n' 'shopt -s inherit_errexit'
   printf '%s\n' 'shopt -s shift_verbose'
   printf '%s\n' 'export LC_ALL=C'
   printf '%s\n' 'true'
} > "${clean}"
clean_rc=0
"${STYLE}" --check -- "${clean}" >/dev/null 2>&1 || clean_rc=$?
check "clean fully-strict .bash is spared (rc 0)" \
   "$( [ "${clean_rc}" -eq 0 ] && printf '%s\n' "yes" || printf '%s\n' "no" )"

printf '%s\n' "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
