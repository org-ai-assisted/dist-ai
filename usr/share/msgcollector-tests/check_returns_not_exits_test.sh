#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## msgcollector's check() must RETURN non-zero on failure -- never exit(), and
## never lean on errexit to abort. Its callers use 'if ! check ...', where
## errexit is disabled in the condition: a check() that exit()s kills the whole
## caller (uncaught by 'if !'), and one that lets a failed sub-check fall through
## returns success on invalid input. Both are silent correctness bugs.
##
## Drives the REAL check() -- extracted from the shipped file -- with the two
## sub-checks stubbed (and unicode-show stubbed on PATH), so no helper-scripts,
## no root and no bwrap are needed. For each failing sub-check it asserts that an
## 'if ! check' caller both CATCHES the failure and CONTINUES afterwards (proof
## check() returned rather than exited the caller).
## style-ok: no-has

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

rel='usr/libexec/msgcollector/check'
candidates=()
[ -z "${MSGCOLLECTOR_REPO:-}" ] || candidates+=( "${MSGCOLLECTOR_REPO}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/msgcollector/${rel}" )
candidates+=( "/${rel}" )
check_file=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      check_file="${candidate}"
      break
   fi
done
if [ -z "${check_file}" ]; then
   printf '%s\n' "SKIP: msgcollector 'check' not found (set MSGCOLLECTOR_REPO)." >&2
   exit 77
fi

workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## Extract the real msgcollector_check() function body, so the test exercises
## shipped code rather than a reimplementation (and does not source the file's
## strings.bsh).
check_fn="${workdir}/check_fn.bash"
sed -n '/^msgcollector_check()/,/^}/p' -- "${check_file}" > "${check_fn}"
if [ ! -s "${check_fn}" ]; then
   printf '%s\n' "FAIL: could not extract msgcollector_check() from ${check_file}" >&2
   exit 1
fi
## The sed range ends at the first unindented '}'; verify the extracted fragment
## is a complete, parseable function so a reformatted definition cannot yield a
## truncated or overlong fragment that silently mis-tests.
if ! bash -n "${check_fn}" 2>/dev/null; then
   printf '%s\n' "FAIL: extracted msgcollector_check() does not parse (incomplete extraction)" >&2
   exit 1
fi

## Stub 'unicode-show' on PATH (a hyphenated name cannot be a shell function).
## It drains stdin and exits ${RC_UNICODE:-0}.
stub_bin="${workdir}/bin"
mkdir --parents -- "${stub_bin}"
printf '%s\n' '#!/bin/bash' 'cat >/dev/null 2>&1 || true' 'exit "${RC_UNICODE:-0}"' \
   > "${stub_bin}/unicode-show"
chmod 0755 -- "${stub_bin}/unicode-show"

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

## Drive msgcollector_check() through an 'if ! msgcollector_check' caller in a
## subshell under errexit, with the sub-checks stubbed via the environment.
## Echoes 'CAUGHT' or 'PASSED', then ':CONTINUED' -- the latter appears ONLY if
## msgcollector_check() returned (did not exit the subshell). RC_NOTEMPTY /
## RC_ALNUM / RC_UNICODE select which sub-check fails.
drive() {
   RC_NOTEMPTY="$1" RC_ALNUM="$2" RC_UNICODE="$3" \
   PATH="${stub_bin}:${PATH}" CHECK_FN="${check_fn}" bash -c '
      set -o errexit
      set -o nounset
      stecho() { printf "%s\n" "$*" >&2; }
      check_is_not_empty_and_only_one_line() { return "${RC_NOTEMPTY}"; }
      check_is_alpha_numeric() { return "${RC_ALNUM}"; }
      # shellcheck disable=SC1090
      source "${CHECK_FN}"
      if ! msgcollector_check "x"; then printf "%s" "CAUGHT"; else printf "%s" "PASSED"; fi
      printf "%s" ":CONTINUED"
   ' 2>/dev/null || true
}

## All sub-checks pass -> check returns 0; caller sees success and continues.
got="$(drive 0 0 0)"
[ "${got}" = "PASSED:CONTINUED" ] \
   && pass "all valid -> caller sees success, continues (${got})" \
   || fail "all valid: expected 'PASSED:CONTINUED', got '${got}'"

## First sub-check (not-empty/one-line) fails. The bug: with errexit disabled in
## the 'if !' condition, an unguarded failure falls through and check returns 0.
got="$(drive 1 0 0)"
[ "${got}" = "CAUGHT:CONTINUED" ] \
   && pass "not-empty failure -> caught + continued (returned, not fell through)" \
   || fail "not-empty failure: expected 'CAUGHT:CONTINUED', got '${got}'"

## unicode-show fails. The bug: the old path exit()ed here, killing the caller,
## so neither CAUGHT nor CONTINUED would appear.
got="$(drive 0 0 1)"
[ "${got}" = "CAUGHT:CONTINUED" ] \
   && pass "unicode failure -> caught + continued (returned, not exited)" \
   || fail "unicode failure: expected 'CAUGHT:CONTINUED', got '${got}'"

## Last sub-check (alpha-numeric) fails -> caught + continued.
got="$(drive 0 1 0)"
[ "${got}" = "CAUGHT:CONTINUED" ] \
   && pass "alpha-numeric failure -> caught + continued" \
   || fail "alpha-numeric failure: expected 'CAUGHT:CONTINUED', got '${got}'"

if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${fail_count} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: check() returns on failure, callers catch and continue (${pass_count} assertions)."
