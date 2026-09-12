#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: msgprogress safe_file_write() must not FREEZE when its target is
## a reader-less FIFO. It exists specifically to bound that write with a timeout,
## but if the '> "$2"' redirection runs in the CALLING shell, open() on a
## reader-less FIFO blocks BEFORE timeout starts -- the freeze the guard was
## meant to prevent. The fix runs the redirect INSIDE the timeout'd bash. This
## test extracts the REAL safe_file_write and drives it against a reader-less
## FIFO, asserting it returns promptly (wall-clock), not only that it exits.
##
## Subject resolution follows the dist-ai convention: the script under test lives
## at ${MSGCOLLECTOR_REPO:-}/usr/libexec/msgcollector/msgprogress (unset ->
## /usr/libexec/msgcollector, i.e. the installed package).

set -o errexit
set -o nounset
set -o errtrace
set -o pipefail
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""
msgcollector_libexec="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector"

if [ ! -r "${msgcollector_libexec}/msgprogress" ]; then
  printf '%s\n' "$0: FATAL: msgprogress not found at '${msgcollector_libexec}/msgprogress'" >&2
  printf '%s\n' "$0: set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
  exit 1
fi

PASS=0
FAIL=0

pass() {
  printf '%s\n' "$0: PASS: $1"
  PASS=$(( PASS + 1 ))
}

fail() {
  printf '%s\n' "$0: FAIL: $1" >&2
  FAIL=$(( FAIL + 1 ))
}

work_dir="$(mktemp --directory)"
cleanup_handler() {
  ## Invoked via trap, not called directly.
  # shellcheck disable=SC2317
  safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup_handler EXIT

test_safe_file_write_does_not_hang_on_readerless_fifo() {
  local func fifo runner start end elapsed

  func="$(sed -n '/^safe_file_write() {/,/^}/p' "${msgcollector_libexec}/msgprogress")"
  if [ -z "${func}" ]; then
    fail "safe_file_write not found in msgprogress"
    return
  fi

  fifo="${work_dir}/readerless_fifo"
  mkfifo -- "${fifo}"

  ## Run the extracted function in a child; give it a generous OUTER timeout that
  ## only fires if the function itself froze (the bug). The function's own inner
  ## timeout should return in ~1s; the outer window is 6s.
  runner="${work_dir}/run_sfw.sh"
  {
    printf '%s\n' '#!/bin/bash'
    printf '%s\n' "${func}"
    printf '%s\n' "safe_file_write 'payload' '${fifo}'"
  } > "${runner}"
  chmod +x -- "${runner}"

  start="$(date +%s)"
  timeout --kill-after=2 6 "${runner}" >/dev/null 2>&1 || true
  end="$(date +%s)"
  elapsed=$(( end - start ))

  ## Fixed: the inner 1s timeout fires, so the child returns in ~1-2s. Buggy: the
  ## caller-shell open() blocks and only the 6s OUTER timeout ends it.
  if [ "${elapsed}" -lt 4 ]; then
    pass "safe_file_write returns promptly (~${elapsed}s) on a reader-less FIFO"
  else
    fail "safe_file_write hung (~${elapsed}s) on a reader-less FIFO -- redirect not under the inner timeout"
  fi
}

test_safe_file_write_writes_a_regular_file() {
  local func out

  func="$(sed -n '/^safe_file_write() {/,/^}/p' "${msgcollector_libexec}/msgprogress")"
  out="${work_dir}/regular_out"
  ( eval "${func}"; safe_file_write "regular-value" "${out}" )
  if [ -f "${out}" ] && [ "$(cat -- "${out}")" = "regular-value" ]; then
    pass "safe_file_write writes the value to a regular file"
  else
    fail "safe_file_write did not write the expected value to a regular file (got '$(cat -- "${out}" 2>/dev/null)')"
  fi
}

test_safe_file_write_does_not_hang_on_readerless_fifo
test_safe_file_write_writes_a_regular_file

printf '%s\n' "$0: Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne "0" ]; then
  exit 1
fi
exit 0
