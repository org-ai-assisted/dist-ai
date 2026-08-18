#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the GUI dialog message must NOT be capped by an argv-length
## limit. msgdispatcher's dispatch_x_active feeds the message body to
## msgdispatcher_dispatch_x.py on STDIN; a large accumulated message (e.g.
## systemcheck's verbose run with a big journal dump) must reach the renderer
## in full, or every later test silently vanishes from the GUI. Drives the REAL
## dispatch_x_active with a recorder stub in place of the PyQt renderer and
## asserts the recorder saw the whole body.
##
## Subject resolution follows the dist-ai convention: the scripts under test
## live at ${MSGCOLLECTOR_REPO:-}/usr/libexec/msgcollector/... (unset ->
## /usr/libexec/msgcollector, i.e. the installed package).

set -o errexit
set -o nounset
set -o errtrace
set -o pipefail
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""
msgcollector_libexec="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector"

if [ ! -r "${msgcollector_libexec}/msgdispatcher" ]; then
  printf '%s\n' "$0: SKIP: msgdispatcher not found at '${msgcollector_libexec}/msgdispatcher'" >&2
  printf '%s\n' "$0: set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
  exit 77
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

test_large_message_not_truncated() {
  local src func stub_py record body msg rc got_len

  src="${msgcollector_libexec}/msgdispatcher"
  func="$(sed -n '/^dispatch_x_active() {/,/^}/p' "${src}")"
  if [ -z "${func}" ]; then
    fail "dispatch_x_active not found in msgdispatcher"
    return
  fi

  ## Recorder stub in place of the PyQt renderer: save exactly the stdin body
  ## the renderer would receive, under a fake MSGCOLLECTOR_REPO layout.
  stub_py="${work_dir}/repo/usr/libexec/msgcollector/msgdispatcher_dispatch_x.py"
  mkdir --parents -- "$(dirname -- "${stub_py}")"
  record="${work_dir}/record"
  printf '%s\n' '#!/bin/bash' "cat > \"${record}\"" > "${stub_py}"
  chmod +x -- "${stub_py}"

  ## A body larger than an argv cap, with a tail sentinel that only survives if
  ## nothing was truncated.
  body="$(head -c 40000 /dev/zero | tr '\0' 'x')"
  msg="${body}__TAIL_SENTINEL__"

  rc=0
  (
    ## Isolated globals dispatch_x_active reads; verbose=1 runs the renderer in
    ## the foreground so the piped recorder finishes before we assert.
    MSGCOLLECTOR_REPO="${work_dir}/repo"
    msgcollector_run_dir="${work_dir}/repo"
    msgdispatcher_identifier="regressiontest"
    type="info"
    title="t"
    verbose="1"
    eval "${func}"
    dispatch_x_active "${type}" "${msg}"
  ) || rc=$?

  ## Guard the read: if dispatch_x_active errored before the recorder ran, the
  ## record file may not exist, and 'wc -c < missing' would abort under errexit
  ## before the assertion.
  got_len=0
  if [ -f "${record}" ]; then
    got_len="$(wc -c < "${record}")"
  fi
  if [ "${rc}" = "0" ] && [ -f "${record}" ] \
     && grep --quiet --fixed-strings -- "__TAIL_SENTINEL__" "${record}" \
     && [ "${got_len}" -ge "40000" ]; then
    pass "dispatch_x_active: full message reaches renderer (no argv truncation)"
  else
    fail "dispatch_x_active: message truncated/lost (rc=${rc} bytes=${got_len}, expected >=40000 with tail sentinel)"
  fi
}

test_large_message_not_truncated

printf '%s\n' "$0: Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne "0" ]; then
  exit 1
fi
exit 0
