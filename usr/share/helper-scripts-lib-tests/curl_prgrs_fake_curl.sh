#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Deterministic 'curl' stand-in for curl_prgrs_test.sh: a stub for the one
## genuine network dependency, so the real curl-prgrs orchestration, size
## checks, progress and signal handling run offline and reproducibly. Behaviour
## is entirely env-driven:
##
##   FAKE_CURL_HEADER_CL       stdout for a '--head' request -- the value
##                             curl-prgrs parses as the Content-Length (default 0)
##   FAKE_CURL_HEADER_EXIT     exit code for a '--head' request (default 0)
##   FAKE_CURL_HEADER_FILE_BYTES  size to grow $CURL_OUT_FILE to on a '--head'
##                             request (default 0 = leave it absent). Real curl
##                             writes the response headers to --output, so this
##                             lets a test exercise the header-phase size ceiling.
##   FAKE_CURL_BODY_BYTES      final size to grow $CURL_OUT_FILE to (default 0)
##   FAKE_CURL_BODY_STEPS      grow the body in N increments (default 1), so the
##                             poll loop iterates and redraws progress
##   FAKE_CURL_BODY_STEP_SLEEP seconds between increments (default 0)
##   FAKE_CURL_BODY_PRESLEEP   seconds to idle before writing (for signal tests,
##                             so a SIGTERM lands mid-download)
##   FAKE_CURL_BODY_EXIT       exit code for a body request (default 0)
##   FAKE_CURL_BODY_NO_FILE    if 1, never create $CURL_OUT_FILE (exercises the
##                             'no file on disk yet' arm of the poll loop)
##
## A '--head' request is detected by the flag curl-prgrs itself passes; every
## other invocation is a body download. The file is grown with 'truncate' (a
## sparse file whose 'stat --format=%s' size is all curl-prgrs inspects).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

is_head=0
for arg in "$@"; do
  if [ "${arg}" = "--head" ]; then
    is_head=1
    break
  fi
done

if [ "${is_head}" = "1" ]; then
  ## Real curl writes the response headers to --output; mirror that so a test can
  ## drive the header-phase size ceiling. Sparse file -- only its stat size matters.
  if [ "${FAKE_CURL_HEADER_FILE_BYTES:-0}" != "0" ] && [ -n "${CURL_OUT_FILE:-}" ]; then
    truncate --size="${FAKE_CURL_HEADER_FILE_BYTES}" -- "${CURL_OUT_FILE}"
  fi
  printf '%s' "${FAKE_CURL_HEADER_CL:-0}"
  exit "${FAKE_CURL_HEADER_EXIT:-0}"
fi

out="${CURL_OUT_FILE:-}"
if [ -z "${out}" ]; then
  printf '%s\n' "curl_prgrs_fake_curl: CURL_OUT_FILE is unset" >&2
  exit 99
fi

total="${FAKE_CURL_BODY_BYTES:-0}"
steps="${FAKE_CURL_BODY_STEPS:-1}"
[ "${steps}" -ge 1 ] || steps=1
presleep="${FAKE_CURL_BODY_PRESLEEP:-0}"
step_sleep="${FAKE_CURL_BODY_STEP_SLEEP:-0}"

if [ "${FAKE_CURL_BODY_NO_FILE:-0}" = "1" ]; then
  ## Leave $CURL_OUT_FILE nonexistent: idle (so the poll loop iterates at least
  ## once seeing no file), then exit without ever creating it.
  if [ "${presleep}" != "0" ]; then
    sleep "${presleep}"
  else
    sleep 0.1
  fi
  exit "${FAKE_CURL_BODY_EXIT:-0}"
fi

truncate --size=0 -- "${out}"

if [ "${presleep}" != "0" ]; then
  sleep "${presleep}"
fi

i=0
while [ "${i}" -lt "${steps}" ]; do
  i=$(( i + 1 ))
  target=$(( total * i / steps ))
  truncate --size="${target}" -- "${out}"
  if [ "${i}" -lt "${steps}" ] && [ "${step_sleep}" != "0" ]; then
    sleep "${step_sleep}"
  fi
done

exit "${FAKE_CURL_BODY_EXIT:-0}"
