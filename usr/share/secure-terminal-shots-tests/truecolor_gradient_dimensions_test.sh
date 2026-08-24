#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: truecolor-gradient.py (the 24-bit colour board) must honour --cols/--rows so the
## comparison-capture pass can pin the board to a fixed size, and must stay cat-safe: ONLY SGR
## colour, the U+2580 half-block,
## and newlines -- no cursor moves / clear / OSC. Asserts, per size: the board is exactly <cols>
## glyphs wide on every line and <rows> lines tall, and a degenerate 1-wide/1-tall canvas is
## rejected.
##
## FAILS on a tree without argparse (a fixed-size board): the panorama check would see the
## default width, not 130.
##
## Subject: truecolor-gradient.py in secure-terminal-shots/ (absent -> exit 77 SKIP). Pure
## Python stdlib, no display, no Qt -- runs in the dist-ai container in milliseconds.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
measure="${script_dir}/art_dims.py"

shots_dir=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}" \
   "${script_dir}/../secure-terminal-shots" \
   "${script_dir}/../../share/secure-terminal-shots" \
   '/usr/share/secure-terminal-shots'; do
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/truecolor-gradient.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi
gen="${shots_dir}/truecolor-gradient.py"

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0

check_size() {  ## $1=label $2=want_rows $3=want_cols $4...=argv
   local label="$1" want_rows="$2" want_cols="$3"; shift 3
   local rc=0 out="${work}/grad.out" got
   "${gen}" "$@" > "${out}" 2>"${work}/err.log" || rc=$?
   if [ "${rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: ${label} (generator rc=${rc})"
      sed 's/^/    /' "${work}/err.log" >&2 || true
      fail=$(( fail + 1 ))
      return
   fi
   got="$(python3 "${measure}" "${out}")"
   if [ "${got}" = "${want_rows} ${want_cols} SAFE" ]; then
      printf '%s\n' "PASS: ${label} (${want_rows} rows x ${want_cols} cols, cat-safe)"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} expected '${want_rows} ${want_cols} SAFE' got '${got}'"
      fail=$(( fail + 1 ))
   fi
}

reject() {  ## $1=label $2...=argv (must exit non-zero)
   local label="$1"; shift
   local rc=0
   "${gen}" "$@" >/dev/null 2>&1 || rc=$?
   if [ "${rc}" -ne 0 ]; then
      printf '%s\n' "PASS: ${label} rejected (rc=${rc})"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} accepted a degenerate canvas (rc=0)"
      fail=$(( fail + 1 ))
   fi
}

check_size 'default'          22 80
check_size 'board fill'       25 130 --cols 130 --rows 25
check_size 'tall + narrow'    40 60  --cols 60  --rows 40

reject '1-wide canvas'   --cols 1
reject '1-tall canvas'   --rows 1
reject '0-wide canvas'   --cols 0
## rows == 2 leaves no hue field above the greyscale ramp (all-grey board) -> rejected
reject '2-tall (all-grey) canvas'  --rows 2

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: truecolor-gradient.py honours --cols/--rows and stays cat-safe'
