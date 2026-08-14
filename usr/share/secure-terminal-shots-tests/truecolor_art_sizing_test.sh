#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: st_size_viewport_payload (comparison-capture.sh) turns the live viewport geometry in
## ~/.st_geom ("ROWS COLS" from stty) into a viewport-sized art.payload, and leaves the
## pre-generated fallback untouched when the geometry is unreadable. Guards the glue that a
## real-GUI shot cannot regression-test offline: field order (ROWS then COLS), the rows-2
## sizing, and every fallback branch.
##
## Extracts the function VERBATIM from the real script (between its BEGIN/END sentinels) and
## drives it with the real truecolor-art.py -- no reimplementation, so it cannot drift from the
## source. Subjects: comparison-capture.sh + truecolor-art.py in secure-terminal-shots/
## (absent -> exit 77 SKIP). Pure shell + Python stdlib, no display.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
measure="${script_dir}/art_dims.py"

shots_dir=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}" \
   "${script_dir}/../secure-terminal-shots" \
   "${script_dir}/../../share/secure-terminal-shots" \
   '/usr/share/secure-terminal-shots'; do
   if [ -n "${cand}" ] && [ -d "${cand}" ] \
      && [ -f "${cand}/comparison-capture.sh" ] && [ -f "${cand}/truecolor-art.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'SKIP: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi
src="${shots_dir}/comparison-capture.sh"

## Extract st_size_viewport_payload verbatim between the sentinels the source carries for this test.
fn="$(sed -n '/## BEGIN st_size_viewport_payload/,/## END st_size_viewport_payload/p' "${src}")"
case "${fn}" in
   *'st_size_viewport_payload() {'*)
      ;;
   *)
      printf '%s\n' 'FAIL: could not extract st_size_viewport_payload (BEGIN/END sentinels moved?)' >&2
      exit 1
      ;;
esac
eval "${fn}"

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## The function reads ~/.st_geom and writes ~/art.payload, resolving the generator via ${here}.
export HOME="${work}"
here="${shots_dir}"

pass=0
fail=0

## Compare the current art.payload's (width, rows) against the expectation. art_dims.py prints
## "<rows> <widths...> <SAFE|UNSAFE>"; a uniform scene yields "<rows> <width> SAFE", so rows is
## the first field and width the second. A missing/empty payload reports 0/0.
expect() {  ## $1=label $2=want_width $3=want_rows [$4=payload basename, default art.payload]
   local label="$1" ww="$2" wr="$3" pf="${4:-art.payload}" gr gw meas rest
   if [ ! -s "${HOME}/${pf}" ]; then
      gr=0
      gw=0
   else
      meas="$(python3 "${measure}" "${HOME}/${pf}")"
      gr="${meas%% *}"
      rest="${meas#* }"
      gw="${rest%% *}"
   fi
   if [ "${gw}" = "${ww}" ] && [ "${gr}" = "${wr}" ]; then
      printf '%s\n' "PASS: ${label} (width=${gw} rows=${gr})"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} expected width=${ww} rows=${wr}, got width=${gw} rows=${gr}"
      fail=$(( fail + 1 ))
   fi
}

## Sentinel fallback payload -- a distinct 8x4 scene the function must OVERWRITE on good geom
## and PRESERVE on bad geom. Regenerated fresh before each case.
seed_fallback() {
   "${shots_dir}/truecolor-art.py" --cols 8 --rows 4 > "${HOME}/art.payload"
}

## Good geometry: "24 130" is ROWS=24 COLS=130 -> art sized 130 cols x (24-2)=22 rows.
## A field-order bug (COLS then ROWS) would size 24 cols x 128 rows -- caught here.
seed_fallback
printf '%s\n' '24 130' > "${HOME}/.st_geom"
st_size_viewport_payload truecolor-art.py art.payload
expect 'good geom 24x130 -> 130 cols x 22 rows' '130' '22'

## The generator + payload basenames are honoured: sizing the gradient board writes
## gradient.payload (not art.payload) at the same viewport-derived dimensions.
if [ -f "${shots_dir}/truecolor-gradient.py" ]; then
   "${shots_dir}/truecolor-gradient.py" --cols 8 --rows 4 > "${HOME}/gradient.payload"
   printf '%s\n' '24 130' > "${HOME}/.st_geom"
   st_size_viewport_payload truecolor-gradient.py gradient.payload
   expect 'gradient board sized via same glue -> 130 cols x 22 rows' '130' '22' gradient.payload
fi

## Trailing garbage / extra fields are rejected (case guard), fallback preserved (8x4).
seed_fallback
printf '%s\n' '24 130 extra' > "${HOME}/.st_geom"
st_size_viewport_payload truecolor-art.py art.payload
expect 'extra field -> fallback preserved' '8' '4'

## Only one field present -> fallback preserved.
seed_fallback
printf '%s\n' '45' > "${HOME}/.st_geom"
st_size_viewport_payload truecolor-art.py art.payload
expect 'single field -> fallback preserved' '8' '4'

## Non-numeric -> fallback preserved.
seed_fallback
printf '%s\n' 'abc def' > "${HOME}/.st_geom"
st_size_viewport_payload truecolor-art.py art.payload
expect 'non-numeric -> fallback preserved' '8' '4'

## Degenerate viewport (rows so small scene_rows = rows-2 < 2) -> fallback preserved.
seed_fallback
printf '%s\n' '2 130' > "${HOME}/.st_geom"
st_size_viewport_payload truecolor-art.py art.payload
expect 'too-short viewport -> fallback preserved' '8' '4'

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: st_size_viewport_payload sizes to the live viewport and falls back safely'
