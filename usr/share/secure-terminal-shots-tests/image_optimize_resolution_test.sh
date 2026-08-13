#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the shots harness must resolve the bundled image-optimize by a
## CHECKOUT-RELATIVE path, so a DIRECT comparison-capture.sh / wayland-capture.sh run (no
## secure-terminal-shots wrapper priming PATH) still finds it -- and fails FAST if missing,
## not after the whole capture. Pure shell: asserts the RESOLUTION, never runs the optimizer,
## so it needs no optipng/cwebp and runs in the dist-ai container in milliseconds.
##
## Subject: lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR, a checkout default, or
## the installed path. Absent -> exit 77 (SKIP), never FAIL.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/lib-capture.sh" \
   "${script_dir}/../secure-terminal-shots/lib-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/lib-capture.sh" \
   '/usr/share/secure-terminal-shots/lib-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'SKIP: lib-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 77
fi

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3 (got '$1', want '$2')"
      fail=$(( fail + 1 ))
   fi
}

## Run a snippet under bash with usr/bin deliberately OFF PATH -- the exact
## source-only-checkout scenario a direct capture run hits, where a bare `image-optimize`
## is unresolvable. `env` sets PATH: a bare VAR=val prefix taken from a variable is reparsed
## as a command name, not an assignment.
src_off_path() {  ## $1=bash snippet
   env PATH=/usr/bin:/bin bash -c "$1"
}

## 1. lib-capture defines an ABSOLUTE image-optimize path (survives the later cd to $HOME).
res="$(src_off_path "source '${lib}'; printf '%s' \"\${shots_image_optimize:-UNSET}\"")"
if [ "${res#/}" != "${res}" ] && [ "${res%/image-optimize}" != "${res}" ]; then
   printf '%s\n' "PASS: shots_image_optimize is an absolute path to image-optimize (${res})"
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: shots_image_optimize not an absolute image-optimize path: ${res}"
   fail=$(( fail + 1 ))
fi

## 2. it resolves + is executable with usr/bin OFF PATH.
r2="$(src_off_path "source '${lib}'; [ -x \"\${shots_image_optimize:-}\" ] && printf '%s' OK || printf '%s' NO")"
check "${r2}" 'OK' 'image-optimize resolves + is executable with usr/bin off PATH'

## 3. the resolved path survives a cwd change (comparison-capture cd's to $HOME after sourcing).
r3="$(src_off_path "source '${lib}'; cd /; [ -x \"\${shots_image_optimize:-}\" ] && printf '%s' OK || printf '%s' NO")"
check "${r3}" 'OK' 'resolution survives a cwd change'

## 4. shots_require_image_optimize: 0 for the real optimizer, non-0 (fail-fast) when missing.
r4a="$(bash -c "source '${lib}'; shots_require_image_optimize >/dev/null 2>&1 && printf '%s' OK || printf '%s' NO")"
check "${r4a}" 'OK' 'shots_require_image_optimize passes for the bundled optimizer'
r4b="$(bash -c "source '${lib}'; shots_image_optimize=/nonexistent/image-optimize; shots_require_image_optimize >/dev/null 2>&1 && printf '%s' BAD || printf '%s' GOOD")"
check "${r4b}" 'GOOD' 'shots_require_image_optimize fails fast when the optimizer is missing'

printf '%s\n' '' "${pass} pass, ${fail} fail"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: image-optimize resolution'
