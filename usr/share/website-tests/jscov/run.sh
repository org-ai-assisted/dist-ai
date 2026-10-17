#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- runs INSIDE the confined sandbox workdir; does not source helper-scripts.

## Confined JS unit-coverage gate: run every jscov/*.test.js under c8 and REQUIRE 100%
## statements/branches/functions/lines over exactly the files listed in covered.txt. Invoked by
## webcheck-jscov-sandbox inside the sandbox (cwd = the synced workdir). jsdom + c8 are global
## (provision jstest), so put the global node_modules on the require path.
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

NODE_PATH="$(npm root -g)"
export NODE_PATH

## Build the c8 --include list from covered.txt (explicit, growing covered-set).
declare -a includes=()
while IFS= read -r line; do
   ## skip blank lines and '#' comments
   if [ -z "${line}" ] || [ "${line#\#}" != "${line}" ]; then
      continue
   fi
   includes+=( "--include" "${line}" )
done < jscov/covered.txt

if [ "${#includes[@]}" -eq 0 ]; then
   printf '%s\n' 'jscov: FATAL: covered.txt lists no files -- the gate would vacuously pass' >&2
   exit 1
fi

c8 --check-coverage --statements 100 --branches 100 --functions 100 --lines 100 \
   "${includes[@]}" --reporter text-summary \
   node --test jscov/
