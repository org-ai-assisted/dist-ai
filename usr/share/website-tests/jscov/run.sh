#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- runs INSIDE the confined sandbox workdir; does not source helper-scripts.

## Confined JS unit-coverage gate: run every jscov/*.test.js under c8 and REQUIRE 100%
## statements/branches/functions/lines over exactly the files listed in covered.txt. Invoked by
## webcheck-jscov-sandbox inside the sandbox (cwd = the synced workdir). jsdom + c8 are global
## (provision jstest), so put the global node_modules on the require path.
##
## c8 --all is MANDATORY: without it c8 reports only the files the tests actually LOADED, so a
## covered.txt entry whose test never exercises it is simply ABSENT from the coverage map and the
## 100% gate passes VACUOUSLY (a false green). --all forces every --include'd file into the report
## -- an unexercised one shows 0% and FAILS. A fail-closed self-check (jscov-selftest/, an
## unexercised include that MUST fail) runs first, so the gate can never silently regress to
## vacuous if --all is ever dropped.
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

NODE_PATH="$(npm root -g)"
export NODE_PATH

## Run the c8 100%-coverage gate over exactly the files in <covered-file>, executing the tests in
## <test-dir>. --all makes an included-but-unexercised file report 0% (and FAIL), closing the
## silent-green hole. Returns c8's exit code.
run_gate(){
   local covered_file="$1"
   local test_dir="$2"
   local -a includes=()
   local line

   ## Build the c8 --include list from the covered-set (explicit, growing).
   while IFS= read -r line; do
      ## skip blank lines and '#' comments
      if [ -z "${line}" ] || [ "${line#\#}" != "${line}" ]; then
         continue
      fi
      ## Every covered file MUST exist on disk (cwd = the synced workdir). c8 --all can only
      ## materialize a file it actually FINDS, so a mistyped/absent entry is silently omitted
      ## from the report; if that leaves the map empty, c8 prints 'Unknown% (0/0)' and
      ## --check-coverage exits 0 -- a false green. Fail loud on a missing covered file instead.
      if [ ! -f "${line}" ]; then
         printf '%s\n' "jscov: FATAL: covered file not found: ${line} (listed in ${covered_file}) -- a missing/mistyped entry would pass the gate vacuously" >&2
         return 1
      fi
      includes+=( "--include" "${line}" )
   done < "${covered_file}"

   if [ "${#includes[@]}" -eq 0 ]; then
      printf '%s\n' "jscov: FATAL: ${covered_file} lists no files -- the gate would vacuously pass" >&2
      return 1
   fi

   ## --config pins c8 to a committed empty config so its findUp does NOT pick up a stray
   ## .c8rc/.nycrc in the workdir or any parent dir whose 'exclude' would drop every covered
   ## file -> empty map -> false green (the self-check cannot catch this, as its own files live
   ## outside roots/).
   c8 --config jscov/c8-config.json --all --check-coverage \
      --statements 100 --branches 100 --functions 100 --lines 100 \
      "${includes[@]}" --reporter text-summary \
      node --test "${test_dir}/"
}

## Fail-closed self-check: jscov-selftest lists two files but exercises only one; under --all the
## unexercised include must drop coverage below 100% and FAIL. A PASS here means --all is missing
## or ineffective and the real gate below would be vacuous -- abort rather than report a false
## green. Its absence is itself fatal (cannot self-verify).
if [ ! -f jscov-selftest/covered.txt ]; then
   printf '%s\n' 'jscov: FATAL: jscov-selftest/covered.txt not staged -- cannot self-verify the gate is non-vacuous' >&2
   exit 1
fi
if run_gate jscov-selftest/covered.txt jscov-selftest >/dev/null 2>&1; then
   printf '%s\n' 'jscov: FATAL: self-check PASSED but MUST FAIL -- an unexercised covered file was not caught, so the coverage gate is VACUOUS (c8 --all missing/ineffective). Refusing to report a false green.' >&2
   exit 1
fi

## Real gate: 100% over covered.txt, fail loud on any shortfall.
run_gate jscov/covered.txt jscov
