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

   ## Build the c8 --include list from the covered-set (explicit, growing). The `|| [ -n ... ]`
   ## is load-bearing: `read` returns non-zero at EOF-without-trailing-newline, so without it a
   ## covered.txt whose LAST line is a real path with no final newline (echo -n / some editors /
   ## an appended path) is silently DROPPED -- never path-validated, [ -f ]-checked, or gated.
   while IFS= read -r line || [ -n "${line}" ]; do
      ## skip blank lines and '#' comments
      if [ -z "${line}" ] || [ "${line#\#}" != "${line}" ]; then
         continue
      fi
      ## covered.txt holds PLAIN RELATIVE file paths. c8 treats each --include as a GLOB, so a
      ## leading '/', a './' prefix, a '..'/'/./' segment, or a glob metacharacter would pass the
      ## literal [ -f ] check below yet NOT match c8's include -- the file is then silently
      ## ungated. Reject anything that is not a plain relative path (also bars spaces + shell/glob
      ## metachars), so the literal path equals the glob c8 matches.
      case "${line}" in
         *[!A-Za-z0-9._/-]* | /* | ./* | */./* | *..* )
            printf '%s\n' "jscov: FATAL: covered entry is not a plain relative path: ${line} (listed in ${covered_file})" >&2
            return 1
            ;;
      esac
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

   ## --config pins c8 to a committed config that sets exclude:[] explicitly, so its findUp does
   ## NOT pick up a stray .c8rc/.nycrc OR a package.json "c8" key (merged via .pkgConf) in the
   ## workdir or any parent dir whose 'exclude' would drop every covered file -> empty map ->
   ## false green (the self-check cannot catch this, as its own files live outside roots/).
   ## exclude:[] is safe here: --include already scopes the report to exactly the covered set.
   ## node --test takes a GLOB, never a bare dir: Node 22 loads a bare-dir arg as a MODULE
   ## (MODULE_NOT_FOUND), unlike Node 20's directory recursion. The glob matches this dir's
   ## *.test.js (and any nested ones); the selftest below fails loud if this ever regresses.
   c8 --config jscov/c8-config.json --all --check-coverage \
      --statements 100 --branches 100 --functions 100 --lines 100 \
      "${includes[@]}" --reporter text-summary \
      node --test "${test_dir}/**/*.test.js"
}

## Fail-closed self-check: jscov-selftest lists two files but exercises only one; under --all the
## unexercised include must drop coverage below 100% and FAIL. A PASS here means --all is missing
## or ineffective and the real gate below would be vacuous -- abort rather than report a false
## green. Its absence is itself fatal (cannot self-verify).
if [ ! -f jscov-selftest/covered.txt ] || [ ! -f jscov-selftest/a.js ] || [ ! -f jscov-selftest/b.js ]; then
   ## The self-check must FAIL because of COVERAGE (b.js unexercised under --all), never because
   ## run_gate bailed on a precondition -- an incomplete fixture would make the `if` below read a
   ## precondition exit as "canary failed as required" and pass vacuously. Require it intact.
   printf '%s\n' 'jscov: FATAL: jscov-selftest fixture incomplete (covered.txt/a.js/b.js) -- cannot self-verify the gate is non-vacuous' >&2
   exit 1
fi
## The self-check must fail SPECIFICALLY because of a COVERAGE-THRESHOLD shortfall (b.js at 0%
## under --all), not merely because run_gate returned non-zero -- a syntax error, a missing file,
## or a c8 config error would ALSO exit non-zero and would let the canary "pass" for the wrong
## reason (never actually proving --all works). Capture the output and require c8's own
## threshold-failure line; any other non-zero, or a zero (vacuous) exit, is fatal.
selfcheck_rc=0
selfcheck_out="$(run_gate jscov-selftest/covered.txt jscov-selftest 2>&1)" || selfcheck_rc="$?"
if [ "${selfcheck_rc}" = '0' ]; then
   printf '%s\n' 'jscov: FATAL: self-check PASSED but MUST FAIL -- an unexercised covered file was not caught, so the coverage gate is VACUOUS (c8 --all missing/ineffective). Refusing to report a false green.' >&2
   exit 1
fi
## The non-zero exit MUST be c8's own coverage-threshold failure (b.js at 0% under --all), not
## an unrelated error (syntax/missing-file/config) that would let the canary pass for the wrong
## reason. Substring-test via parameter expansion: if stripping the phrase leaves the output
## unchanged, the phrase was absent -> the self-check did not prove --all works.
if [ "${selfcheck_out#*does not meet global threshold}" = "${selfcheck_out}" ]; then
   printf '%s\n' 'jscov: FATAL: self-check failed for the WRONG reason (no c8 coverage-threshold failure in its output) -- it did not prove --all catches an unexercised file, so the gate cannot be trusted. Self-check output follows:' >&2
   printf '%s\n' "${selfcheck_out}" >&2
   exit 1
fi

## Real gate: 100% over covered.txt, fail loud on any shortfall.
run_gate jscov/covered.txt jscov
