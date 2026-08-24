#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## torrc-parser: two defects that both made it silently do the wrong thing.
##
## 1. unknown_option_specifier ran
##       grep -- PATTERN "${torrc_files[@]}"
##    and with an EMPTY array grep has no file operands, so it reads STDIN and
##    anon-verify HANGS instead of printing its diagnosis. Reachable today:
##    anon-verify's tor_start_command is empty, so parser() can run with two
##    empty paths and discover no files. The hang IS the property, so stdin is
##    left open on a pipe that never closes and the run is given a short
##    timeout: a version that reads stdin times out, one that does not returns.
##
## 2. the directory traversal used 'for fso in $(find ...)', which splits on
##    whitespace -- so a torrc.d file named 'custom conf.conf' became two
##    nonexistent paths and was silently DROPPED. Nothing reported it missing,
##    so the assertion is that the file's CONTENT was seen, not merely that the
##    loop ran.
##
## Both functions are driven directly; anon-verify itself needs a live tor.
##
## No root, no network, no tor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v ANON_GW_ANONYMIZER_CONFIG_REPO ] || ANON_GW_ANONYMIZER_CONFIG_REPO=""

if [ -n "${ANON_GW_ANONYMIZER_CONFIG_REPO}" ]; then
   subject="${ANON_GW_ANONYMIZER_CONFIG_REPO}/usr/libexec/anon-gw-anonymizer-config/torrc-parser"
else
   subject='/usr/libexec/anon-gw-anonymizer-config/torrc-parser'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: torrc-parser not found at '${subject}'" >&2
   printf '%s\n' "set ANON_GW_ANONYMIZER_CONFIG_REPO to a checkout, or install the package" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/torrc-parser-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the driver bodies are LITERAL code written into a file.
# shellcheck disable=SC2016
run_unknown_option() {
   local files_mode base status

   files_mode="$1"
   base="${work_dir}/uo.${files_mode}"
   safe-rm --recursive --force -- "${base}"
   mkdir --parents -- "${base}"
   printf '%s\n' 'SomeUnknownOption 1' >"${base}/torrc"

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail'
      printf '%s\n' 'error_handler() { printf "%s\n" "STUB error_handler"; }'
      if [ "${files_mode}" = populated ]; then
         printf '%s\n' "declare -a torrc_files=(${base@Q}/torrc)"
      else
         printf '%s\n' 'declare -a torrc_files=()'
      fi
      sed -n '/^function unknown_option_specifier(){/,/^}/p' "${subject}"
      printf '%s\n' 'unknown_option_specifier SomeUnknownOption'
      printf '%s\n' 'printf "%s\n" "RETURNED"'
   } >"${base}/driver"

   ## stdin is a pipe that never closes: a grep with no file operands blocks on
   ## it, which is exactly the hang being detected.
   status=0
   timeout --kill-after=5 5 bash "${base}/driver" < <(sleep 30) >/dev/null 2>&1 || status=$?
   printf '%s' "${status}"
}

check_unknown_option() {
   local description files_mode status verdict

   description="$1"
   files_mode="$2"
   status="$(run_unknown_option "${files_mode}")"

   verdict=PASS
   if [ "${status}" = "124" ]; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: timed out -- it read stdin, which is the hang"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description} (exit ${status})"
   else
      fail_count=$(( fail_count + 1 ))
   fi
}

# shellcheck disable=SC2016
run_traverse() {
   local file_name base conf_dir

   file_name="$1"
   base="${work_dir}/tr"
   safe-rm --recursive --force -- "${base}"
   conf_dir="${base}/torrc.d"
   mkdir --parents -- "${conf_dir}"
   printf '%s\n' 'SocksPort 9050' >"${conf_dir}/${file_name}"

   ## parser() is recursive and does a great deal; only the directory-traversal
   ## branch is under test, so parser is stubbed to record what it was handed.
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail'
      printf '%s\n' 'shopt -s nullglob'
      printf '%s\n' "temp_verbose_torrc=${base@Q}/verbose"
      printf '%s\n' 'parser() { printf "%s\n" "PARSED:[$1]"; }'
      printf '%s\n' "abs_path=${conf_dir@Q}"
      ## Wrapped in a function: the branch opens with 'local fso', which bash
      ## rejects at top level.
      printf '%s\n' 'traverse() {'
      sed -n '/^         local fso$/,/^         done/p' "${subject}" | sed 's/^         //'
      printf '%s\n' '}' 'traverse'
      printf '%s\n' 'printf "%s\n" "REACHED_END"'
   } >"${base}/driver"

   if ! grep --fixed-strings -- 'local fso' "${base}/driver" >/dev/null; then
      printf '%s' 'EXTRACTION_EMPTY'
      return 0
   fi

   timeout --kill-after=20 20 bash "${base}/driver" 2>&1 || true
}

check_traverse() {
   local description file_name want output verdict

   description="$1"
   file_name="$2"
   want="$3"
   output="$(run_traverse "${file_name}")"

   verdict=PASS
   if printf '%s\n' "${output}" | grep --fixed-strings -- 'EXTRACTION_EMPTY' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the traversal branch extracted EMPTY"
   elif ! printf '%s\n' "${output}" | grep --fixed-strings -- "${want}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the file was never handed to parser"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

## 1. the stdin hang.
check_unknown_option 'an EMPTY torrc_files must not read stdin' empty
check_unknown_option 'a populated torrc_files still greps' populated

## 2. the dropped filename. The assertion is the CONTENT was reached, i.e. that
## parser was handed the path -- not merely that the loop ran.
## The expected string carries the FULL filename: a split 'custom conf.conf'
## produces 'PARSED:[.../custom]' and 'PARSED:[conf.conf]', neither of which
## matches. Asserting only that SOME parse happened would accept the bug.
check_traverse 'a filename containing a space is parsed' 'custom conf.conf' \
   'torrc.d/custom conf.conf]'
check_traverse 'an ordinary filename is still parsed' '50_plain.conf' \
   'torrc.d/50_plain.conf]'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
