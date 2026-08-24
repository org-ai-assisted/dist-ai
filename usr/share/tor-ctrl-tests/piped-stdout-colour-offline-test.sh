#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## tor-ctrl-stream and tor-ctrl-circuit: no colour palette on a stdout that is
## not a terminal.
##
## THE BUG: helper-scripts' get_colors.sh decides whether to colour by testing
## fd 2. These two scripts write their tables to fd 1, so piping stdout while
## stderr was still a terminal injected escape sequences into reports and into
## anything parsing the output. The fix is each script's own
## '[ ! -t 1 ]' gate, which blanks the palette.
##
## The gate is lifted out of the file and run on its own, so the test needs no
## live tor.
##
## No tor, no network, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v TOR_CTRL_REPO ] || TOR_CTRL_REPO=""

if [ -n "${TOR_CTRL_REPO}" ]; then
   bin_dir="${TOR_CTRL_REPO}/usr/bin"
else
   bin_dir="/usr/bin"
fi

if [ ! -r "${bin_dir}/tor-ctrl-stream" ]; then
   printf '%s\n' "FATAL: tor-ctrl-stream not found in '${bin_dir}'" >&2
   printf '%s\n' "set TOR_CTRL_REPO to a tor-ctrl checkout, or install the package" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/tor-ctrl-colour-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the driver body below is LITERAL code written to a file, not text
## this shell should expand.
# shellcheck disable=SC2016
build_driver() {
   local subject driver_path palette_vars palette_var

   subject="$1"
   driver_path="$2"
   palette_vars="$3"

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail'
      ## The stub populates the palette UNCONDITIONALLY -- it deliberately does
      ## NOT replicate get_colors.sh's own 'test -t 2'.
      ##
      ## That is the whole point. Under a test runner stderr is not a terminal
      ## either, so a faithful stub would blank the palette by itself and the
      ## case would pass no matter what the script does. Measured on the
      ## original harness: it reported 2 pass before the gate existed at all.
      ## Populating unconditionally puts the script's own '[ ! -t 1 ]' on the
      ## hook, which is the thing under test.
      ##
      ## A SENTINEL, not a real escape sequence: '\033' inside a double-quoted
      ## bash assignment is a literal backslash-0-3-3, not an ESC byte, and the
      ## scripts differ in whether they print the palette with %s or %b -- so
      ## hunting for escape BYTES in the output tested nothing. The property
      ## that matters is simply whether the gate BLANKED the palette.
      printf '%s\n' 'bold="SENTINEL"; nocolor="SENTINEL"; yellow="SENTINEL"'
      ## The gate is anchored on ITSELF, not on a range starting at the source
      ## line: a range ending at the next '^fi$' swallowed 219 lines of
      ## unrelated script the moment the gate was removed, so the canary died
      ## instead of failing. Anchored this way a missing gate simply
      ## contributes nothing, the palette stays populated, and the case fails --
      ## which is what a canary must do.
      sed -n '/^if \[ ! -t 1 \]; then$/,/^fi$/p' "${subject}"
      ## Print ONLY the variables this script actually uses. Printing the whole
      ## palette failed every case on a variable the script never touches --
      ## 'yellow' does not appear in tor-ctrl-stream at all.
      for palette_var in ${palette_vars}; do
         printf '%s\n' "printf \"%s\\n\" \"PALETTE ${palette_var}=[\${${palette_var}:-}]\""
      done
   } >"${driver_path}"
}

## check <description> <script name> <palette variables>
check() {
   local description name palette_vars subject driver output verdict

   description="$1"
   name="$2"
   palette_vars="$3"
   subject="${bin_dir}/${name}"

   if [ ! -r "${subject}" ]; then
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description}: '${subject}' is missing"
      return 0
   fi

   ## Report an absent gate explicitly. The case would fail anyway -- an empty
   ## extraction leaves the palette populated -- but naming the cause is the
   ## difference between a legible canary and a puzzle.
   if ! grep --quiet -- '^if \[ ! -t 1 \]; then$' "${subject}"; then
      printf '%s\n' "  note: no '[ ! -t 1 ]' gate found in '${subject}'"
   fi

   driver="${work_dir}/${name}.driver"
   build_driver "${subject}" "${driver}" "${palette_vars}"

   ## stdout to a PIPE (not a terminal), stderr discarded -- the exact shape
   ## that leaked the palette into redirected output.
   output="$(bash "${driver}" 2>/dev/null)"

   verdict=PASS
   case "${output}" in
      *SENTINEL*)
         verdict=FAIL
         ;;
   esac

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description}: the palette survived a piped stdout"
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

check 'tor-ctrl-stream: piped stdout stays plain'  tor-ctrl-stream  'bold nocolor'
check 'tor-ctrl-circuit: piped stdout stays plain' tor-ctrl-circuit 'yellow nocolor'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
