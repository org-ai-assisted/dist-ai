#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## qubes-remote-support-provider: every value assigned to 'output_command' must
## be something bash can actually execute.
##
## THE BUG CLASS: the script prints via '${output_command} "msg"' -- UNQUOTED,
## so the value word-splits into a command plus its arguments. If that variable
## ever holds something bash cannot run, bash tries to execute the MESSAGE as a
## command instead -- exactly what happened in vm-config-dist during the same
## pass, where defaulting it to empty turned every message into 'command not
## found'.
##
## The shipped idiom selects on xtrace:
##   if test -o xtrace ; then output_command=true
##   else                     output_command="printf %s\n" ; fi
## i.e. stay silent under xtrace (the trace already shows the line), otherwise
## print the message. Both values are shell builtins.
##
## Two lanes: (1) a STRUCTURAL check that the command WORD of every
## output_command value is executable; (2) a BEHAVIORAL check that drives the
## real xtrace-based selection with xtrace off and asserts a message actually
## reaches stdout.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v QUBES_WHONIX_REPO ] || QUBES_WHONIX_REPO=""

if [ -n "${QUBES_WHONIX_REPO}" ]; then
   subject="${QUBES_WHONIX_REPO}/usr/bin/qubes-remote-support-provider"
else
   subject='/usr/bin/qubes-remote-support-provider'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: qubes-remote-support-provider not found at '${subject}'" >&2
   printf '%s\n' "set QUBES_WHONIX_REPO to a qubes-whonix checkout, or install the package" >&2
   exit 1
fi

fail=0
checked=0

## The command WORD of each output_command value: strip an optional opening
## quote, then take the first whitespace-delimited token -- the value may carry
## a printf format and args (e.g. 'printf %s\n'), but only its command word has
## to be executable. 'sort --unique' dedups across the selection branches.
while IFS= read -r value; do
   [ -n "${value}" ] || continue
   checked=$(( checked + 1 ))
   ## 'type -t' rather than R-090's 'has': the values are shell builtins
   ## ('true', 'printf'), and an installed has.bsh predating the builtin fix
   ## answers false for those -- which would fail this lane on a correct script.
   ## 'type -t' reports function, builtin, file, alias or keyword, so a non-empty
   ## answer is exactly "bash can run this".
   if [ -n "$(type -t "${value}")" ]; then
      printf '%s\n' "PASS: '${value}' is executable"
   else
      printf '%s\n' "FAIL: '${value}' is NOT executable -- messages would be run as commands"
      fail=1
   fi
done < <(grep --only-matching --perl-regexp -- 'output_command=\K.+' "${subject}" \
   | sed -e 's/^"//' | awk '{ print $1 }' | sort --unique)

printf '%s\n' ""
printf '%s\n' "${checked} value(s) checked"

## No assignment found means the grep anchor no longer matches the script --
## a rename or a refactor -- and the run would otherwise report clean while
## checking nothing.
if [ "${checked}" -eq 0 ]; then
   printf '%s\n' "FAIL: no output_command assignment found -- this check tested nothing"
   exit 1
fi

## Behavioral: drive the SHIPPED xtrace-based selection with xtrace OFF (the
## normal, non-silent path) and assert output_command actually prints its
## argument. Catches a regression that keeps the selection block but breaks
## emission (a dropped message, a value bash cannot run), which the structural
## lane cannot see.
##
## Only the FIRST 'if test -o xtrace' block -- the output_command selection.
## The script has other such blocks (ls/tar debug guards) referencing different
## runtime variables; a greedy range would pull those in.
select_src="$(awk '/^if test -o xtrace/{f=1} f{print} f && /^fi/{exit}' "${subject}")"
if [ -z "${select_src}" ] || ! grep --quiet 'output_command=' <<< "${select_src}"; then
   ## Anti-vacuous: extraction empty / wrong block means the script changed
   ## shape; fail rather than silently skip the behavioral check.
   printf '%s\n' "FAIL: could not extract the output_command selection from '${subject}' -- behavioral check tested nothing"
   fail=1
else
   marker="QRSP_MARKER_9137"
   behavior_out="$(
      ## xtrace off -> the selection takes the else branch (output_command set to
      ## the printing value), exactly as a normal interactive run.
      set +x
      eval "${select_src}"
      # shellcheck disable=SC2154  # output_command: set by the eval'd selection
      # shellcheck disable=SC2086  # intentional: the value is a command + args and must word-split
      ${output_command} "${marker} hello"
   )"
   case "${behavior_out}" in
      *"${marker} hello"*)
         printf '%s\n' "PASS: real output_command path prints the message to stdout"
         ;;
      *)
         printf '%s\n' "FAIL: real output_command path did not print the message (got: '${behavior_out}') -- messages would be dropped or run as commands"
         fail=1
         ;;
   esac
fi

exit "${fail}"
