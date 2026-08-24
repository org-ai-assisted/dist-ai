#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## qubes-remote-support-provider: every value assigned to 'output_command' must
## be something bash can actually execute.
##
## THE BUG CLASS: the script prints via '${output_command} "msg"'. If that
## variable ever holds something bash cannot run, bash tries to execute the
## MESSAGE as a command instead -- which is exactly what happened in
## vm-config-dist during the same pass, where defaulting it to empty turned
## every message into 'command not found'.
##
## R-034 could not be applied at the call sites: 'echo' was the COMMAND NAME
## held in a variable, not a call. It became a print_line wrapper, so this
## checks the substitution did not break the indirection.
##
## Two lanes: (1) a STRUCTURAL check that every output_command value is
## executable; (2) a BEHAVIORAL check that drives the shipped print_line
## indirection + the xtrace-based selection and asserts a message actually
## reaches stdout. The full ssh/key-copying flow is still not driven (it would
## need those steps stubbed), but the message-emission property -- the actual
## bug class -- is now exercised, not just asserted structurally.
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

while IFS= read -r value; do
   [ -n "${value}" ] || continue
   checked=$(( checked + 1 ))
   if grep --extended-regexp -- "^${value}\(\) \{" "${subject}" >/dev/null; then
      printf '%s\n' "PASS: '${value}' is a function defined in the script"
   ## 'type -t' rather than R-090's 'has': one of the values IS a shell
   ## builtin ('true'), and an installed has.sh predating the builtin fix
   ## answers false for those -- which would fail this lane on a correct
   ## script. 'type -t' reports function, builtin, file, alias or keyword, so a
   ## non-empty answer is exactly "bash can run this".
   elif [ -n "$(type -t "${value}")" ]; then
      printf '%s\n' "PASS: '${value}' is a real command"
   else
      printf '%s\n' "FAIL: '${value}' is NOT executable -- messages would be run as commands"
      fail=1
   fi
done < <(grep --only-matching --perl-regexp -- 'output_command=\K\S+' "${subject}" | sort --unique)

printf '%s\n' ""
printf '%s\n' "${checked} value(s) checked"

## No assignment found means the grep anchor no longer matches the script --
## a rename or a refactor -- and the run would otherwise report clean while
## checking nothing.
if [ "${checked}" -eq 0 ]; then
   printf '%s\n' "FAIL: no output_command assignment found -- this check tested nothing"
   exit 1
fi

## Behavioral: the SHIPPED print_line indirection actually PRINTS its argument.
## The value check above proves each output_command value is executable; this
## drives the real print_line function plus the real xtrace-based selection
## block and asserts a message reaches stdout -- so a regression that keeps
## print_line a defined function but stops it emitting (the message silently
## dropped, or the whole banner lost) is caught, which the value check cannot
## see.
print_line_src="$(sed -n '/^print_line() {/,/^}/p' -- "${subject}")"
## Only the FIRST 'if test -o xtrace' block -- the output_command selection.
## The script has several such blocks (ls/tar debug guards) that reference
## other runtime variables; a greedy range would pull those in.
select_src="$(awk '/^if test -o xtrace/{f=1} f{print} f && /^fi/{exit}' "${subject}")"
if [ -z "${print_line_src}" ] || [ -z "${select_src}" ] \
   || ! grep --quiet 'output_command=print_line' <<< "${select_src}"; then
   ## Anti-vacuous: extraction empty / wrong block means the script changed
   ## shape; fail rather than silently skip the behavioral check.
   printf '%s\n' "FAIL: could not extract print_line / the output_command selection from '${subject}' -- behavioral check tested nothing"
   fail=1
else
   marker="QRSP_MARKER_9137"
   behavior_out="$(
      ## xtrace off -> the selection sets output_command=print_line (the
      ## non-silent path), exactly as a normal interactive run.
      set +x
      eval "${print_line_src}"
      eval "${select_src}"
      "${output_command}" "${marker} hello"
   )"
   case "${behavior_out}" in
      *"${marker} hello"*)
         printf '%s\n' "PASS: real print_line indirection prints the message to stdout"
         ;;
      *)
         printf '%s\n' "FAIL: real output_command path did not print the message (got: '${behavior_out}') -- messages would be dropped or run as commands"
         fail=1
         ;;
   esac
fi

exit "${fail}"
