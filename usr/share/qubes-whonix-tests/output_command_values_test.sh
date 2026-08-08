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
## A STRUCTURAL check, stated plainly: it asserts the values are executable,
## not that the script produces particular output. Driving the message path end
## to end would need the key-copying and ssh steps stubbed, a much bigger
## fixture than this property warrants.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v QUBES_WHONIX_REPO ] || QUBES_WHONIX_REPO=""

if [ -n "${QUBES_WHONIX_REPO}" ]; then
   subject="${QUBES_WHONIX_REPO}/usr/bin/qubes-remote-support-provider"
else
   subject='/usr/bin/qubes-remote-support-provider'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: qubes-remote-support-provider not found at '${subject}'" >&2
   printf '%s\n' "set QUBES_WHONIX_REPO to a qubes-whonix checkout, or install the package" >&2
   exit 77
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

exit "${fail}"
