#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Every script in this package that CALLS 'has' must also SOURCE has.sh.
##
## THE BUG: 'has' is a shell FUNCTION from
## /usr/libexec/helper-scripts/has.sh, not an executable.
## anon-server-to-client-install called it without sourcing it, so every
## invocation died with 'has: command not found'.
##
## This is a whole-package check rather than a single-file one, because the
## same omission can recur in any sibling -- which is the reason it is worth
## having as a standing test at all.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v ANON_GW_ANONYMIZER_CONFIG_REPO ] || ANON_GW_ANONYMIZER_CONFIG_REPO=""

if [ -n "${ANON_GW_ANONYMIZER_CONFIG_REPO}" ]; then
   package_root="${ANON_GW_ANONYMIZER_CONFIG_REPO}"
else
   ## Installed, the package's scripts are spread across /usr; there is no
   ## package root to walk, so this lane needs a checkout.
   package_root=""
fi

if [ -z "${package_root}" ] || [ ! -d "${package_root}/usr" ]; then
   printf '%s\n' "FATAL: no anon-gw-anonymizer-config checkout to scan" >&2
   printf '%s\n' "set ANON_GW_ANONYMIZER_CONFIG_REPO to one" >&2
   exit 1
fi

fail=0
caller_count=0

while IFS= read -r script; do
   ## A CALL is 'has' at the start of a command -- not the word inside a
   ## comment, not a longer identifier, and not an assignment.
   if ! grep --extended-regexp -- '^[[:space:]]*has[[:space:]]+[^=]' "${script}" >/dev/null; then
      continue
   fi
   caller_count=$(( caller_count + 1 ))
   if grep --fixed-strings -- 'helper-scripts/has.sh' "${script}" >/dev/null; then
      printf '%s\n' "PASS: $(basename -- "${script}") calls has, sources has.sh"
   else
      printf '%s\n' "FAIL: $(basename -- "${script}") calls has WITHOUT sourcing has.sh"
      grep --line-number --extended-regexp -- '^[[:space:]]*has[[:space:]]+[^=]' "${script}" | head -1
      fail=1
   fi
done < <(find "${package_root}/usr" -type f -exec grep -l -- '^#!.*bash' {} + 2>/dev/null | sort)

printf '%s\n' ""
printf '%s\n' "${caller_count} script(s) call has; fail=${fail}"

## A scan that matched nothing would report a clean run while checking
## nothing at all -- the failure mode this whole suite exists to avoid.
if [ "${caller_count}" -eq 0 ]; then
   printf '%s\n' "FAIL: no callers of 'has' found at all -- the check is testing nothing"
   exit 1
fi

exit "${fail}"
