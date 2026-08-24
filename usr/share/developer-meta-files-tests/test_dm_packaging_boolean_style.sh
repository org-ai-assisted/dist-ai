#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards the y/n -> true/false boolean conversion in developer-meta-files'
## dm-packaging-helper-script. Its internal flags were single-char 'y'/'n'
## strings; they are now standard 'true'/'false'. A uniform swap cannot desync a
## set from its compare (every token changed at once), so the realistic
## regression is a NEW 'y'/'n' boolean creeping back in. Assert the file carries
## no boolean-shaped 'y'/'n' token and does use true/false.
##
## Structural only (greps the file). Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}

rel='usr/bin/dm-packaging-helper-script'
candidates=()
[ -z "${DM_PACKAGING_HELPER_SCRIPT:-}" ] || candidates+=( "${DM_PACKAGING_HELPER_SCRIPT}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-packaging-helper-script not found (set DM_PACKAGING_HELPER_SCRIPT)." >&2
   exit 1
fi

## Boolean-shaped 'y'/'n' tokens: an assignment ('=y'), a comparison ('= y' /
## '!= y', single or double quoted) or a ':-y}' default. Ordinary words and
## comments containing the letters y or n do NOT match (the quotes + '=' anchor).
yn_hits="$(grep --line-number --extended-regexp \
   -e "=('[yn]'|\"[yn]\")" \
   -e "= ('[yn]'|\"[yn]\")" \
   -e ":-[yn]\}" \
   -- "${subject}" || true)"
if [ -z "${yn_hits}" ]; then
   pass "no boolean-shaped 'y'/'n' token remains"
else
   fail "a 'y'/'n' boolean token is present (should be true/false):"
   printf '%s\n' "${yn_hits}" | sed 's/^/    /' >&2
fi

## And the true/false booleans must actually be in use (a canary against the
## grep above passing simply because the file was gutted).
if grep --quiet --extended-regexp -- "=('true'|'false'|\"true\"|\"false\")" "${subject}"; then
   pass "true/false string booleans are in use"
else
   fail "no true/false booleans found; the file may have changed shape"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-packaging-helper-script uses true/false booleans (${pass_count} assertions)."
