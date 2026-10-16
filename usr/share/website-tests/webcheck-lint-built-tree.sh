#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-has -- standalone confined lint lane; does not source helper-scripts.

## CONFINED HTML-validity + CSS-lint lane for the family Pages sites. Runs INSIDE
## sandbox-confine (no network): html-tidy over every page + stylelint over every CSS.
##
##   webcheck-lint-built-tree.sh <tree-dir> <stylelint-config>
##
## - tidy: HTML validity per page. Gates on tidy ERRORS (malformed structure). tidy
##   WARNINGS (implicit tags, empty-element trim, a proprietary attribute like
##   aria-current that tidy does not know but is valid) are advisory, never gating.
## - stylelint: CSS validity/correctness per stylesheet, using the shipped config.
## Not run directly -- webcheck-lint-sandbox stages the tree + config together and
## invokes this confined. Exit: 0 clean, 1 a tidy error and/or a stylelint finding.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tree="${1:?usage: webcheck-lint-built-tree.sh <tree-dir> <stylelint-config>}"
sl_config="${2:?usage: webcheck-lint-built-tree.sh <tree-dir> <stylelint-config>}"

rc=0

printf '%s\n' '== html-tidy (validity) =='
err_files=0
warn_total=0
n=0
while IFS= read -r -d '' f; do
  n=$((n + 1))
  ## tidy exit: 0 clean, 1 warnings, 2 errors. -errors suppresses the cleaned-HTML stdout.
  if out="$(tidy -quiet -errors -utf8 "${f}" 2>&1)"; then
    trc=0
  else
    trc="${?}"
  fi
  w="$(printf '%s\n' "${out}" | grep -c 'Warning:')" || true
  e="$(printf '%s\n' "${out}" | grep -c 'Error:')" || true
  warn_total=$((warn_total + w))
  if [ "${trc}" -ge 2 ] || [ "${e}" -gt 0 ]; then
    err_files=$((err_files + 1))
    printf '%s\n' "TIDY ERROR in ${f}:"
    printf '%s\n' "${out}" | grep 'Error:' || true
  fi
done < <(find "${tree}" -name '*.html' -print0 | sort -z)
printf '%s\n' "tidy: ${n} file(s), ${warn_total} warning(s) [advisory], ${err_files} file(s) with errors"
if [ "${err_files}" -gt 0 ]; then
  rc=1
fi

printf '%s\n' '' '== stylelint (CSS) =='
css_n=0
css_bad=0
while IFS= read -r -d '' css; do
  css_n=$((css_n + 1))
  if ! stylelint --config "${sl_config}" "${css}"; then
    css_bad=$((css_bad + 1))
  fi
done < <(find "${tree}" -name '*.css' -print0 | sort -z)
printf '%s\n' "stylelint: ${css_n} stylesheet(s), ${css_bad} with findings"
if [ "${css_bad}" -gt 0 ]; then
  rc=1
fi

exit "${rc}"
