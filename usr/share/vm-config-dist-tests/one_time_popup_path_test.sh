#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## msgcollector ships the popup tool as 'one-time-popup.py'. A caller that
## invokes the bare '/usr/libexec/msgcollector/one-time-popup' path hits a file
## that does not exist, so subprocess raises FileNotFoundError and the popup
## never starts -- the wlr-resize-watcher symptom this guards.
##
## Guard the whole package: NO file shipped by vm-config-dist may reference the
## msgcollector popup executable by any name other than 'one-time-popup.py'. The
## '~/.wlr-resize-watcher_one-time-popup' STATE file has no
## /usr/libexec/msgcollector/ prefix and is correctly not matched.
##
## Checkout mode (VM_CONFIG_DIST_REPO set) scans the whole tree -- codebase
## wide, the lane CI runs. Installed mode scans the one real invocation site.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v VM_CONFIG_DIST_REPO ] || VM_CONFIG_DIST_REPO=""

## The one real invocation site -- also the anchor that keeps this test from
## passing vacuously if the call is ever removed or the module renamed.
caller_rel='usr/lib/python3/dist-packages/wlr_resize_watcher/wlr_resize_watcher.py'

files=()
if [ -n "${VM_CONFIG_DIST_REPO}" ]; then
   if [ ! -d "${VM_CONFIG_DIST_REPO}" ]; then
      printf '%s\n' "FATAL: VM_CONFIG_DIST_REPO='${VM_CONFIG_DIST_REPO}' is not a directory" >&2
      exit 1
   fi
   while IFS= read -r -d '' f; do
      files+=( "${f}" )
   done < <(find "${VM_CONFIG_DIST_REPO}" \
      -type d \( -name .git -o -name debian \) -prune -o -type f -print0)
   caller_abs="${VM_CONFIG_DIST_REPO}/${caller_rel}"
else
   caller_abs="/${caller_rel}"
   files=( "${caller_abs}" )
fi

if [ ! -r "${caller_abs}" ]; then
   printf '%s\n' "FATAL: caller not found at '${caller_abs}'" >&2
   printf '%s\n' "set VM_CONFIG_DIST_REPO to a checkout, or install the package" >&2
   exit 1
fi

pass_count=0
fail_count=0

## Anchor: the correct '.py' invocation must be present, or a later accidental
## removal would make the bare-reference scan pass against nothing.
if grep --quiet --fixed-strings -- '/usr/libexec/msgcollector/one-time-popup.py' "${caller_abs}"; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: caller invokes one-time-popup.py"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: no '/usr/libexec/msgcollector/one-time-popup.py' invocation in ${caller_abs}"
   printf '%s\n' "  (anchor gone -- the bare-reference scan below would be vacuous)"
fi

## The bug: the msgcollector popup path followed by anything other than '.py'
## (a quote, comma, whitespace, slash, or end of line) is a stale bare
## reference. '.py' is excluded because the char after 'popup' is then '.'.
bare_hits="$(grep --recursive --line-number --extended-regexp \
   -- '/usr/libexec/msgcollector/one-time-popup([^.]|$)' "${files[@]}" || true)"

if [ -z "${bare_hits}" ]; then
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: no bare msgcollector one-time-popup references"
else
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: stale bare one-time-popup reference(s) -- must be one-time-popup.py:"
   printf '%s\n' "${bare_hits}"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
