#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: R-003 - 3-space indent to match the sibling *_test.sh in this suite.

## grub-live's LIVE USER wrappers must export boot_mode_id='live' BEFORE they exec
## the dist generator, so 10_00_linux_dist / 10_50_linux_dist_advanced scope the
## LIVE USER --id ('gnulinux-live-*') apart from the persistent USER entry
## ('gnulinux-user-*'). A missing (pre-fix) or late assignment leaves the LIVE USER
## entry on the ':-simple' fallback id, colliding with any other unset-mode entry
## and defeating id-based boot-mode selection.
##
## The emit-check suite cannot assert this: both wrappers short-circuit at their
## 'pkg_installed grub-live' guard when grub-live is absent (the core dist-ai CI
## env), never reaching the export. This reads the REAL wrapper source and asserts
## the assignment exists and precedes the generator exec -- environment-independent.
##
## No root, no network, no grub-mkconfig.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v GRUB_LIVE_REPO ] || GRUB_LIVE_REPO=""

if [ -n "${GRUB_LIVE_REPO}" ]; then
   grub_d="${GRUB_LIVE_REPO}/etc/grub.d"
else
   grub_d='/etc/grub.d'
fi

## wrapper : generator it execs for the LIVE USER entry
specs=(
   "${grub_d}/10_20_linux_live:/etc/grub.d/10_00_linux_dist"
   "${grub_d}/10_60_linux_live_advanced:/etc/grub.d/10_50_linux_dist_advanced"
)

missing=''
for spec in "${specs[@]}"; do
   wrapper="${spec%%:*}"
   [ -r "${wrapper}" ] || missing="${missing} ${wrapper}"
done
if [ -n "${missing}" ]; then
   printf '%s\n' "SKIP: missing grub-live wrapper(s):${missing}" >&2
   printf '%s\n' "set GRUB_LIVE_REPO if the checkout lives elsewhere" >&2
   ## style-ok: allow-skip: the grub-live checkout/package is absent in the core dist-ai CI job
   exit 77
fi

fail=0
checks=0

for spec in "${specs[@]}"; do
   wrapper="${spec%%:*}"
   generator="${spec#*:}"
   label="$(basename -- "${wrapper}")"
   checks=$(( checks + 1 ))

   ## First line that assigns boot_mode_id='live', and first line that execs the
   ## generator. grep -n emits '<line>:<text>'; take the leading line number only.
   ## '|| true': a no-match grep exits 1, which under pipefail+inherit_errexit would
   ## abort the script AT this substitution -- never reaching the FAIL branches below
   ## (making them dead code and swallowing the WHICH-wrapper/WHY diagnostic). Empty
   ## string instead flows to the '[ -z ]' checks, which report the failure properly.
   assign_line="$(grep -n -- "^[[:space:]]*boot_mode_id='live'" "${wrapper}" | head -n 1 | cut -d: -f1 || true)"
   exec_line="$(grep -nF -- "${generator}" "${wrapper}" | head -n 1 | cut -d: -f1 || true)"

   if [ -z "${assign_line}" ]; then
      printf '%s\n' "FAIL  ${label}: no boot_mode_id='live' assignment"
      fail=1
      continue
   fi
   if [ -z "${exec_line}" ]; then
      printf '%s\n' "FAIL  ${label}: does not reference generator '${generator}'"
      fail=1
      continue
   fi
   if [ "${assign_line}" -ge "${exec_line}" ]; then
      printf '%s\n' "FAIL  ${label}: boot_mode_id='live' (line ${assign_line}) not before generator exec (line ${exec_line})"
      fail=1
      continue
   fi
   printf '%s\n' "PASS  ${label}: boot_mode_id='live' (line ${assign_line}) before generator exec (line ${exec_line})"
done

printf '%s\n' "" "${checks} checks, ${fail} failed"
[ "${fail}" -eq 0 ]
