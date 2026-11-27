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
## the assignment exists, is effectively EXPORTED (an explicit 'export' keyword or an
## active 'set -o allexport' / 'set -a' before it -- else the exec'd engine child
## cannot inherit it), and precedes the generator exec -- environment-independent.
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

   ## First line assigning boot_mode_id='live' (with or without an 'export' keyword -- the
   ## wrappers rely on an earlier 'set -o allexport'), and first line that execs the generator.
   ## grep -n emits '<line>:<text>'; take the leading line number only.
   ## '|| true': a no-match grep exits 1, which under pipefail+inherit_errexit would abort the
   ## script AT this substitution -- never reaching the FAIL branches below (making them dead
   ## code and swallowing the diagnostic). Empty flows to the '[ -z ]' checks, which report it.
   assign_line="$(grep -n -E -- "^[[:space:]]*(export[[:space:]]+)?boot_mode_id='live'" "${wrapper}" | head -n 1 | cut -d: -f1 || true)"
   exec_line="$(grep -nF -- "${generator}" "${wrapper}" | head -n 1 | cut -d: -f1 || true)"
   ## boot_mode_id reaches the CHILD engine (exec'd, not sourced) only if EXPORTED: either the
   ## assignment carries 'export', or a 'set -o allexport' / 'set -a' is active before it (what
   ## the wrappers use). A bare assignment with neither is a real bug the engine would not see.
   export_kw_line="$(grep -n -E -- "^[[:space:]]*export[[:space:]]+boot_mode_id='live'" "${wrapper}" | head -n 1 | cut -d: -f1 || true)"
   allexport_line="$(grep -n -E -- "^[[:space:]]*set[[:space:]]+(-o[[:space:]]+allexport|-a)([[:space:]]|\$)" "${wrapper}" | head -n 1 | cut -d: -f1 || true)"

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
   if [ -z "${export_kw_line}" ] \
      && { [ -z "${allexport_line}" ] || [ "${allexport_line}" -ge "${assign_line}" ]; }; then
      printf '%s\n' "FAIL  ${label}: boot_mode_id='live' (line ${assign_line}) not exported -- no 'export' keyword and no 'set -o allexport'/'set -a' before it; the engine child cannot inherit it"
      fail=1
      continue
   fi
   printf '%s\n' "PASS  ${label}: boot_mode_id='live' (line ${assign_line}) exported and before generator exec (line ${exec_line})"
done

printf '%s\n' "" "${checks} checks, ${fail} failed"
[ "${fail}" -eq 0 ]
