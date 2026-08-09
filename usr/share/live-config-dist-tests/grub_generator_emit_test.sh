#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## live-config-dist's /etc/grub.d generators must still emit their boot menu
## configuration.
##
## The reasoning and the stubbed environment live in the shared checker,
## because three components ship such generators and one copy of the
## argument is better than three that drift:
##   /usr/share/dist-ai-tests-common/grub-generator-emit-check
##
## No root, no network, no grub-mkconfig.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v LIVE_CONFIG_DIST_REPO ] || LIVE_CONFIG_DIST_REPO=""

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

if [ -x "${script_dir}/../dist-ai-tests-common/grub-generator-emit-check" ]; then
   checker="${script_dir}/../dist-ai-tests-common/grub-generator-emit-check"
else
   checker='/usr/share/dist-ai-tests-common/grub-generator-emit-check'
fi

if [ ! -x "${checker}" ]; then
   printf '%s\n' "FATAL: shared checker not found at '${checker}'" >&2
   exit 1
fi

if [ -n "${LIVE_CONFIG_DIST_REPO}" ]; then
   grub_d="${LIVE_CONFIG_DIST_REPO}/etc/grub.d"
else
   grub_d='/etc/grub.d'
fi

fail=0
skipped=0
checked=0

## SC2043: this component ships exactly ONE generator today, so the loop runs
## once. The loop shape is kept deliberately -- it is identical to the sibling
## suites, and adding a second generator here should not need a rewrite.
# shellcheck disable=SC2043
for generator in 35_uefi-firmware_live-config-dist; do
   rc=0
   "${checker}" "${grub_d}/${generator}" "${generator}" || rc=$?
   if [ "${rc}" -eq 77 ]; then
      skipped=$(( skipped + 1 ))
   elif [ "${rc}" -ne 0 ]; then
      fail=1
   else
      checked=$(( checked + 1 ))
   fi
done

## Every generator skipping is not a pass: it means the subject was never
## resolved, and the run would otherwise report a clean sweep over nothing.
if [ "${checked}" -eq 0 ]; then
   printf '%s\n' "SKIP: no generator resolved; set LIVE_CONFIG_DIST_REPO" >&2
   exit 77
fi

printf '%s\n' "" "${checked} generator(s) checked, ${skipped} skipped"
exit "${fail}"
