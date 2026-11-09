#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## user-sysmaint-split's /etc/grub.d boot-mode wrappers must still EMIT their menu
## entry AND export the per-mode boot_mode_id token that 10_00_linux_dist scopes
## each menuentry --id by. A shared id across boot modes makes id-based selection
## (grub-editenv next_entry / default) hit the first entry only, so the installed
## system could never be driven into SYSMAINT by id -- the exact property this guards.
##
## Reasoning + stubbed environment live in the shared checker (the dist engine it
## execs is stubbed to echo the inherited boot_mode_id):
##   /usr/share/dist-ai-tests-common/grub-generator-emit-check
##
## No root, no network, no grub-mkconfig.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v USER_SYSMAINT_SPLIT_REPO ] || USER_SYSMAINT_SPLIT_REPO=""

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

## The wrappers ship as conf files symlinked into /etc/grub.d (see
## debian/user-sysmaint-split.links); test the checkout's conf files when the repo
## is wired, else the installed symlinks.
if [ -n "${USER_SYSMAINT_SPLIT_REPO}" ]; then
   conf_dir="${USER_SYSMAINT_SPLIT_REPO}/usr/share/user-sysmaint-split/conf"
   sysmaint_gen="${conf_dir}/grub.d_10_10_linux_sysmaint"
   remove_gen="${conf_dir}/grub.d_10_30_linux_remove_sysmaint"
else
   sysmaint_gen='/etc/grub.d/10_10_linux_sysmaint'
   remove_gen='/etc/grub.d/10_30_linux_remove_sysmaint'
fi

fail=0
skipped=0
checked=0

check_one() {
   local generator="$1" token="$2" extra="${3:-}" rc=0
   GRUB_EMIT_CHECK_EXTRA_ENV="${extra}" \
      "${checker}" "${generator}" "$(basename -- "${generator}")${extra:+ [${extra}]}" "${token}" \
      || rc=$?
   if [ "${rc}" -eq 77 ]; then
      skipped=$(( skipped + 1 ))
   elif [ "${rc}" -ne 0 ]; then
      fail=1
   else
      checked=$(( checked + 1 ))
   fi
}

## The SYSMAINT wrapper is re-exec'd by grub-live's 10_20_linux_live with
## persistence_type=LIVE, so its --id token MUST differ by persistence -- else the
## live and persistent SYSMAINT entries share one id and id-based selection cannot
## tell them apart. Assert both. REMOVE is persistent-only (never live-chained).
check_one "${sysmaint_gen}" 'boot_mode_id=persistent-sysmaint'
check_one "${sysmaint_gen}" 'boot_mode_id=live-sysmaint' 'persistence_type=LIVE'
check_one "${remove_gen}"   'boot_mode_id=remove-sysmaint'

## All-skipped is not a pass: the subject was never resolved. (A real failure
## already set fail=1 and must report as a failure, not this diagnostic.)
if [ "${checked}" -eq 0 ] && [ "${fail}" -eq 0 ]; then
   printf '%s\n' "FATAL: no generator resolved; set USER_SYSMAINT_SPLIT_REPO" >&2
   exit 1
fi

printf '%s\n' "" "${checked} generator(s) checked, ${skipped} skipped"
exit "${fail}"
