#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drift guard (authoritative half): the VirtualBox-host kernel-module build toolchain
## that dist-installer-cli and the virtualbox-host metapackage re-add (because
## Kicksecure installs --no-install-recommends) must COVER what Oracle's
## virtualbox-N package ACTUALLY Recommends -- parsed live from the package, never a
## hardcoded list. When Oracle adds a new build Recommends, this FAILS until both
## consumers re-add it.
##
## Needs the Oracle apt index (the virtualbox-N package must be visible to apt). Where
## it is not configured (a bare CI), this is a RUNTIME capability gap -> env-unmet SKIP
## (78), governed by the orchestrator's --allow-skip; it still gates on the provisioned
## VirtualBox host and any Oracle-repo environment. The offline installer-vs-meta
## consistency check is the sibling virtualbox_host_toolchain_consistency_test.sh.
##
## Required tooling (grep-dctrl, apt-cache) absent -> FATAL, never a silent skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
set -o noglob
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
suite_exit_helper="${script_dir}/../dist-ai-tests-common/suite-exit.bash"
[ -r "${suite_exit_helper}" ] || suite_exit_helper='/usr/share/dist-ai-tests-common/suite-exit.bash'
# shellcheck source=../dist-ai-tests-common/suite-exit.bash
source "${suite_exit_helper}"
# shellcheck source=./virtualbox_toolchain_lib.bash
source "${script_dir}/virtualbox_toolchain_lib.bash"

installer="$(vbox_installer_path)"
meta_control="$(vbox_meta_control_path)"
if [ ! -r "${installer}" ] || [ ! -r "${meta_control}" ]; then
   result_skip_target_absent "installer '${installer}' or meta control '${meta_control}' not readable; set USABILITY_MISC_REPO / DERIVATIVE_MAKER_DIR"
fi
if ! type -P grep-dctrl >/dev/null || ! type -P apt-cache >/dev/null; then
   printf '%s\n' 'FAIL: grep-dctrl (dctrl-tools) or apt-cache not on PATH; the guard cannot run' >&2
   result_fail
fi

## Non-build Recommends deliberately NOT re-added for a host. A Recommends group is
## excluded if ANY member is here (or it folds to empty, e.g. linux-image):
##   libasound2/libpulse0/libsdl-ttf2.0-0 -- audio/SDL, GUI-only, not module build
##   pdf-viewer                            -- documentation viewer
##   linux-image                           -- a kernel image; a host already runs one
##   kmod/kldutils/module-init-tools       -- Essential-priority base (modprobe/depmod),
##                                            always present, never dropped
exclude_members=" libasound2 libpulse0 libsdl-ttf2.0-0 pdf-viewer linux-image kmod kldutils module-init-tools "

## The Oracle package must be visible to apt; else the capability is unmet here.
vbox_pkg="$(apt-cache search --names-only '^virtualbox-[0-9]+\.[0-9]+$' 2>/dev/null | cut -d' ' -f1 | sort --version-sort | tail -1 || true)"
if [ -z "${vbox_pkg}" ]; then
   result_skip_env_unmet "no virtualbox-N package in the apt index (Oracle repo not configured here); cannot read its Recommends"
fi

recommends="$(apt-cache show --no-all-versions "${vbox_pkg}" 2>/dev/null | grep-dctrl --show-field=Recommends --no-field-names '' | head -1 || true)"
if [ -z "${recommends}" ]; then
   printf '%s\n' "FAIL: ${vbox_pkg} has no Recommends field (unexpected for an Oracle VirtualBox package)" >&2
   result_fail
fi

installer_set="$(vbox_installer_toolchain_set "${installer}")" || { printf '%s\n' "FAIL: installer toolchain extraction failed" >&2; result_fail; }
meta_set="$(vbox_meta_toolchain_set "${meta_control}")" || { printf '%s\n' "FAIL: meta toolchain extraction failed" >&2; result_fail; }

fail_count=0
pass() { printf '%s\n' "PASS: $1"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $1" >&2; }

## Does space-delimited set $2 contain any normalized member of group $1 (space list)?
set_covers_group() {
   local group_norm="$1" set="$2" member
   for member in ${group_norm}; do
      case " ${set} " in
         *" ${member} "*)
            return 0
            ;;
      esac
   done
   return 1
}

## Parse Recommends into comma groups (strip version/arch first), build the normalized
## union, and assert every REQUIRED (non-excluded) group is covered by BOTH consumers.
recommends_clean="$(printf '%s' "${recommends}" | sed -e 's/([^)]*)//g' -e 's/\[[^]]*\]//g')"
recommends_union=""
saved_ifs="${IFS}"
IFS=','
for group in ${recommends_clean}; do
   IFS="${saved_ifs}"
   group_members="$(printf '%s' "${group}" | tr '|' ' ')"
   ## excluded?
   excluded=0
   for member in ${group_members}; do
      case "${exclude_members}" in
         *" ${member} "*)
            excluded=1
            ;;
      esac
   done
   group_norm="$(normalize_set "${group_members}")"
   recommends_union="${recommends_union} ${group_norm}"
   ## a group that folds to empty (e.g. linux-image only) is non-build -> skip
   if [ "${excluded}" = "1" ] || [ -z "${group_norm// /}" ]; then
      IFS=','
      continue
   fi
   if set_covers_group "${group_norm}" "${installer_set}"; then
      pass "installer covers required Recommends group: ${group_norm}"
   else
      fail "installer does NOT cover required Recommends group '${group_norm}' (installer set: ${installer_set})"
   fi
   if set_covers_group "${group_norm}" "${meta_set}"; then
      pass "virtualbox-host meta covers required Recommends group: ${group_norm}"
   else
      fail "virtualbox-host meta does NOT cover required Recommends group '${group_norm}' (meta set: ${meta_set})"
   fi
   IFS=','
done
IFS="${saved_ifs}"
recommends_union="$(normalize_set "${recommends_union}")"

## Neither consumer may re-add a toolchain package the real package does NOT Recommend,
## except udev (Oracle's undeclared dep, ticket 21804).
for token in ${installer_set} ${meta_set}; do
   [ "${token}" = "udev" ] && continue
   case " ${recommends_union} " in
      *" ${token} "*)
         ;;
      *)
         fail "a consumer declares '${token}', which ${vbox_pkg} does not Recommend (and it is not the documented udev exception)"
         ;;
   esac
done

printf '%s\n' "---- recommends coverage vs ${vbox_pkg}: ${fail_count} failed ----"
suite_exit "${fail_count}" 0 0
