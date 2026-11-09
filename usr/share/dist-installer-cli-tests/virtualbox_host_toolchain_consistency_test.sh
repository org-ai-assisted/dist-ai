#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drift guard (offline half): the VirtualBox-host kernel-module build toolchain is
## declared in TWO places and they must not diverge:
##   - dist-installer-cli (usability-misc): re-adds the toolchain Oracle only
##     Recommends, dropped by Kicksecure's --no-install-recommends, on the
##     --oracle-repo Debian path.
##   - the virtualbox-host metapackage (kicksecure-meta-packages/debian/control):
##     Depends on the same toolchain so `apt upgrade` fixes existing hosts.
## A one-sided edit (adding a build dep to one but not the other) silently
## reintroduces the "vboxdrv absent after kernel update" failure on whichever path
## was missed. This test asserts the two toolchain sets are EQUAL. It needs no apt
## index (no Oracle repo), so it gates in every CI; the authoritative
## "both match virtualbox-N's real Recommends" check is the sibling
## virtualbox_recommends_coverage_test.sh (needs the Oracle index).
##
## Required tooling (grep-dctrl) absent -> FATAL, never a silent skip.

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
if ! type -P grep-dctrl >/dev/null; then
   printf '%s\n' 'FAIL: grep-dctrl (dctrl-tools) not on PATH; the guard cannot run' >&2
   result_fail
fi

fail_count=0

installer_set="$(vbox_installer_toolchain_set "${installer}")" || fail_count=$(( fail_count + 1 ))
meta_set="$(vbox_meta_toolchain_set "${meta_control}")" || fail_count=$(( fail_count + 1 ))

if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAIL: could not extract one or both toolchain sets (shape changed)" >&2
   suite_exit "${fail_count}" 0 0
fi

if [ "${installer_set}" = "${meta_set}" ]; then
   printf '%s\n' "PASS: installer and virtualbox-host meta declare the same build toolchain: ${installer_set}"
else
   printf '%s\n' "FAIL: build toolchain DIVERGED -- installer: '${installer_set}' vs meta: '${meta_set}'" >&2
   fail_count=$(( fail_count + 1 ))
fi

printf '%s\n' "---- toolchain consistency: ${fail_count} failed ----"
suite_exit "${fail_count}" 0 0
