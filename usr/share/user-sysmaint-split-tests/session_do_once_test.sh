#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## sysmaint-session-wayland: an unwritable HOME must not stop the session from starting.
##
## The reasoning and the driver live in the shared checker, because a second
## component ships an equivalent script and one copy of the argument is better
## than two that drift:
##   /usr/share/dist-ai-tests-common/session-do-once-check
##
## No root, no network, no session.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v USER_SYSMAINT_SPLIT_REPO ] || USER_SYSMAINT_SPLIT_REPO=""

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

if [ -x "${script_dir}/../dist-ai-tests-common/session-do-once-check" ]; then
   checker="${script_dir}/../dist-ai-tests-common/session-do-once-check"
else
   checker='/usr/share/dist-ai-tests-common/session-do-once-check'
fi

if [ ! -x "${checker}" ]; then
   printf '%s\n' "FATAL: shared checker not found at '${checker}'" >&2
   exit 1
fi

if [ -n "${USER_SYSMAINT_SPLIT_REPO}" ]; then
   subject="${USER_SYSMAINT_SPLIT_REPO}/usr/libexec/user-sysmaint-split/sysmaint-session-wayland"
else
   subject="/usr/libexec/user-sysmaint-split/sysmaint-session-wayland"
fi

"${checker}" "${subject}" 'sysmaint-session-wayland'
