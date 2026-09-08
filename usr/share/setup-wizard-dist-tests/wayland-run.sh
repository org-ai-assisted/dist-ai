#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Run a command against a private, headless Wayland compositor (the xvfb-run analogue for
## Wayland), so a Qt client connects to the real 'wayland' platform plugin. Delegates to the
## shared wl-headless-run (labwc on WLR_BACKENDS=headless), the single source of the compositor
## bringup used by the shots capture and the other GUI-test harnesses -- no private weston.
## --no-autoconfirm: the setup-wizard render probe self-captures via Qt grab() and has no
## dialog to click, so the input auto-confirm loop is not needed here.
##
##   wayland-run.sh <command> [args...]

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
## Last command: its exit code is this script's (no `exec` process-replacement, per R-103).
"${here}/../dist-ai-tests-common/wl-headless-run" --no-autoconfirm -- "$@"
