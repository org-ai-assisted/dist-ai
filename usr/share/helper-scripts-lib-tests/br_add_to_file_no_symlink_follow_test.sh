#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## strings.bsh br_add_to_file must carry NO symlink-follow LPE sink: it writes
## "${file}_br" via an mktemp temp + atomic 'mv --no-target-directory' (rename
## replaces a dest symlink, never follows it), not the old in-place 'touch' /
## 'tee -a'. Drives the shipped dist_ai.lpe_sinks scanner over the REAL
## strings.bsh via the probe -- no copy of the subject. A missing dep is a HARD
## FAIL, never a skip (R-220).
##
## Tests the INSTALLED library by default; HELPER_SCRIPTS_REPO points it at a
## checkout explicitly, which is what the suite runner wires in CI where nothing
## is installed. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
  libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
else
  libdir='/usr/libexec/helper-scripts'
fi
strings_bsh_path="${libdir}/strings.bsh"

if [ ! -r "${strings_bsh_path}" ]; then
  printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh_path}'" >&2
  printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
  exit 1
fi
if [ ! -r "${libdir}/has.bsh" ]; then
  printf '%s\n' "FATAL: has.bsh not readable at '${libdir}/has.bsh'" >&2
  exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${libdir}/has.bsh"

if ! has python3 ; then
  printf '%s\n' "FATAL: python3 not on PATH" >&2
  exit 1
fi
if ! has shfmt ; then
  printf '%s\n' "FATAL: shfmt not on PATH (bash_ast requires it)" >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${script_dir}/br_add_to_file_no_symlink_follow_probe.py"
if [ ! -x "${probe}" ]; then
  printf '%s\n' "FATAL: probe not executable: ${probe}" >&2
  exit 1
fi

"${probe}" "${strings_bsh_path}"
