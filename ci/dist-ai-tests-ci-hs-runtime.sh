#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI helper for reusable-dist-ai-tests.yml: expose a checked-out helper-scripts
## tree's runtime files at the system path /usr/libexec/helper-scripts, for
## tools that source them via an ABSOLUTE path (genmkfile's make-helper ->
## trace.bsh, git-meld -> has.sh). PATH / PYTHONPATH / HELPER_SCRIPTS_PATH are
## wired per-suite by dist-ai-tests-all; only this absolute path needs a link.
##
## Usage: dist-ai-tests-ci-hs-runtime.sh <helper-scripts checkout root>

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

hs_root="${1:-}"
if [ -z "${hs_root}" ]; then
   printf '%s\n' 'dist-ai-tests-ci-hs-runtime: missing helper-scripts checkout root argument' >&2
   exit 2
fi

src="${hs_root}/usr/libexec/helper-scripts"
if [ ! -d "${src}" ]; then
   printf '%s\n' "dist-ai-tests-ci-hs-runtime: ${src} not found" >&2
   exit 1
fi

mkdir --parents /usr/libexec
ln --symbolic --force --no-target-directory -- "${src}" /usr/libexec/helper-scripts
