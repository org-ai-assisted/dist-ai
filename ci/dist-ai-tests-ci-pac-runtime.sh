#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI helper for reusable-dist-ai-tests.yml: expose a checked-out private-ai-config
## tree's safe-pgrep / safe-pkill on the system PATH (/usr/local/bin), so the
## secure-terminal-shots reaper's marker-scoped orphan sweep resolves them. They
## ship ONLY in private-ai-config, and the reaper HARD-FAILS (R-220) when they are
## absent rather than fall back to a bare pgrep -f (which self-matches the caller's
## own shell). On the host they are already on PATH via the installed package; this
## reproduces that in the container. Both scripts are self-contained (source
## nothing), so a symlink is sufficient -- no sibling-relative resolution to keep.
##
## Usage: dist-ai-tests-ci-pac-runtime.sh <private-ai-config checkout root>

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pac_root="${1:-}"
if [ -z "${pac_root}" ]; then
   printf '%s\n' 'dist-ai-tests-ci-pac-runtime: missing private-ai-config checkout root argument' >&2
   exit 2
fi

mkdir --parents /usr/local/bin
for tool in safe-pgrep safe-pkill; do
   src="${pac_root}/usr/bin/${tool}"
   if [ ! -f "${src}" ]; then
      printf '%s\n' "dist-ai-tests-ci-pac-runtime: ${src} not found (private-ai-config checkout incomplete)" >&2
      exit 1
   fi
   ## ABSOLUTE target: 'ln -s' stores the literal string, and a RELATIVE src (a
   ## relative checkout root) would be re-resolved from /usr/local/bin -> a broken
   ## link that only surfaces later as an unrelated R-220 reaper failure. Canonicalize
   ## so the link is valid whatever CWD the checkout root was relative to.
   src="$(readlink --canonicalize -- "${src}")"
   ln --symbolic --force --no-target-directory -- "${src}" "/usr/local/bin/${tool}"
   chmod +x "${src}"
done
