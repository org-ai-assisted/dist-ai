#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Runs INSIDE temp-claude, invoked by secure-terminal-shots-sandbox after it syncs the three
## trees. Kept as its own file rather than an inline `bash -lc` in the driver: an inline
## multi-line interpreter program is a style violation (belongs in a file), same rule as an
## inline python heredoc. Points the in-sandbox runner at the freshly-synced trees and streams
## its per-terminal progress line-buffered so the durable-bg supervisor tracks real liveness.
##
## Usage (in the sandbox): run-lane-in-sandbox.sh SANDBOX_BASE LANE [LANE_ARGS...]
##   SANDBOX_BASE   the sync dir under $HOME holding secure-terminal / dist-ai / terminal-poc-corpus

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ "$#" -lt 2 ]; then
   printf '%s\n' 'run-lane-in-sandbox.sh: need SANDBOX_BASE and LANE' >&2
   exit 2
fi

sandbox_base="$1"
shift

export SECURE_TERMINAL_REPO="${HOME}/${sandbox_base}/secure-terminal"
export CORPUS_REPO="${HOME}/${sandbox_base}/terminal-poc-corpus"

## The synced dist-ai tree carries its local (gitignored) shots/ dir; clear it so this run pulls
## back ONLY the shots it just captured, never stale ones from an earlier local/filtered capture.
shots_out="${HOME}/${sandbox_base}/dist-ai/usr/share/secure-terminal-shots/shots"
safe-rm --recursive --force -- "${shots_out}"
mkdir --parents -- "${shots_out}"

## stdbuf -oL: line-buffer the lane so its per-terminal "captured X" progress reaches the
## caller (and the durable-bg progress file) as it happens, not flushed at the end -- a silent
## multi-minute capture was false-stalling the supervisor.
stdbuf -oL -eL "${HOME}/${sandbox_base}/dist-ai/usr/bin/secure-terminal-shots" "$@"
