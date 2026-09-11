#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Run a component's dist-ai suites FAITHFULLY: real derivative-maker builds start
## as a NON-ROOT user and 'sudo' internally for privileged steps; the resolver
## (help-steps/pre + variables) is written for that non-root invoker and refuses
## to run as root. GitHub runs container steps as root, so when invoked as root
## this drops to a dedicated non-root build user -- passwordless sudo for dm's
## internal escalation, owning the workspace so the resolver's 'git rev-parse
## HEAD' is not refused for dubious ownership -- and runs the suite as it. When
## already non-root (a developer host) it runs the suite directly, unchanged.
##
## This is the ONLY CI-side logic that needs to live near the workflow; the
## reusable workflow (developer-meta-files) is a thin caller, so future changes
## land here in dist-ai rather than in the reusable.
##
## All arguments are forwarded verbatim to dist-ai-tests-all.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
tests_all="${script_dir}/../usr/bin/dist-ai-tests-all"
if [ ! -x "${tests_all}" ]; then
   tests_all="dist-ai-tests-all"
fi

## Already non-root: a developer host runs the suite as themselves, exactly as a
## real build is started.
if [ "$(id -u)" != "0" ]; then
   ## style-ok: R-103 -- a thin CI wrapper is MEANT to replace itself with the suite runner.
   exec "${tests_all}" "$@"
fi

## Root (the GitHub container default): reproduce the non-root build context.
build_user="dm-ci-build"
id "${build_user}" >/dev/null 2>&1 \
   || useradd --create-home --shell /bin/bash "${build_user}"
## dm 'sudo's internally for privileged build steps; grant that. Inert without sudo.
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "${build_user}" \
   > "/etc/sudoers.d/${build_user}"
## Own the whole workspace so the build user can read the trees, write scratch,
## and use git (no 'dubious ownership' refusal in the resolver's git HEAD read).
workspace="${GITHUB_WORKSPACE:-${PWD}}"
chown --recursive "${build_user}" "${workspace}"
## Run the suite as the build user, preserving the CI environment; only HOME is
## repointed at the build user's own writable home.
exec runuser --preserve-environment -u "${build_user}" -- \
   env HOME="/home/${build_user}" "${tests_all}" "$@"
