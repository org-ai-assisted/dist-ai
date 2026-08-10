#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI helper for reusable-pre-push-static.yml: read the caller repo's
## .github/dm-consumer.yml and report whether the static gate needs a
## helper-scripts sibling checkout, so 'shellcheck -x' can FOLLOW a
## '# shellcheck source=../../../../helper-scripts/...' directive instead of
## emitting SC1091 -- which consumers otherwise silence with an inline
## '# shellcheck disable=SC1091'.
##
## Reuses the SAME 'dist-ai-tests: helper-scripts: true' flag consumers already
## set for the test runtime: one signal that a repo sources helper-scripts, so a
## consumer opts in once. A dedicated reader rather than dist-ai-tests-ci-config.sh,
## which also inits submodules and resolves an apt-package set the static gate
## neither wants nor has.
##
## All control-flow logic lives here, not inline in the workflow yaml (no
## embedded shell scripts in CI files). Requires the apt 'yq'.
##
## Usage: pre-push-static-ci-config.sh <path-to-dm-consumer.yml>
## Emits to $GITHUB_OUTPUT:
##   helper_scripts  'true' if a helper-scripts sibling checkout is needed

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

cfg="${1:-}"
if [ -z "${cfg}" ]; then
   printf '%s\n' 'pre-push-static-ci-config: missing dm-consumer.yml path argument' >&2
   exit 2
fi

## A missing 'yq' would make the read emit nothing, silently reporting
## helper_scripts=false -- so a consumer that opted in would still hit SC1091.
## Fail loud naming the dependency instead. 'type -P', not the house 'has': this
## script does not source helper-scripts (it runs before that is even provided).
if ! type -P yq >/dev/null; then
   printf '%s\n' 'pre-push-static-ci-config: yq not found (apt-get install yq)' >&2
   exit 1
fi

helper_scripts='false'
if [ -f "${cfg}" ] \
   && [ "$(yq -r '.["dist-ai-tests"]["helper-scripts"] // ""' -- "${cfg}")" = 'true' ]; then
   helper_scripts='true'
fi

printf '%s\n' "helper_scripts=${helper_scripts}" >> "${GITHUB_OUTPUT}"
