#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI helper for reusable-dist-ai-tests.yml: read the caller repo's per-repo
## dist-ai test config from .github/dm-consumer.yml and emit the resolved
## values to $GITHUB_OUTPUT for later workflow steps. All control-flow logic
## lives here, not embedded in the workflow yaml (no embedded shell scripts in
## CI files). Requires the apt 'yq' (kislyuk python-yq) already installed.
##
## Usage: dist-ai-tests-ci-config.sh <path-to-dm-consumer.yml>
##
## Emits to $GITHUB_OUTPUT:
##   apt_packages    packages to apt-install for the suites (default: the base
##                   testing stack)
##   helper_scripts  'true' if a helper-scripts checkout is also needed
##   hs_arg          the matching '--helper-scripts-root <dir>' argument for
##                   dist-ai-tests-all, or empty

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

cfg="${1:-}"
if [ -z "${cfg}" ]; then
   printf '%s\n' 'dist-ai-tests-ci-config: missing dm-consumer.yml path argument' >&2
   exit 2
fi

apt_packages='python3 python3-pytest python3-hypothesis'
helper_scripts='false'
skip_args=''

if [ -f "${cfg}" ]; then
   value="$(yq -r '.["dist-ai-tests"]["apt-packages"] // ""' "${cfg}")"
   if [ -n "${value}" ] && [ "${value}" != 'null' ]; then
      apt_packages="${value}"
   fi
   if [ "$(yq -r '.["dist-ai-tests"]["helper-scripts"] // ""' "${cfg}")" = 'true' ]; then
      helper_scripts='true'
   fi
   ## Optional list of suite entrypoints to skip (a suite temporarily broken /
   ## pending a merge). Each becomes a '--skip <name>' argument.
   while IFS= read -r skip_name; do
      [ -n "${skip_name}" ] || continue
      case "${skip_name}" in
         *[![:alnum:]-]*)
            printf '%s\n' "dist-ai-tests-ci-config: invalid skip suite name: ${skip_name}" >&2
            exit 1
            ;;
      esac
      skip_args="${skip_args} --skip ${skip_name}"
   done < <(yq -r '.["dist-ai-tests"].skip[]? // empty' "${cfg}")
fi

## Reject newline injection into $GITHUB_OUTPUT.
case "${apt_packages}" in
   *$'\n'*|*$'\r'*)
      printf '%s\n' 'dist-ai-tests-ci-config: dist-ai-tests.apt-packages contains a newline' >&2
      exit 1
      ;;
esac

{
   printf 'apt_packages=%s\n' "${apt_packages}"
   printf 'helper_scripts=%s\n' "${helper_scripts}"
   printf 'skip_args=%s\n' "${skip_args# }"
   if [ "${helper_scripts}" = 'true' ]; then
      printf 'hs_arg=--helper-scripts-root %s/helper-scripts\n' "${GITHUB_WORKSPACE}"
   else
      printf 'hs_arg=\n'
   fi
} >> "${GITHUB_OUTPUT}"
