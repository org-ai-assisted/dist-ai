#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai-tests-all's pkg_dir() honors an ambient DIST_AI_PKG_<NAME> override, so
## a local "run everything" can point a subject that is NOT a monorepo packages/
## subpath (a sibling repo such as secure-terminal) at an arbitrary checkout.
## Extracts the REAL pkg_dir from the shipped orchestrator and drives it.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
orch="${test_dir}/../../bin/dist-ai-tests-all"
if [ ! -r "${orch}" ]; then
   orch='/usr/bin/dist-ai-tests-all'
fi
if [ ! -r "${orch}" ]; then
   printf '%s\n' 'FATAL: pkg_dir_env_override_test: dist-ai-tests-all not found' >&2
   exit 1
fi

## Extract the real pkg_dir() -- from its header to the first column-0 '}'.
pkg_dir_src="$(awk '
   /^pkg_dir\(\) \{/ { f = 1 }
   f { print }
   f && /^\}$/ { exit }
' "${orch}")"
if [ -z "${pkg_dir_src}" ]; then
   printf '%s\n' 'FATAL: could not extract pkg_dir() from dist-ai-tests-all' >&2
   exit 1
fi
eval "${pkg_dir_src}"

## The resolution context the eval'd pkg_dir reads via dynamic scope; shellcheck
## cannot see the use across the eval, hence the disable.
# shellcheck disable=SC2034
component=''
# shellcheck disable=SC2034
component_root=''
# shellcheck disable=SC2034
helper_scripts_root=''
# shellcheck disable=SC2034
repo_root='/fake/monorepo'

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## No override: a monorepo package resolves to its packages/ path.
check "no override -> monorepo path" \
   "$(pkg_dir security-misc)" '/fake/monorepo/packages/kicksecure/security-misc'

## Override wins for a sibling repo whose normal resolution would be a path that
## does not exist.
check "DIST_AI_PKG_SECURE_TERMINAL wins" \
   "$(DIST_AI_PKG_SECURE_TERMINAL='/home/user/private-sources/secure-terminal' pkg_dir secure-terminal)" \
   '/home/user/private-sources/secure-terminal'

## Dash -> underscore in the var name (terminal-poc-corpus -> DIST_AI_PKG_TERMINAL_POC_CORPUS).
check "dashed name maps '-' to '_'" \
   "$(DIST_AI_PKG_TERMINAL_POC_CORPUS='/checkout/tpc' pkg_dir terminal-poc-corpus)" \
   '/checkout/tpc'

## An empty override is ignored (falls through to normal resolution).
check "empty override is ignored" \
   "$(DIST_AI_PKG_SECURITY_MISC='' pkg_dir security-misc)" \
   '/fake/monorepo/packages/kicksecure/security-misc'

## The override does not disturb an unrelated subject.
check "override is per-subject (no bleed)" \
   "$(DIST_AI_PKG_SECURE_TERMINAL='/x' pkg_dir security-misc)" \
   '/fake/monorepo/packages/kicksecure/security-misc'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
