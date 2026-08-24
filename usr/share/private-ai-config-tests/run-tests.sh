#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Entry point for the private-ai-config test surface. Delegates to the
## component's own runner and adds nothing but this repo's tools.
##
## The lane membership, the exclusions and the authorized skips all live in the
## COMPONENT, beside the tests they describe. They used to live here, as arrays
## of paths into the other repo, which meant no single commit could add a test
## and register it: two repos, two PRs, and a red CI in between. Thirty-one test
## files accumulated in no lane that way -- never run, never reported.
##
## So this file must never learn a test's name again. If something here needs
## editing when a test is added, the split has come back.
##
## Exit contract (dist-ai-tests-all): 0 PASS / 77 SKIP / anything else FAIL.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

repo="${PRIVATE_AI_CONFIG_PATH:-}"
if [ -z "${repo}" ] || [ ! -d "${repo}/tests" ]; then
   printf '%s\n' 'private-ai-config-tests: PRIVATE_AI_CONFIG_PATH unset or has no tests/ dir; skipping.' >&2
   exit 77  ## style-ok: allow-skip: private-ai-config is a private repo, absent from the public dist-ai lane by design
fi
## Canonical: PRIVATE_AI_CONFIG_PATH may be RELATIVE, and a relative entry on
## PATH below resolves against whatever directory a test happens to chdir into.
repo="$(readlink --canonicalize -- "${repo}")"

runner="${repo}/tests/run"
if [ ! -f "${runner}" ]; then
   printf '%s\n' "private-ai-config-tests: no runner at ${runner}; the checkout predates the in-component test runner." >&2
   exit 1
fi

## dist-ai's own tools (pre-push-static and friends) live in THIS repo's
## usr/bin. An installed dist-ai already has them on PATH; a CI checkout does
## not, and a test driving the REAL gate rather than a stub then cannot find it.
##
## Canonicalised BEFORE the -d test, so a path that will not resolve fails the
## test and leaves PATH untouched. Resolving after it instead ('cd && pwd')
## yields an EMPTY string when the traversal fails, and an empty PATH element
## means the CURRENT directory.
runner_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
dist_ai_bin="$(readlink --canonicalize -- "${runner_dir}/../../bin" || true)"
if [ -d "${dist_ai_bin}" ]; then
   PATH="${dist_ai_bin}:${PATH}"
   export PATH
fi

bash -- "${runner}" "$@"
