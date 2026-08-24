#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Secret-isolation regression guard. Driven by
## developer-meta-files' local-secrets-audit.yml (workflow_dispatch).
## Presence flags arrive as boolean env vars computed at
## expression-evaluation time; secret values themselves never reach
## this script.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ "${CI:-}" != "true" ] && [ "${ALLOW_LOCAL:-}" != "true" ]; then
  printf '%s\n' "${BASH_SOURCE[0]}: refusing to run outside CI. Set ALLOW_LOCAL=true to override." >&2
  exit 1
fi

fail=0

printf '%s\n' "CLAUDE_CODE_OAUTH_TOKEN present: ${CLAUDE_OAUTH_PRESENT:-unknown}"
printf '%s\n' "OPENAI_API_KEY present:          ${OPENAI_PRESENT:-unknown}"
printf '%s\n' "COVERITY_SCAN_TOKEN present:     ${COVERITY_TOKEN_PRESENT:-unknown}"
printf '%s\n' "COVERITY_SCAN_EMAIL present:     ${COVERITY_EMAIL_PRESENT:-unknown}"

if [ "${OPENAI_PRESENT:-}" = "true" ]; then
  printf '%s\n' '::error::OPENAI_API_KEY leaked into the secrets context' >&2
  fail=1
fi

if [ "${COVERITY_TOKEN_PRESENT:-}" = "true" ]; then
  printf '%s\n' '::error::COVERITY_SCAN_TOKEN leaked into the secrets context' >&2
  fail=1
fi

if [ "${COVERITY_EMAIL_PRESENT:-}" = "true" ]; then
  printf '%s\n' '::error::COVERITY_SCAN_EMAIL leaked into the secrets context' >&2
  fail=1
fi

if [ "${CLAUDE_OAUTH_PRESENT:-}" != "true" ]; then
  printf '%s\n' '::warning::CLAUDE_CODE_OAUTH_TOKEN not forwarded by caller' >&2
fi

exit "${fail}"
