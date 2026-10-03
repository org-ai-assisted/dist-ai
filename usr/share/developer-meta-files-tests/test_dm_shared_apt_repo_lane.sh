#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-shared-apt-repo shares a built apt repo from dm's binary build dir. A laned build writes under
## derivative-binary/<slot>, so this READER must follow a forwarded/explicit dist_build_slot to find
## the repo -- but must NOT invent a slot (that could miss a flat build). DERIVATIVE_BINARY overrides
## outright. The real repo_parent line is extracted + eval'd. Canary: fails on the pre-lane default.

## File-wide: repo_parent is assigned by `eval` of the extracted line; dist_build_slot /
## DERIVATIVE_BINARY are read by it (SC2034/SC2154); the grep patterns match the subject's
## literal '${...}' text, so single quotes are intentional (SC2016).
# shellcheck disable=SC2016,SC2034,SC2154
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DIST_AI_REPO:-}" ]; then
   subject="${DIST_AI_REPO}/usr/bin/dm-shared-apt-repo"
else
   here="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
   subject="${here}/../../bin/dm-shared-apt-repo"
   [ -f "${subject}" ] || subject='/usr/bin/dm-shared-apt-repo'
fi
[ -f "${subject}" ] || { printf '%s\n' "FATAL: dm-shared-apt-repo not found" >&2; exit 1; }

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*"; }

line="$(grep -E '^repo_parent=' -- "${subject}")"
if [ -z "${line}" ]; then
   fail "dm-shared-apt-repo has no repo_parent assignment"
   printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
   exit 1
fi

HOME=/home/user

## DERIVATIVE_BINARY overrides everything.
DERIVATIVE_BINARY=/custom/root dist_build_slot=ignored eval "${line}"
if [ "${repo_parent}" = "/custom/root" ]; then pass "DERIVATIVE_BINARY overrides outright"; else fail "DERIVATIVE_BINARY not honored (got '${repo_parent}')"; fi

## A forwarded/explicit slot -> the lane subdir.
unset DERIVATIVE_BINARY
dist_build_slot=sess-XYZ eval "${line}"
if [ "${repo_parent}" = "/home/user/derivative-binary/sess-XYZ" ]; then pass "dist_build_slot -> derivative-binary/<slot>"; else fail "lane not followed (got '${repo_parent}')"; fi

## No slot -> flat (does NOT invent a slot; matches a flat build).
unset dist_build_slot
eval "${line}"
if [ "${repo_parent}" = "/home/user/derivative-binary" ]; then pass "no slot -> flat derivative-binary (flat build matched)"; else fail "invented a slot / wrong flat default (got '${repo_parent}')"; fi

## Structural: a followed lane is VALIDATED before it becomes a share host path (a '..'
## would point the read-only guest share outside derivative-binary). CANARY.
if grep -E 'check_is_alpha_numeric[[:space:]]+dist_build_slot' -- "${subject}" >/dev/null; then
   pass "dist_build_slot is validated with check_is_alpha_numeric when the lane is followed"
else
   fail "dist_build_slot is NOT validated -- '..' would share a dir outside derivative-binary"
fi

## Structural: helper-scripts is sourced LAZILY (inside the lane-followed branch), so the common
## flat / DERIVATIVE_BINARY path needs no helper-scripts dependency. CANARY.
src_ln="$(grep -n 'helper-scripts/strings.bsh' -- "${subject}" | head -1 | cut -d: -f1)"
branch_ln="$(grep -n 'DERIVATIVE_BINARY:-}" \] && \[ -n "\${dist_build_slot' -- "${subject}" | head -1 | cut -d: -f1)"
if [ -n "${src_ln}" ] && [ -n "${branch_ln}" ] && [ "${src_ln}" -gt "${branch_ln}" ]; then
   pass "strings.bsh sourced lazily inside the lane-followed branch (flat path needs no dep)"
else
   fail "strings.bsh sourced unconditionally (regresses the flat / override path)"
fi

## Structural: the rejected slot is printed via string_quote_safe (no terminal-escape injection).
if grep -E 'string_quote_safe' -- "${subject}" >/dev/null; then
   pass "invalid-lane error quotes the slot with string_quote_safe"
else
   fail "invalid-lane error prints the slot raw (terminal-escape injection)"
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
