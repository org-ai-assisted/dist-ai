#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-shared-apt-repo shares a built apt repo from dm's shared repo base under
## /srv/derivative-maker. A laned build writes under /srv/derivative-maker/<slot>, so this
## READER must follow a forwarded/explicit dist_build_slot to find the repo -- but must NOT
## invent a slot (that could miss a flat build). LOCAL_APT_REPOSITORY_BASE overrides outright.
## The real repo_parent line is extracted + eval'd.

## File-wide: repo_parent is assigned by `eval` of the extracted line; dist_build_slot /
## LOCAL_APT_REPOSITORY_BASE are read by it (SC2034/SC2154); the grep patterns match the
## subject's literal '${...}' text, so single quotes are intentional (SC2016).
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

## Drive the REAL script's `repo-path` (it exercises the FULL repo_parent selection end to end:
## ${repo_parent}/aptrepo_local/<deriv>), not an eval of the extracted line in isolation -- a
## later re-derivation inside the script would otherwise pass unnoticed.

## LOCAL_APT_REPOSITORY_BASE overrides everything (slot ignored).
got="$(LOCAL_APT_REPOSITORY_BASE=/custom/root dist_build_slot=ignored "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "/custom/root/aptrepo_local/whonix" ]; then pass "LOCAL_APT_REPOSITORY_BASE overrides outright"; else fail "LOCAL_APT_REPOSITORY_BASE not honored (got '${got}')"; fi

## A forwarded/explicit slot -> the lane subdir under /srv/derivative-maker.
got="$(dist_build_slot=sess-XYZ "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "/srv/derivative-maker/sess-XYZ/aptrepo_local/whonix" ]; then pass "dist_build_slot -> /srv/derivative-maker/<slot>"; else fail "lane not followed (got '${got}')"; fi

## No slot -> flat (does NOT invent a slot; matches a flat build).
got="$("${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "/srv/derivative-maker/aptrepo_local/whonix" ]; then pass "no slot -> flat /srv/derivative-maker (flat build matched)"; else fail "invented a slot / wrong flat default (got '${got}')"; fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
