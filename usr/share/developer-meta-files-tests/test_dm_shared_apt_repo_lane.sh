#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-shared-apt-repo shares a built apt repo from dm's shared repo base under
## /srv/derivative-maker. A laned build writes under /srv/derivative-maker/<slot>; a flat
## build writes directly under /srv/derivative-maker. This READER must resolve ONE share base
## (repo-path, attach, expose, cache-path all agree on it) matching whatever lane the build
## ACTUALLY used -- it must NOT follow an ambient dist_build_slot to a slot dir the build never
## populated (the flat-build + slotted-run 404 this guards). LOCAL_APT_REPOSITORY_BASE overrides
## outright. The existence probe keys on <slot>/aptrepo_local (only a real build creates it), so
## `expose`'s <slot>/aptcache side-effect cannot fool it into picking an empty slot.
##
## Drives the REAL script's `repo-path` / `cache-path` end to end (exercises the full
## repo_parent selection: ${repo_parent}/aptrepo_local/<deriv>); DM_SHARED_APT_REPO_ROOT
## relocates the repo root onto a temp fixture tree so slot-vs-flat selection is tested with
## no root and no /srv writes.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Hermetic: the resolver reads these from the environment, so a case that does not set one
## must not inherit a caller's value (a dm build shell exports dist_build_slot). Each case
## sets exactly what it needs; everything else starts cleared.
unset LOCAL_APT_REPOSITORY_BASE dist_build_slot DM_SHARED_APT_REPO_ROOT

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

## Fixture repo root: a flat repo, a populated laned repo, a slot dir that holds ONLY aptcache
## (the shape `expose` leaves behind when the build was actually flat), a slot dir carrying
## only the OTHER derivative, and a slot dir whose NAME holds a disallowed byte.
tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${tmp}"; }
trap cleanup EXIT
mkdir --parents -- "${tmp}/aptrepo_local/whonix"               # flat build output
mkdir --parents -- "${tmp}/laned/aptrepo_local/whonix"         # a laned build output
mkdir --parents -- "${tmp}/cache-only/aptcache"                # expose side-effect, no repo
mkdir --parents -- "${tmp}/kick-only/aptrepo_local/kicksecure" # slot holds only the OTHER deriv
mkdir --parents -- "${tmp}/has space/aptrepo_local/whonix"     # slot name with a disallowed byte
mkdir --parents -- "${tmp}/sub"                                # a repo_root for the traversal case
mkdir --parents -- "${tmp}/evil/aptrepo_local/whonix"          # a '..' escape target outside ${tmp}/sub

## 1. LOCAL_APT_REPOSITORY_BASE overrides outright (slot + root ignored).
got="$(LOCAL_APT_REPOSITORY_BASE=/custom/root dist_build_slot=ignored DM_SHARED_APT_REPO_ROOT="${tmp}" "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "/custom/root/aptrepo_local/whonix" ]; then pass "LOCAL_APT_REPOSITORY_BASE overrides outright"; else fail "override not honored (got '${got}')"; fi

## 2. Slot set AND the slotted repo exists -> slotted (a laned build is matched).
got="$(DM_SHARED_APT_REPO_ROOT="${tmp}" dist_build_slot=laned "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "${tmp}/laned/aptrepo_local/whonix" ]; then pass "slot with a populated slotted repo -> slotted"; else fail "laned repo not followed (got '${got}')"; fi

## 3. CANARY: slot set but the slotted repo is ABSENT, flat repo present -> flat. The exact
## flat-build + slotted-run shape. OLD code returned the nonexistent <root>/<slot> path
## (blind slot follow) -> this FAILS on old, passes on new.
got="$(DM_SHARED_APT_REPO_ROOT="${tmp}" dist_build_slot=no-such-slot "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "${tmp}/aptrepo_local/whonix" ]; then pass "slot set but slotted repo absent -> flat (flat build matched)"; else fail "invented a slot a flat build never populated (got '${got}')"; fi

## 4. CANARY: slot dir exists with ONLY aptcache (expose's side-effect), no aptrepo_local ->
## flat. The probe must key on <slot>/aptrepo_local, not the bare slot dir. FAILS on old.
got="$(DM_SHARED_APT_REPO_ROOT="${tmp}" dist_build_slot=cache-only "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "${tmp}/aptrepo_local/whonix" ]; then pass "slot dir with only aptcache (no repo) -> flat"; else fail "aptcache-only slot fooled the probe (got '${got}')"; fi

## 5. No slot -> flat (does NOT invent a slot).
got="$(DM_SHARED_APT_REPO_ROOT="${tmp}" "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "${tmp}/aptrepo_local/whonix" ]; then pass "no slot -> flat root"; else fail "wrong flat default (got '${got}')"; fi

## 6. CANARY (single-share invariant): repo-path and cache-path MUST agree on ONE base. A slot
## holding a built repo is chosen deriv-AGNOSTICALLY, so cache-path's aptcache sits beside the
## repo under the SAME base and the single 'shared' vboxsf carries both. OLD (per-deriv probe)
## picked the base PER derivative, so a slot holding only kicksecure sent repo-path whonix to
## flat while cache-path stayed slotted -> the share split, guest aptcache 404. The repo base
## (strip trailing /aptrepo_local/<deriv>) must equal the cache base (strip trailing /aptcache).
repo_whonix="$(DM_SHARED_APT_REPO_ROOT="${tmp}" dist_build_slot=kick-only "${subject}" repo-path whonix 2>/dev/null || true)"
cache_path="$(DM_SHARED_APT_REPO_ROOT="${tmp}" dist_build_slot=kick-only "${subject}" cache-path 2>/dev/null || true)"
repo_base="${repo_whonix%/aptrepo_local/whonix}"
cache_base="${cache_path%/aptcache}"
## Both outputs must actually carry their suffix (strip changed the string) before comparing --
## else two failed (empty) commands would strip to '' == '' and PASS vacuously.
if [ "${repo_whonix}" != "${repo_base}" ] && [ "${cache_path}" != "${cache_base}" ] && [ -n "${repo_base}" ] && [ "${repo_base}" = "${cache_base}" ]; then pass "repo-path and cache-path share one base (single-share invariant)"; else fail "share split or invalid path: repo '${repo_whonix}' cache '${cache_path}'"; fi

## 7. CANARY: a dist_build_slot with a disallowed byte (here a space) is REJECTED -> flat, never
## concatenated into a shared/mounted path. OLD (segment check that only rejected ''/./../ and
## '*/*') ACCEPTED 'has space' and shared "${tmp}/has space" -> this FAILS on old, passes on new.
got="$(DM_SHARED_APT_REPO_ROOT="${tmp}" dist_build_slot='has space' "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "${tmp}/aptrepo_local/whonix" ]; then pass "slot with a disallowed byte rejected -> flat"; else fail "slot charset not enforced (got '${got}')"; fi

## 8. CANARY: a '..' slot must not escape repo_root. Rejected -> flat (repo_root=${tmp}/sub),
## never the ${tmp}/evil target. A no-segment-check build concatenated and followed the escape.
got="$(DM_SHARED_APT_REPO_ROOT="${tmp}/sub" dist_build_slot=../evil "${subject}" repo-path whonix 2>/dev/null || true)"
if [ "${got}" = "${tmp}/sub/aptrepo_local/whonix" ]; then pass "traversal slot rejected -> flat (no repo_root escape)"; else fail "slot '..' escaped repo_root (got '${got}')"; fi

## 9. CANARY: a non-absolute LOCAL_APT_REPOSITORY_BASE is rejected (dies, no stdout) rather than
## rooting the share/mount at a relative path.
got="$(LOCAL_APT_REPOSITORY_BASE=relative/path "${subject}" repo-path whonix 2>/dev/null || true)"
if [ -z "${got}" ]; then pass "non-absolute LOCAL_APT_REPOSITORY_BASE rejected"; else fail "accepted a non-absolute base (got '${got}')"; fi

## 10. CANARY: a LOCAL_APT_REPOSITORY_BASE carrying whitespace is rejected (dies, no stdout). An
## embedded newline would survive command substitution mid-string and a space would split an
## unquoted mount path; dm forbids whitespace in this base too. OLD (absolute check only)
## ACCEPTED '/a b' and printed it -> this FAILS on old, passes on new.
got="$(LOCAL_APT_REPOSITORY_BASE='/a b' "${subject}" repo-path whonix 2>/dev/null || true)"
if [ -z "${got}" ]; then pass "whitespace LOCAL_APT_REPOSITORY_BASE rejected"; else fail "accepted a whitespace base (got '${got}')"; fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
