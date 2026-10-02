#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for usr/bin/dm-iso-build.
##
## WHY this exists: dm-iso-build must produce a test/gate image that ships the
## derivative APT repository ENABLED, exactly as a release image does. It used to
## call `./derivative-maker` DIRECTLY with no --repo and no dist_build_redistributable,
## so build_remote_repo_enable stayed at its false default, repository_dist_initializer_setup
## was skipped, /var/lib/repository-dist/derivative_apt_repository_opts was never written,
## and the ISO shipped the repo DISABLED (systemcheck check_apt_repository == Disabled,
## caught on a live-ISO gate). The fix routes dm-iso-build through the OFFICIAL path
## (help-steps/dm-build-official-one), which sets dist_build_redistributable=true and
## thereby enables --repo (repo is the official path's implicit default; dm-iso-build
## must NOT pass --repo itself).
##
## This guards the INPUT side (fast, no ~1h build): it dry-plans dm-iso-build via
## dm-build-official-one's --show-steps and asserts the per-flavor ISO build carries
## `--repo true`. The OUTPUT side (the opts file actually present in the built squashfs,
## and systemcheck check_apt_repository on the live gate) is owned by the image/boot
## harness post-build and must never be masked.
##
## It also structurally guards two safety-critical properties of dm-iso-build itself:
##   - it drives dm-build-official-one, never a bare ./derivative-maker (the old bug);
##   - it forces uploads to simulate (a test/gate builder must NEVER publish to the
##     release server).
##
## Source-tree test. The dist-ai checkout is found via DIST_AI_REPO or the script
## location; the derivative-maker checkout via DERIVATIVE_MAKER_DIR or ~/derivative-maker.
## No dist-ai tree is FATAL (exit 1). No derivative-maker checkout is an OPTIONAL
## SKIP (exit 77): dm-iso-build cannot be dry-planned without the orchestration it
## drives, and that sibling checkout is not always present.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## Resolve the dist-ai checkout that ships dm-iso-build.
repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dm-iso-build" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi
if [ -z "${repo}" ] || [ ! -f "${repo}/usr/bin/dm-iso-build" ]; then
   printf '%s\n' 'FATAL: dm-iso-build-repo-enabled-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi
dm_iso_build="${repo}/usr/bin/dm-iso-build"

failures=0
fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## ---- a caller-passed --repo must be REFUSED ------------------------------------
## This builder always builds repo-ENABLED via the official path; a caller must not
## be able to pass --repo (true duplicates the default, false would otherwise ride
## through to a late redistributable-incompatibility error). The refusal happens
## before any derivative-maker work, so this runs even without that checkout.
## Assert the refusal MESSAGE, not merely a non-zero exit: the OLD code also exits
## non-zero here (cd to a bogus DM_REPO, or ./derivative-maker rejecting --show-steps),
## so an exit-code check would false-pass it. The refusal fires before any cd, so a
## bogus DM_REPO is fine.
for repo_flag_arg in '--repo true' '--repo false' '--repo=false'; do
   # shellcheck disable=SC2086  ## deliberate word-split of the test arg pair
   refuse_out="$(DM_REPO=/nonexistent/dm bash -- "${dm_iso_build}" ${repo_flag_arg} --show-steps 2>&1 || true)"
   if ! grep --quiet -- "refusing '--repo'" <<< "${refuse_out}"; then
      fail "dm-iso-build did not refuse a caller-passed '${repo_flag_arg}' -- it must refuse --repo so the image is always repo-enabled"
   fi
done

## Resolve the derivative-maker checkout dm-iso-build drives.
dm_repo="${DERIVATIVE_MAKER_DIR:-}"
if [ -z "${dm_repo}" ] && [ -n "${HOME:-}" ]; then
   dm_repo="${HOME}/derivative-maker"
fi
if [ -z "${dm_repo}" ] || [ ! -f "${dm_repo}/help-steps/dm-build-official-one" ]; then
   if [ "${failures}" -ne 0 ]; then
      printf '%s\n' "dm-iso-build-repo-enabled-test: ${failures} check(s) failed" >&2
      exit 1
   fi
   printf '%s\n' "dm-iso-build-repo-enabled-test: no derivative-maker checkout at '${dm_repo}' (set DERIVATIVE_MAKER_DIR); ran --repo-refusal checks only. SKIP the build-plan checks." >&2
   ## style-ok: allow-skip: the dry-plan checks cannot run without a derivative-maker checkout (optional sibling).
   exit 77
fi

## ---- behavioral: the dry-planned ISO build enables the repo --------------------
## --show-steps makes dm-build-official-one PRINT the build plan without running it,
## so this exercises the real routing (dm-iso-build -> dm-build-official-one) with no
## ~1h build. On the OLD dm-iso-build (bare ./derivative-maker), --show-steps is an
## unknown flag that parse-cmd rejects AND no --repo true is ever emitted, so this
## assertion FAILS -- which is the point.
plan="$(DM_REPO="${dm_repo}" DM_FLAVOR=kicksecure-lxqt DM_ARCH=amd64 \
   bash -- "${dm_iso_build}" --show-steps 2>/dev/null)" || plan=''

## The per-flavor ISO build line: `./derivative-maker ... --target iso --flavor kicksecure-lxqt ...`.
## `|| true`: a no-match grep must yield an empty string for the assertion below to
## report it cleanly, not abort the test via errexit/pipefail (which, on the OLD
## no-repo code whose --show-steps emits no plan, would kill the test silently).
iso_build_line="$(printf '%s\n' "${plan}" \
   | grep -- './derivative-maker' \
   | grep -- '--target iso' \
   | grep -- '--flavor kicksecure-lxqt' \
   | head -n1 || true)"

if [ -z "${iso_build_line}" ]; then
   fail 'no ISO build step (./derivative-maker --target iso --flavor kicksecure-lxqt) found in the dm-iso-build plan -- dm-iso-build did not route through dm-build-official-one'
elif ! grep --quiet -- '--repo true' <<< "${iso_build_line}"; then
   fail "the ISO build step does not carry '--repo true' (repo would ship DISABLED): ${iso_build_line}"
fi

## The plan must come from the official orchestration: a bare ./derivative-maker
## --show-steps errors in parse-cmd (unknown flag) and emits no plan, so these
## dm-build-official-one build-steps.d/* run_cmd plan lines prove the official routing.
if ! grep --quiet --fixed-strings -- './build-steps.d/' <<< "${plan}"; then
   fail 'the plan lacks dm-build-official-one build-steps.d/* lines -- routing through the official path is not confirmed'
fi

## ---- structural: safety-critical invariants of dm-iso-build itself -------------
## Guard against a regression to the old direct-./derivative-maker call, and ensure
## uploads stay simulated (a test/gate builder must never publish to the release server).
## Comment lines are stripped first: the header legitimately mentions ./derivative-maker
## and rsync_cmd in prose, which must not satisfy or trip these code-level checks.
## Fixed-string match: regex '.' would match the '/' in the legitimate
## "${HOME}/derivative-maker" checkout-path default, a false positive.
code_only="$(grep -vE '^[[:space:]]*##' -- "${dm_iso_build}")"
if grep --quiet --fixed-strings -- './derivative-maker' <<< "${code_only}"; then
   fail 'dm-iso-build invokes ./derivative-maker directly again -- it must drive help-steps/dm-build-official-one so the repo is enabled'
fi
if ! grep --quiet -- 'dm-build-official-one' <<< "${code_only}"; then
   fail 'dm-iso-build no longer drives dm-build-official-one'
fi
if ! grep --quiet --extended-regexp -- 'rsync_cmd=.*simulate' <<< "${code_only}"; then
   fail 'dm-iso-build no longer forces uploads to simulate (rsync_cmd) -- a test/gate builder must never upload to the release server'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "dm-iso-build-repo-enabled-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'dm-iso-build-repo-enabled-test: all checks passed'
