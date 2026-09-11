#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for dm-gitlink-bump (usr/bin/dm-gitlink-bump).
##
## THE BUG IT GUARDS: a submodule advanced + pushed on 'ai' but whose parent
## gitlink was never bumped -- CI checks out the stale pin. dm-gitlink-bump is
## the tool that pins the published submodule HEAD in one parent commit; its
## --check mode is what the pre-push hook uses to REJECT such a push.
##
## Drives the REAL tool against throwaway git repos (a bare "fork", a
## superproject shaped like a derivative-maker checkout, and its submodule). No
## network: "published" is modelled by pushing to the local bare fork, which
## sets the submodule's remote-tracking ai tip.
##
## Setup commits gitlink pointers, which the global gitlink pre-commit guard
## would refuse -- so setup git ops run with hooks OFF (they are fixtures, not
## the code under test). The dm-gitlink-bump invocation itself runs with hooks
## as-is, so its own guard overrides are exercised.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

## Resolve the tool from the dist-ai checkout under test (never an installed copy).
dist_ai_bin="$(cd -- "${test_dir}/../../bin" && pwd)"
tool="${dist_ai_bin}/dm-gitlink-bump"
if [ ! -x "${tool}" ]; then
   printf '%s\n' "FATAL: dm-gitlink-bump not found/executable at '${tool}'." >&2
   exit 1
fi

## Deterministic identity + no interactive prompts for the throwaway commits.
export GIT_AUTHOR_NAME="test" GIT_AUTHOR_EMAIL="test@example.invalid"
export GIT_COMMITTER_NAME="test" GIT_COMMITTER_EMAIL="test@example.invalid"

workspace="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workspace}"; }
trap cleanup EXIT

## Setup git ops must not fight the global gitlink/branch guards: fixtures, not
## the tested behaviour. An empty hooks dir disables custom hooks for THESE
## invocations only (the tool's own commit below runs without this override).
gitq() { git -c core.hooksPath="${workspace}/nohooks" -c protocol.file.allow=always "$@"; }
mkdir --parents -- "${workspace}/nohooks"

## A bare repo standing in for the org fork, and a superproject shaped like a
## derivative-maker checkout (build-steps.d + help-steps) with one submodule.
fork="${workspace}/fork.git"
sub_src="${workspace}/sub-src"
super="${workspace}/super"

gitq init --quiet --bare -- "${fork}"

## Seed the submodule content and publish THREE commits to the fork's ai branch:
## PIN (v1, what the superproject pins), MID (v2, published intermediate), and
## TIP (v3, the published head). TIP is the published-but-unpinned HEAD the tool
## advances to; MID exists so a below-tip published HEAD can be tested (it must
## NOT be pinned -- only the tip is).
gitq init --quiet -- "${sub_src}"
gitq -C "${sub_src}" checkout --quiet -b ai
printf 'v1\n' > "${sub_src}/file"
gitq -C "${sub_src}" add file
gitq -C "${sub_src}" commit --quiet -m "sub v1"
sub_pin="$(gitq -C "${sub_src}" rev-parse HEAD)"
printf 'v2\n' > "${sub_src}/file"
gitq -C "${sub_src}" add file
gitq -C "${sub_src}" commit --quiet -m "sub v2"
sub_mid="$(gitq -C "${sub_src}" rev-parse HEAD)"
printf 'v3\n' > "${sub_src}/file"
gitq -C "${sub_src}" add file
gitq -C "${sub_src}" commit --quiet -m "sub v3"
sub_tip="$(gitq -C "${sub_src}" rev-parse HEAD)"
## file:// (a URL scheme), not a bare path: dm-gitlink-bump only trusts a
## remote-tracking 'ai' tip from a NETWORK remote (scheme or user@host:), the
## same *://*|*@*:* classification dm-preflight uses. A bare-path scratch remote
## is deliberately NOT accepted as published.
gitq -C "${sub_src}" remote add fork "file://${fork}"
gitq -C "${sub_src}" push --quiet fork ai

## Superproject on 'ai', with the submodule pinned at PIN (the stale pointer).
gitq init --quiet -- "${super}"
gitq -C "${super}" checkout --quiet -b ai
mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
printf 'x\n' > "${super}/build-steps.d/keep"
printf 'x\n' > "${super}/help-steps/keep"
gitq -C "${super}" add build-steps.d help-steps
gitq -C "${super}" commit --quiet -m "super base"
gitq -C "${super}" -c protocol.file.allow=always submodule --quiet add -b ai "file://${fork}" sub
## Force the recorded gitlink to PIN (submodule add records the tip; we want stale).
gitq -C "${super}/sub" checkout --quiet "${sub_pin}"
gitq -C "${super}" update-index --cacheinfo "160000,${sub_pin},sub"
gitq -C "${super}" commit --quiet -m "pin sub at v1" -- sub
## Put the submodule working tree on 'ai' at the published TIP, mirroring "I
## committed + pushed the submodule, forgot to bump the parent". The submodule's
## remote (created by 'submodule add') is 'origin' -> the bare fork; its
## remote-tracking origin/ai tip is what the tool treats as published (no
## network: local bare fork).
gitq -C "${super}/sub" fetch --quiet origin ai
gitq -C "${super}/sub" checkout --quiet ai
gitq -C "${super}/sub" reset --quiet --hard "${sub_tip}"
gitq -C "${super}/sub" branch --quiet --set-upstream-to=origin/ai ai 2>/dev/null || true

pin_now() { git -C "${super}" rev-parse "HEAD:sub"; }

## --- Assertion 1: --check flags the stale pin (exit 3) --------------------------
if "${tool}" --check --dir "${super}" >/dev/null 2>&1; then
   fail "--check should exit 3 while a published-ahead submodule is unpinned"
else
   rc=$?
   if [ "${rc}" -eq 3 ]; then
      pass "--check exits 3 on a published-ahead unpinned submodule"
   else
      fail "--check exited ${rc}, expected 3"
   fi
fi

## --- Assertion 2: the bump pins the published TIP in ONE commit -----------------
head_before="$(git -C "${super}" rev-parse HEAD)"
if "${tool}" --dir "${super}" >/dev/null 2>&1; then
   pass "dm-gitlink-bump ran"
else
   fail "dm-gitlink-bump exited non-zero: $?"
fi
if [ "$(pin_now)" = "${sub_tip}" ]; then
   pass "gitlink advanced to the published tip"
else
   fail "gitlink is '$(pin_now)', expected TIP '${sub_tip}'"
fi
commits_added="$(git -C "${super}" rev-list --count "${head_before}"..HEAD)"
if [ "${commits_added}" = "1" ]; then
   pass "exactly one bump commit created"
else
   fail "expected 1 bump commit, got ${commits_added}"
fi

## --- Assertion 3: --check is clean afterwards (self-canary) ---------------------
if "${tool}" --check --dir "${super}" >/dev/null 2>&1; then
   pass "--check exits 0 once the pin is current (proves 1 could tell the states apart)"
else
   fail "--check should exit 0 after the bump, exited $?"
fi

## --- Assertion 4: a below-tip published HEAD is NOT bumped ----------------------
## Re-pin at v1, then point local ai at MID (v2): HEAD is a published commit,
## strictly ahead of the pin, but NOT the published tip (v3). Must be left alone.
gitq -C "${super}/sub" reset --quiet --hard "${sub_pin}"
gitq -C "${super}" commit --quiet -m "re-pin sub at v1" -- sub
gitq -C "${super}/sub" reset --quiet --hard "${sub_mid}"
if "${tool}" --check --dir "${super}" >/dev/null 2>&1; then
   pass "--check exits 0 when HEAD is a below-tip published commit (no intermediate pin)"
else
   fail "--check should NOT flag a below-tip HEAD ahead of the pin (exited $?)"
fi
if [ "$(pin_now)" = "${sub_pin}" ]; then
   pass "pin left at v1 (a below-tip HEAD is not pinned)"
else
   fail "pin unexpectedly changed to '$(pin_now)'"
fi

## --- Assertion 5: a bare-PATH remote tip is NOT "published" (CI can't fetch) --
## HEAD at the published TIP and ahead of the pin, but the only remote carrying
## that ai tip is a bare filesystem path -- a fresh CI checkout using the URL
## could never fetch it, so it must not be pinned.
gitq -C "${super}/sub" checkout --quiet ai
gitq -C "${super}/sub" reset --quiet --hard "${sub_tip}"
gitq -C "${super}/sub" remote set-url origin "${fork}"   ## bare path, not file://
if "${tool}" --check --dir "${super}" >/dev/null 2>&1; then
   pass "--check exits 0 when the ai tip is only on a bare-path remote (not CI-fetchable)"
else
   fail "a bare-path remote tip must not count as published (--check exited $?)"
fi
gitq -C "${super}/sub" remote set-url origin "file://${fork}"   ## restore network remote

## --- Assertion 6: a DETACHED submodule HEAD is never bumped ---------------------
gitq -C "${super}/sub" checkout --quiet ai
gitq -C "${super}/sub" reset --quiet --hard "${sub_tip}"
gitq -C "${super}/sub" checkout --quiet --detach "${sub_tip}"
if "${tool}" --check --dir "${super}" >/dev/null 2>&1; then
   pass "--check exits 0 when the submodule HEAD is detached (not on 'ai')"
else
   fail "a detached submodule HEAD must not be bumped (--check exited $?)"
fi

## --- Assertion 7: not a derivative-maker checkout -> check no-ops, bump errors --
plain="${workspace}/plain"
gitq init --quiet -- "${plain}"
if "${tool}" --check --dir "${plain}" >/dev/null 2>&1; then
   pass "--check is a clean no-op (exit 0) outside a derivative-maker checkout"
else
   fail "--check should exit 0 on a non-dm checkout, exited $?"
fi
if "${tool}" --dir "${plain}" >/dev/null 2>&1; then
   fail "bump mode should exit 2 on a non-dm checkout"
else
   rc=$?
   if [ "${rc}" -eq 2 ]; then
      pass "bump mode exits 2 (usage) on a non-dm checkout"
   else
      fail "bump mode exited ${rc}, expected 2"
   fi
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-gitlink-bump bumps published tips, skips stale/detached/below-tip."
