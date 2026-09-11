#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-ci-dispatch resolves the LOCAL sha of the ref it is about to dispatch and
## refuses to dispatch when it differs from the remote ("Push first"). That
## reader must emit the sha and NOTHING else.
##
## THE BUG THIS GUARDS: the reader was `git rev-parse --end-of-options <ref>`
## with no --verify. `git rev-parse` treats an unconsumed `--end-of-options` as a
## passthrough token and ECHOES it back as its own output line ahead of the sha,
## so local_sha became two lines ("--end-of-options\n<sha>") and could never
## equal the single-line remote sha -- every dispatch was blocked with a spurious
## "local X, remote Y -- Push first" even when local and remote matched. --verify
## makes rev-parse emit only the single resolved object.
##
## Two directions, so neither a dropped --verify nor a git that stopped echoing
## can pass silently: the SHIPPED command form must carry --verify, and on this
## git the un-verified form must actually produce the extra line the fix removes.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

## Same discovery order as the sibling preflight tests: an explicit override,
## then the checkout, then the installed copy.
subject=""
for candidate in "${DM_CI_DISPATCH:-}" \
   "${test_dir}/../../bin/dm-ci-dispatch" \
   "/usr/bin/dm-ci-dispatch"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-ci-dispatch not found (set DM_CI_DISPATCH)." >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## --- the SHIPPED local-sha reader must carry --verify -----------------------
## Drift guard: run against the real script text, not a restated command. A
## future edit that drops --verify reintroduces the two-line echo and fails here.
local_sha_line="$( grep -E 'local_sha=.*rev-parse' -- "${subject}" || true )"
if [ -z "${local_sha_line}" ]; then
   fail "could not find the local_sha rev-parse line in ${subject}; the reader moved -- update this test"
elif [[ "${local_sha_line}" =~ rev-parse[[:space:]]+--verify[[:space:]]+--end-of-options ]]; then
   pass 'the shipped local_sha reader uses rev-parse --verify --end-of-options'
else
   fail "the shipped local_sha reader lacks --verify (the --end-of-options echo bug is back):
${local_sha_line}"
fi

## --- on THIS git the flag actually matters ----------------------------------
## Canary: prove the fixture reproduces the echo, so the guard above is not
## passing on a git that would never have echoed in the first place. A fixture
## repo with a single commit on branch 'ai'.
workdir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
git -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   init --quiet -- "${workdir}"
printf '%s\n' "content" > "${workdir}/file"
git -C "${workdir}" -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   add file
git -C "${workdir}" -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   commit --quiet --message one
git -C "${workdir}" -c core.hooksPath=/dev/null branch --move ai

verified_lines="$( git -C "${workdir}" rev-parse --verify --end-of-options ai | wc -l )"
unverified_lines="$( git -C "${workdir}" rev-parse --end-of-options ai | wc -l )"
if [ "${verified_lines}" = "1" ] && [ "${unverified_lines}" -gt "1" ]; then
   pass "on this git --verify yields one line while the un-verified form yields ${unverified_lines} -- the flag is load-bearing"
elif [ "${verified_lines}" != "1" ]; then
   fail "rev-parse --verify --end-of-options emitted ${verified_lines} lines, expected 1"
else
   fail "the un-verified form emitted a single line on this git, so this fixture no longer reproduces the bug -- the source guard above would pass vacuously; strengthen the fixture"
fi

summary_line="===== dm-ci-dispatch local sha: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
