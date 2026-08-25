#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-preflight's submodule-pin reachability check must answer the question a
## FRESH `git clone --recurse-submodules` asks -- and must not cry wolf.
##
## THE BUG THIS GUARDS: the check was `git ls-remote <url> | grep <sha>`.
## ls-remote advertises ref TIPS only, so every pin that is not a branch head
## read as unreachable. That is most pins the moment upstream commits again. It
## produced a confident FORK-ONLY verdict for two pins that were in fact
## perfectly reachable from upstream, and that verdict was reported to a code
## reviewer as fact.
##
## A false positive here is worse than no check at all: it fires on healthy
## pins, so the check becomes noise, and a genuinely fork-only pin hides inside
## that noise. Hence this file pins BOTH directions -- silent on a reachable
## non-tip pin, loud on a truly fork-only one.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

## Same discovery order as the sibling preflight_test.sh: an explicit override,
## then the checkout, then the installed copy.
subject=""
for candidate in "${DM_PREFLIGHT:-}" \
   "${test_dir}/../../bin/dm-preflight" \
   "/usr/bin/dm-preflight"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-preflight not found (set DM_PREFLIGHT)." >&2
   exit 1
fi

## dm-preflight fails a tree whose static gate it cannot run, so these cases need
## dist-ai-style reachable -- present in the checkout but not on PATH in CI.
gate_bin_dir="$( cd -- "${test_dir}/../../bin" 2>/dev/null && pwd || true )"
if [ -n "${gate_bin_dir}" ] && [ -x "${gate_bin_dir}/dist-ai-style" ]; then
   PATH="${gate_bin_dir}:${PATH}"
   export PATH
fi
if ! type -P dist-ai-style >/dev/null; then
   printf '%s\n' "FATAL: dist-ai-style not reachable; dm-preflight cannot complete a run." >&2
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

workdir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## `git submodule foreach` sets GIT_PROTOCOL_FROM_USER=0, so git treats every
## file:// url inside it as non-user-initiated and refuses it (protocol.file.allow
## defaults to "user"). That would make every probe below fail for a reason that
## has nothing to do with reachability. Real remotes are https, so this is a
## fixture artifact only -- but without it the cases silently prove nothing.
GIT_ALLOW_PROTOCOL='file'
export GIT_ALLOW_PROTOCOL

## Local git needs telling to answer sha requests; GitHub already does. Without
## this the fixture cannot represent a GitHub-like server at all.
git_quiet() {
   git -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com "$@"
}

make_upstream() {
   local repo="$1" allow_sha="$2"
   git_quiet init --quiet -- "${repo}"
   ## Each fixture repo must produce DISTINCT commit shas. Identical content and
   ## messages across two repos yield identical shas, which silently made the
   ## "unreachable" fixture reachable after all -- the case then proved nothing.
   printf '%s\n' "identity ${repo##*/}" > "${repo}/identity"
   git_quiet -C "${repo}" add identity
   git_quiet -C "${repo}" commit --quiet --message "identity ${repo##*/}"
   printf '%s\n' "one" > "${repo}/file"
   git_quiet -C "${repo}" add file
   git_quiet -C "${repo}" commit --quiet --message one
   ## The commit under test, then ANOTHER on top, so the pin is an ANCESTOR and
   ## not a tip. That gap is the whole bug.
   printf '%s\n' "two" > "${repo}/file"
   git_quiet -C "${repo}" add file
   git_quiet -C "${repo}" commit --quiet --message two
   git_quiet -C "${repo}" rev-parse HEAD > "${repo}/.ancestor-sha"
   printf '%s\n' "three" > "${repo}/file"
   git_quiet -C "${repo}" add file
   git_quiet -C "${repo}" commit --quiet --message three
   git_quiet -C "${repo}" config uploadpack.allowReachableSHA1InWant "${allow_sha}"
   git_quiet -C "${repo}" config uploadpack.allowAnySHA1InWant false
}

## Exercise the SHIPPED probe sequence rather than a restatement of it: extract
## nothing, run the real script against a real fixture. A private copy of the
## logic would keep passing after the real one regressed.
run_preflight() {
   local super="$1"
   "${subject}" --dir "${super}" --quick 2>&1 || true
}

build_super() {
   local super="$1" upstream="$2" pin="$3"
   git_quiet init --quiet -- "${super}"
   git_quiet -C "${super}" remote add origin "https://example.com/super.git"
   ## dm-preflight refuses anything that is not a derivative-maker checkout, and
   ## that refusal exits before the pin probe ever runs -- which silently made
   ## every case here vacuous until the marker dirs were present.
   mkdir --parents -- "${super}/build-steps.d" "${super}/help-steps"
   printf '%s\n' "placeholder" > "${super}/build-steps.d/.keep"
   printf '%s\n' "placeholder" > "${super}/help-steps/.keep"
   printf '%s\n' "top" > "${super}/top"
   git_quiet -C "${super}" add top build-steps.d help-steps
   git_quiet -C "${super}" commit --quiet --message top
   git_quiet -C "${super}" -c protocol.file.allow=always \
      submodule --quiet add -- "file://${upstream}" sub >/dev/null 2>&1
   git_quiet -C "${super}" -c protocol.file.allow=always \
      -C "${super}/sub" checkout --quiet "${pin}" 2>/dev/null || \
      git_quiet -C "${super}/sub" checkout --quiet "${pin}"
   git_quiet -C "${super}" add sub
   git_quiet -C "${super}" commit --quiet --message pin
}

## --- a REACHABLE non-tip pin must NOT be reported ---------------------------
## This is the canary. The old ls-remote|grep check fails here: the pin is a
## real ancestor on the configured url, but it is not a ref tip.
upstream="${workdir}/upstream"
make_upstream "${upstream}" true
ancestor_sha="$( cat "${upstream}/.ancestor-sha" )"
super="${workdir}/super"
build_super "${super}" "${upstream}" "${ancestor_sha}"

output="$( run_preflight "${super}" )"
## Absence of FORK-ONLY is NOT enough: a probe that failed outright is also
## silent, so this must confirm the pin was POSITIVELY verified. UNVERIFIED here
## means the probe never reached a conclusion, which would make the case vacuous.
if grep --quiet 'FORK-ONLY' <<< "${output}"; then
   fail "a pin that IS reachable from the configured url was reported FORK-ONLY -- the tip-only false positive is back:
$( printf '%s\n' "${output}" | grep 'FORK-ONLY' )"
elif grep --quiet 'UNVERIFIED' <<< "${output}"; then
   fail "the probe reached no conclusion for a reachable pin, so this case proves nothing:
$( printf '%s\n' "${output}" | grep 'UNVERIFIED' )"
else
   pass 'a reachable non-tip pin is positively verified, not reported as fork-only'
fi

## --- a genuinely unreachable pin MUST still be caught -----------------------
## Guards the opposite failure: a check relaxed until it reports nothing.
fork_upstream="${workdir}/fork-upstream"
make_upstream "${fork_upstream}" true
orphan_sha="$( cat "${fork_upstream}/.ancestor-sha" )"
lonely="${workdir}/lonely"
make_upstream "${lonely}" true

super_bad="${workdir}/super-bad"
build_super "${super_bad}" "${fork_upstream}" "${orphan_sha}"
## Repoint .gitmodules at a DIFFERENT repo, which has never seen this commit --
## exactly the fork-only shape: the object exists where it was fetched from, and
## nowhere the configured url can reach.
git_quiet -C "${super_bad}" config -f .gitmodules submodule.sub.url "file://${lonely}"
git_quiet -C "${super_bad}" add .gitmodules
git_quiet -C "${super_bad}" commit --quiet --message repoint

output_bad="$( run_preflight "${super_bad}" )"
if grep --quiet 'FORK-ONLY' <<< "${output_bad}"; then
   pass 'a pin absent from the configured url is still reported FORK-ONLY'
else
   fail "a genuinely unreachable pin was NOT reported; the check has been relaxed into uselessness:
${output_bad}"
fi

## --- an UNREACHABLE SERVER is UNVERIFIED, never FORK-ONLY -------------------
## The offline case. If a transport failure could produce a fork-only verdict,
## every pin would be flagged the moment the network is down or a host is
## temporarily unreachable -- the same cry-wolf failure in a new costume.
##
## NOT COVERED HERE: the third probe step, where a host advertises refs but
## refuses fetch-by-sha (uploadpack.allowReachableSHA1InWant off). It cannot be
## simulated with a local fixture -- git does not enforce that restriction over
## the file transport, and the alternatives (unreadable objects, a failing
## pack-objects hook) break ls-remote too, which lands in the branch below
## instead. That step is reasoned, not test-covered; said plainly rather than
## papered over with a case that would pass without exercising it.
unreachable="${workdir}/super-unreachable"
build_super "${unreachable}" "${upstream}" "${ancestor_sha}"
git_quiet -C "${unreachable}" config -f .gitmodules submodule.sub.url "file://${workdir}/does-not-exist"
git_quiet -C "${unreachable}" add .gitmodules
git_quiet -C "${unreachable}" commit --quiet --message repoint-nowhere

output_unreachable="$( run_preflight "${unreachable}" )"
if grep --quiet 'FORK-ONLY' <<< "${output_unreachable}"; then
   fail "an unreachable server produced a FORK-ONLY verdict; an outage would flag every pin:
$( printf '%s\n' "${output_unreachable}" | grep 'FORK-ONLY' )"
elif grep --quiet 'not contactable' <<< "${output_unreachable}"; then
   pass 'an unreachable server is reported UNVERIFIED, naming the reason'
else
   fail "expected an UNVERIFIED 'not contactable' verdict; got neither that nor FORK-ONLY:
${output_unreachable}"
fi

## --- the probe must not mutate the repo under inspection -------------------
## A --depth=1 fetch into a full clone writes a .git/shallow graft. An
## inspection tool that corrupts its subject is not an inspection tool.
if [ -e "${super}/sub/.git/shallow" ] || [ -e "${super}/.git/modules/sub/shallow" ]; then
   fail 'the pin probe made the inspected submodule SHALLOW'
else
   pass 'the inspected submodule was not made shallow by the probe'
fi

summary_line="===== dm-preflight pin reachability: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
