#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard: dm-gitlink-bump pins a submodule gitlink ONLY to a tip
## published on the CI-fetched org (org-ai-assisted) -- never to a tip that
## lives only on a bot MIRROR (assisted-by-ai, gitlab-adrelanos) or upstream.
## A mirror-only pin is unfetchable by a fresh CI/build 'git fetch
## --recurse-submodules' ('upload-pack: not our ref'), the same SHAs every
## retry, invisible to the author whose own checkout HAS the objects.
##
## Canary: the old filter accepted ANY network remote (*://* | *@*:*), so a
## mirror tip got pinned -> case A would BUMP and this test FAIL on old code.
## The org case (B) and the insteadOf-rewrite case (C) keep it non-vacuous: a
## filter broken to reject everything fails B/C; reading the raw url instead of
## the rewrite-applied one (get-url vs ls-remote --get-url) fails C.
##
## Drives the REAL dm-gitlink-bump against throwaway superprojects + submodules
## with the remote-tracking tip set directly. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Resolve dm-gitlink-bump under test (runner exports DM_GITLINK_BUMP).
locate_bin() {
   local candidate
   for candidate in \
      "${DM_GITLINK_BUMP:-}" \
      "$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../../bin/dm-gitlink-bump" \
      /usr/bin/dm-gitlink-bump
   do
      [ -n "${candidate}" ] || continue
      if test -x "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! bin="$(locate_bin)"; then
   printf '%s\n' 'FATAL: dm-gitlink-bump not found (set DM_GITLINK_BUMP).' >&2
   exit 1
fi

## Not testing a possibly-stale install when nothing was wired.
if [ -z "${DM_GITLINK_BUMP:-}" ] && [ "${bin}" = "/usr/bin/dm-gitlink-bump" ]; then
   printf '%s\n' "SKIP: no dm-gitlink-bump checkout wired (set DM_GITLINK_BUMP); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT

## Hermetic: ignore host global/system config (insteadOf, hooksPath, identity).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

git_fx() { git -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"; }
set_identity() { git -C "$1" config user.email fx@example.invalid && git -C "$1" config user.name fx; }

## Build a published-ahead fixture: submodule 'ai' with HEAD (c1) one commit
## ahead of the pin (c0), clean; the given remote's tracking 'ai' ref set to c1
## so the tool treats c1 as a published tip (reads the tracking ref, no fetch).
## Optional 4th arg: an "insteadOf-prefix=base" local rewrite on the submodule.
## Emits "${c0} ${c1}" so the caller can assert the resulting pin.
make_fixture() {
   local dir="$1" remote="$2" url="$3" rewrite="${4:-}"
   local super="${dir}/super" sub
   sub="${super}/sub"
   mkdir -p -- "${sub}"
   git_fx -C "${sub}" init -q -b ai
   set_identity "${sub}"
   git_fx -C "${sub}" commit -q --allow-empty -m c0
   local c0 c1
   c0="$(git -C "${sub}" rev-parse HEAD)"
   git_fx -C "${sub}" commit -q --allow-empty -m c1
   c1="$(git -C "${sub}" rev-parse HEAD)"
   if [ -n "${rewrite}" ]; then
      git_fx -C "${sub}" config "url.${rewrite#*=}.insteadOf" "${rewrite%%=*}"
   fi
   git_fx -C "${sub}" remote add "${remote}" "${url}"
   git_fx -C "${sub}" update-ref "refs/remotes/${remote}/ai" "${c1}"

   mkdir -p -- "${super}/build-steps.d" "${super}/help-steps"
   git_fx -C "${super}" init -q -b ai
   set_identity "${super}"
   cat > "${super}/.gitmodules" <<EOF
[submodule "sub"]
	path = sub
	url = ${url}
EOF
   git_fx -C "${super}" add .gitmodules
   git_fx -C "${super}" update-index --add --cacheinfo "160000,${c0},sub"
   git_fx -C "${super}" commit -q -m init
   printf '%s\n' "${c0} ${c1}"
}

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }
count() { tests_total=$(( tests_total + 1 )); }

## Run the bump, print resulting pin (unchanged == refused).
run_bump() {
   local super="$1"
   "${bin}" --dir "${super}" >/dev/null 2>&1 || true
   git -C "${super}" rev-parse --verify --quiet 'HEAD:sub' || true
}

## CASE A: mirror-only tips (ssh github mirror AND gitlab mirror) -> REFUSED.
while read -r name url; do
   [ -n "${name}" ] || continue
   d="${test_root}/mirror-${name}"
   read -r a_c0 _ < <(make_fixture "${d}" "${name}" "${url}")
   pin="$(run_bump "${d}/super")"
   count
   if [ "${pin}" = "${a_c0}" ]; then
      pass "A mirror-only tip refused (${name}): pin stays ${a_c0:0:12}"
   else
      fail "A mirror-only tip PINNED (${name}): pin=${pin:0:12} (want unchanged ${a_c0:0:12})"
   fi
done <<'EOF'
assisted-by-ai git@github.com:assisted-by-ai/sub.git
gitlab-adrelanos git@gitlab.com:someuser/sub.git
EOF

## CASE B: the CI-fetched org tip -> ACCEPTED (bumps c0 -> c1).
read -r b_c0 b_c1 < <(make_fixture "${test_root}/org" org-ai-assisted "git@github.com:org-ai-assisted/sub.git")
pin="$(run_bump "${test_root}/org/super")"
count
if [ "${pin}" = "${b_c1}" ]; then
   pass "B org tip accepted: pin ${b_c0:0:12} -> ${b_c1:0:12}"
else
   fail "B org tip NOT pinned: pin=${pin:0:12} (want ${b_c1:0:12})"
fi

## CASE C: a Kicksecure remote whose url insteadOf-rewrites to the org -> ACCEPTED.
## Guards the ls-remote --get-url (rewrite-applied) choice; raw get-url sees
## Kicksecure and would wrongly refuse.
read -r c_c0 c_c1 < <(make_fixture "${test_root}/rewrite" github-kicksecure \
   "git@github.com:Kicksecure/sub.git" \
   "git@github.com:Kicksecure/=git@github.com:org-ai-assisted/")
pin="$(run_bump "${test_root}/rewrite/super")"
count
if [ "${pin}" = "${c_c1}" ]; then
   pass "C insteadOf-rewritten Kicksecure tip accepted: pin ${c_c0:0:12} -> ${c_c1:0:12}"
else
   fail "C rewritten tip NOT pinned: pin=${pin:0:12} (want ${c_c1:0:12}); ls-remote --get-url regressed to get-url?"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "published_org_only_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "published_org_only_test: ${tests_total} pass, 0 fail, 0 skip"
