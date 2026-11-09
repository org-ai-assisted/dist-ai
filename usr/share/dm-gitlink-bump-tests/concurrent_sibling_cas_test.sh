#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard: dm-gitlink-bump must sample its compare-and-swap anchor (old_tip) BEFORE
## the validation loop, so a concurrent SIBLING commit that lands DURING validation is caught by
## the final update-ref CAS -- not missed, which would let the bump REGRESS a gitlink the sibling
## just advanced.
##
## Deterministic fixture: superproject pins sub@c0; sub HEAD is c1 (the published org tip), so
## the tool decides to bump the gitlink c0 -> c1. A 'git' PATH-shim injects a sibling commit that
## advances the SAME gitlink to c2 (a newer sub commit) exactly at the tool's first
## 'git -C <top> symbolic-ref HEAD' -- AFTER the pin is read: the window a post-validation
## old_tip sample fails to cover. Assert the final pin is c2 (the tool's CAS aborts), never c1.
##
## Canary: an old_tip sampled after validation matches the sibling-moved tip and the CAS
## SUCCEEDS, overwriting the gitlink with the stale validated c1 -> the pin REGRESSES to c1, so
## this test stays RED until old_tip is sampled before validation. Drives the REAL
## dm-gitlink-bump. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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
if [ -z "${DM_GITLINK_BUMP:-}" ] && [ "${bin}" = "/usr/bin/dm-gitlink-bump" ]; then
   printf '%s\n' "SKIP: no dm-gitlink-bump checkout wired (set DM_GITLINK_BUMP); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

real_git="$(type -P git)"

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git_fx() { git -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"; }
set_identity() { git -C "$1" config user.email fx@example.invalid && git -C "$1" config user.name fx; }

super="${test_root}/super"
sub="${super}/sub"
url='git@github.com:org-ai-assisted/sub.git'

## Submodule: c0, c1, c2 linear; HEAD reset to c1 (c2 stays as an object the sibling will pin).
mkdir -p -- "${sub}"
git_fx -C "${sub}" init -q -b ai
set_identity "${sub}"
printf '%s\n' v0 > "${sub}/data.txt"; git_fx -C "${sub}" add data.txt; git_fx -C "${sub}" commit -q -m c0
c0="$(git -C "${sub}" rev-parse HEAD)"
printf '%s\n' v1 > "${sub}/data.txt"; git_fx -C "${sub}" commit -q -m c1 -- data.txt
c1="$(git -C "${sub}" rev-parse HEAD)"
printf '%s\n' v2 > "${sub}/data.txt"; git_fx -C "${sub}" commit -q -m c2 -- data.txt
c2="$(git -C "${sub}" rev-parse HEAD)"
git_fx -C "${sub}" reset --hard -q "${c1}"
git_fx -C "${sub}" tag c2keep "${c2}"  ## keep c2 referenced
git_fx -C "${sub}" remote add org-ai-assisted "${url}"
git_fx -C "${sub}" update-ref 'refs/remotes/org-ai-assisted/ai' "${c1}"  ## published tip = sub HEAD

## Superproject on ai pinning c0.
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

## git PATH-shim: on the tool's FIRST 'git -C <super> symbolic-ref ...' (after it has read the
## pin, before the OLD old_tip sample), land a sibling commit advancing the gitlink to c2, then
## delegate to the real git. One-shot (sentinel). Uses the real git only, so no recursion.
shimdir="${test_root}/shim"
mkdir -p -- "${shimdir}"
cat > "${shimdir}/git" <<SHIM
#!/bin/bash
if [ ! -e "\${INJECT_SENTINEL}" ] && [ "\$1" = "-C" ] && [ "\$2" = "\${INJECT_TOP}" ] && [ "\$3" = "symbolic-ref" ]; then
   : > "\${INJECT_SENTINEL}"
   sib_idx="\$(mktemp)"
   GIT_INDEX_FILE="\${sib_idx}" "\${INJECT_REAL_GIT}" -C "\${INJECT_TOP}" read-tree HEAD
   GIT_INDEX_FILE="\${sib_idx}" "\${INJECT_REAL_GIT}" -C "\${INJECT_TOP}" update-index --add --cacheinfo "160000,\${INJECT_C2},sub"
   sib_tree="\$(GIT_INDEX_FILE="\${sib_idx}" "\${INJECT_REAL_GIT}" -C "\${INJECT_TOP}" write-tree)"
   sib_commit="\$("\${INJECT_REAL_GIT}" -C "\${INJECT_TOP}" commit-tree "\${sib_tree}" -p HEAD -m sibling-bump)"
   "\${INJECT_REAL_GIT}" -C "\${INJECT_TOP}" update-ref refs/heads/ai "\${sib_commit}" "\$("\${INJECT_REAL_GIT}" -C "\${INJECT_TOP}" rev-parse HEAD)"
   rm -f "\${sib_idx}"
fi
exec "\${INJECT_REAL_GIT}" "\$@"
SHIM
chmod +x -- "${shimdir}/git"

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }
count() { tests_total=$(( tests_total + 1 )); }

## Run the bump with the sibling injected mid-validation.
INJECT_TOP="${super}" \
   INJECT_C2="${c2}" \
   INJECT_REAL_GIT="${real_git}" \
   INJECT_SENTINEL="${test_root}/injected" \
   PATH="${shimdir}:${PATH}" \
   "${bin}" --dir "${super}" >/dev/null 2>&1 || true

## Sanity: the sibling injection actually fired (else the test is vacuous).
count
if [ -e "${test_root}/injected" ]; then
   pass "fixture: concurrent sibling commit was injected mid-run"
else
   fail "fixture: sibling injection never fired (test vacuous)"
fi

## The gitlink must NOT have regressed: the sibling advanced it to c2; the tool's stale c1 must
## be rejected by the CAS.
pin="$(git -C "${super}" rev-parse --verify --quiet 'HEAD:sub' || true)"
count
if [ "${pin}" = "${c2}" ]; then
   pass "no regression: pin stayed at the sibling's ${c2:0:12} (CAS covered the window)"
else
   fail "regression: pin=${pin:0:12}, want sibling ${c2:0:12} (stale c1=${c1:0:12} overwrote it)"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "concurrent_sibling_cas_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "concurrent_sibling_cas_test: ${tests_total} pass, 0 fail, 0 skip"
