#!/bin/bash
## flavor / stages are the subject globals this test SETS to drive the sourced functions; they are
## READ only inside those functions (cross-file). branch / repo_url are sourced subject constants.
## shellcheck sees neither assigned here (file-wide).
# shellcheck disable=SC2034,SC2154

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-qubes-template-build's pure logic:
##   - flavor_to_config maps each supported flavor to its qubes-builderv2 example-config:
##       kicksecure-18         -> example-configs/kicksecure.yml
##       whonix-gateway-18     -> example-configs/qubes-os-r4.3.yml
##       whonix-workstation-18 -> example-configs/qubes-os-r4.3.yml
##     and returns non-zero for an unknown flavor (so main() errors instead of building nothing).
##   - write_builder_conf includes the mapped config AND overrides the executor to docker; it
##     injects use-qubes-repo for the whonix flavors (qubes-os-r4.3.yml lacks it) but NOT for
##     kicksecure (kicksecure.yml already sets it).
##   - stages_build_requested recognizes both 'build' and its 'b' alias (so report() finds the rpm).
##   - report() prints its diagnostic (not a silent errexit abort) when the artifacts dir is absent.
## Drives the REAL functions, sourced define-only (the subject's BASH_SOURCE guard skips main()).
## No docker, no network, no git, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_QUBES_TEMPLATE_BUILD:-}" \
  "${test_dir}/../../bin/dm-qubes-template-build" \
  "/usr/bin/dm-qubes-template-build"; do
  [ -n "${candidate}" ] || continue
  if [ -x "${candidate}" ]; then
    subject="$(readlink --canonicalize -- "${candidate}")"
    break
  fi
done
[ -n "${subject}" ] || {
  printf '%s\n' "FATAL: dm-qubes-template-build not found (set DM_QUBES_TEMPLATE_BUILD)." >&2
  exit 1
}

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

# shellcheck disable=SC1090
source "${subject}"

pass=0
fail=0
check() {
  if [ "$2" -eq 0 ]; then
    pass=$((pass + 1))
    printf '%s\n' "PASS: $1"
  else
    fail=$((fail + 1))
    printf '%s\n' "FAIL: $1"
  fi
}

## assert MSG CMD...: pass if CMD succeeds. assert_not: pass if CMD fails.
assert() {
  local msg="$1"
  shift
  if "$@"; then check "${msg}" 0; else check "${msg}" 1; fi
}
assert_not() {
  local msg="$1"
  shift
  if "$@"; then check "${msg}" 1; else check "${msg}" 0; fi
}

## expect_config FLAVOR EXPECTED: flavor_to_config prints EXPECTED and returns 0.
expect_config() {
  local flavor_in="$1" expected="$2" got rc=0
  got="$(flavor_to_config "${flavor_in}")" || rc=$?
  if [ "${rc}" -eq 0 ] && [ "${got}" = "${expected}" ]; then
    check "flavor_to_config ${flavor_in} -> ${expected}" 0
  else
    printf '%s\n' "  got rc=${rc} out='${got}' want='${expected}'" >&2
    check "flavor_to_config ${flavor_in} -> ${expected}" 1
  fi
}

expect_config kicksecure-18 "example-configs/kicksecure.yml"
expect_config whonix-gateway-18 "example-configs/qubes-os-r4.3.yml"
expect_config whonix-workstation-18 "example-configs/qubes-os-r4.3.yml"

assert_not "flavor_to_config rejects unknown flavor" flavor_to_config "not-a-real-flavor"

## stages_build_requested: 'build' and the 'b' alias -> yes; fetch-only -> no.
# shellcheck disable=SC2034  ## stages is read by the sourced stages_build_requested
stages="fetch prep build"
assert "stages_build_requested matches 'build'" stages_build_requested
stages="b"
assert "stages_build_requested matches 'b' alias" stages_build_requested
stages="fetch prep"
assert_not "stages_build_requested rejects fetch-only" stages_build_requested

## write_builder_conf: kicksecure -> no use-qubes-repo; whonix -> use-qubes-repo injected. dir and
## flavor are the subject globals the function reads.
dir="${work}/co"
mkdir -p -- "${dir}"
conf="${dir}/builder.yml"

# shellcheck disable=SC2034  ## flavor is read by the sourced write_builder_conf / flavor_needs_qubes_repo
flavor="kicksecure-18"
write_builder_conf "example-configs/kicksecure.yml"
assert "kicksecure builder.yml has include:" grep --quiet --line-regexp --fixed-strings "include:" "${conf}"
assert "kicksecure builder.yml includes the mapped config" grep --quiet --fixed-strings "example-configs/kicksecure.yml" "${conf}"
assert "kicksecure builder.yml overrides executor to docker" grep --quiet --fixed-strings "type: docker" "${conf}"
assert "kicksecure builder.yml pins the builder image" grep --quiet --fixed-strings "image: \"qubes-builder-fedora:latest\"" "${conf}"
assert_not "kicksecure builder.yml omits use-qubes-repo" grep --quiet --fixed-strings "use-qubes-repo:" "${conf}"

flavor="whonix-gateway-18"
write_builder_conf "example-configs/qubes-os-r4.3.yml"
assert "whonix builder.yml includes the mapped config" grep --quiet --fixed-strings "example-configs/qubes-os-r4.3.yml" "${conf}"
assert "whonix builder.yml injects use-qubes-repo" grep --quiet --fixed-strings "use-qubes-repo:" "${conf}"
assert "whonix builder.yml overrides executor to docker" grep --quiet --fixed-strings "type: docker" "${conf}"

## report() must PRINT the diagnostic and exit 1 (not abort silently via errexit) when the rpm
## artifacts dir is absent. CANARY: without the find '|| true', the assignment trips errexit and
## report exits 1 with NO output -- report_out would be empty.
flavor="kicksecure-18"
stages="fetch prep build"
dir="${work}/absent-build"
report_rc=0
report_out="$( (report) 2>&1)" || report_rc=$?
case "${report_out}" in
*"no template rpm"*)
  diag_found=0
  ;;
*)
  diag_found=1
  ;;
esac
if [ "${report_rc}" -ne 0 ] && [ "${diag_found}" -eq 0 ]; then
  check "report() prints diagnostic on missing artifacts dir" 0
else
  printf '%s\n' "  rc=${report_rc} out='${report_out}'" >&2
  check "report() prints diagnostic on missing artifacts dir" 1
fi

## clone_or_update must REFUSE to reset --hard an existing fork checkout that has uncommitted
## TRACKED changes (the dirty check runs before any fetch, so this stays offline). CANARY:
## pre-guard code ran straight to 'reset --hard' and would discard the edit instead of refusing.
gitrepo="${work}/dirtyco"
## Neutralize the host's global/system git config so the origin check sees the literal https
## url (a dev-host url.insteadOf would otherwise rewrite 'git remote get-url' to ssh). Production
## build hosts carry no such rewrite, so this mirrors their behavior.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git -c init.defaultBranch="${branch}" init --quiet "${gitrepo}"
git -C "${gitrepo}" -c core.hooksPath=/dev/null config user.email ci@example.invalid
git -C "${gitrepo}" -c core.hooksPath=/dev/null config user.name ci
git -C "${gitrepo}" remote add origin "${repo_url}"
printf '%s\n' orig >"${gitrepo}/tracked"
git -C "${gitrepo}" -c core.hooksPath=/dev/null add tracked
git -C "${gitrepo}" -c core.hooksPath=/dev/null commit --quiet -m init
printf '%s\n' changed >>"${gitrepo}/tracked"
dir="${gitrepo}"
clone_rc=0
clone_out="$( (clone_or_update) 2>&1)" || clone_rc=$?
case "${clone_out}" in
*"uncommitted changes to tracked files"*)
  clone_diag=0
  ;;
*)
  clone_diag=1
  ;;
esac
if [ "${clone_rc}" -ne 0 ] && [ "${clone_diag}" -eq 0 ]; then
  check "clone_or_update refuses a dirty tracked checkout" 0
else
  printf '%s\n' "  rc=${clone_rc} out='${clone_out}'" >&2
  check "clone_or_update refuses a dirty tracked checkout" 1
fi

## --- --local-repo generators -----------------------------------------------

## expect_fn MSG EXPECTED FN ARGS...: FN prints EXPECTED and returns 0.
expect_fn() {
  local msg="$1" expected="$2"
  shift 2
  local got rc=0
  got="$("$@")" || rc=$?
  if [ "${rc}" -eq 0 ] && [ "${got}" = "${expected}" ]; then
    check "${msg}" 0
  else
    printf '%s\n' "  got rc=${rc} out='${got}' want='${expected}'" >&2
    check "${msg}" 1
  fi
}

expect_fn "flavor_to_component kicksecure-18" "template-kicksecure" flavor_to_component kicksecure-18
expect_fn "flavor_to_component whonix-gateway-18" "template-whonix" flavor_to_component whonix-gateway-18
expect_fn "flavor_to_component whonix-workstation-18" "template-whonix" flavor_to_component whonix-workstation-18
assert_not "flavor_to_component rejects unknown flavor" flavor_to_component "not-a-real-flavor"

expect_fn "flavor_to_fork_url kicksecure-18" \
  "https://github.com/org-ai-assisted/qubes-template-kicksecure" flavor_to_fork_url kicksecure-18
expect_fn "flavor_to_fork_url whonix-gateway-18" \
  "https://github.com/org-ai-assisted/qubes-template-whonix" flavor_to_fork_url whonix-gateway-18

## stages_without_fetch drops the fetch stage (and its 'f' alias), keeping the rest in order.
expect_stages() {
  local msg="$1" expected="$3" got
  stages="$2"
  got="$(stages_without_fetch)"
  if [ "${got}" = "${expected}" ]; then
    check "${msg}" 0
  else
    printf '%s\n' "  got='${got}' want='${expected}'" >&2
    check "${msg}" 1
  fi
}
expect_stages "stages_without_fetch drops 'fetch'" "fetch prep build" "prep build"
expect_stages "stages_without_fetch drops the 'f' alias" "f b" "b"
expect_stages "stages_without_fetch keeps a fetchless list" "prep build" "prep build"

## write_builder_conf gates the fork repoint + insecure-skip-checking on --local-repo. CANARY:
## emitting them unconditionally would make EVERY build fetch the fork and skip its verification.
dir="${work}/co-lr"
mkdir -p -- "${dir}"
conf="${dir}/builder.yml"

flavor="kicksecure-18"
local_repo=""
write_builder_conf "example-configs/kicksecure.yml"
assert_not "no --local-repo: builder.yml omits +components" \
  grep --quiet --fixed-strings "+components:" "${conf}"
assert_not "no --local-repo: builder.yml omits insecure-skip-checking" \
  grep --quiet --fixed-strings "insecure-skip-checking:" "${conf}"
assert_not "no --local-repo: builder.yml omits force-fetch" \
  grep --quiet --fixed-strings "force-fetch:" "${conf}"

local_repo=1
write_builder_conf "example-configs/kicksecure.yml"
assert "--local-repo: builder.yml repoints to the org-ai-assisted fork" \
  grep --quiet --fixed-strings "url: https://github.com/org-ai-assisted/qubes-template-kicksecure" "${conf}"
assert "--local-repo: builder.yml pins the fork branch ai" \
  grep --quiet --fixed-strings "branch: ai" "${conf}"
assert "--local-repo: builder.yml skip-checks the fork component" \
  grep --quiet --fixed-strings "insecure-skip-checking:" "${conf}"
assert "--local-repo: skip-checking names the component" \
  grep --quiet --fixed-strings -- "- template-kicksecure" "${conf}"
assert "--local-repo: builder.yml forces a fresh fetch" \
  grep --quiet --fixed-strings "force-fetch: true" "${conf}"

## build_local_repo_conf emits a Trusted local stanza for the FLAVOR's own derivative, at the
## suite the flavor requires, and fails loud when that derivative's suite is absent (so a build
## never silently falls back to the remote repo). Stub the bridge IP so no docker is needed.
local_repo_bridge_ip() { printf '%s\n' "172.17.0.1"; }
local_repo_port=9999
flavor="kicksecure-18"

local_repo_dir="${work}/aptrepo-empty"
mkdir -p -- "${local_repo_dir}"
lr_rc=0
## Subshell: build_local_repo_conf exit()s on the empty path -- contain it, do not abort the test.
(build_local_repo_conf) >/dev/null 2>&1 || lr_rc=$?
if [ "${lr_rc}" -ne 0 ]; then
  check "build_local_repo_conf fails loud on an empty local repo" 0
else
  check "build_local_repo_conf fails loud on an empty local repo" 1
fi

local_repo_dir="${work}/aptrepo"
mkdir -p -- "${local_repo_dir}/kicksecure/dists/trixie"
lr_conf="$(build_local_repo_conf)"
case "${lr_conf}" in
*'kicksecure_repository_sources="Types: deb'*'URIs: http://172.17.0.1:9999/kicksecure'*'Suites: trixie'*'Trusted: yes"'*)
  check "build_local_repo_conf emits a Trusted kicksecure stanza" 0
  ;;
*)
  printf '%s\n' "  got='${lr_conf}'" >&2
  check "build_local_repo_conf emits a Trusted kicksecure stanza" 1
  ;;
esac
case "${lr_conf}" in
*whonix_repository_sources*)
  printf '%s\n' "  unexpected whonix stanza in '${lr_conf}'" >&2
  check "build_local_repo_conf omits an absent derivative (whonix)" 1
  ;;
*)
  check "build_local_repo_conf omits an absent derivative (whonix)" 0
  ;;
esac

## F3: a kicksecure flavor whose derivative is ABSENT (only whonix published) must FAIL LOUD, not
## silently leave kicksecure to the remote testers repo. CANARY: the per-present-derivative loop
## emitted a whonix stanza and returned 0 here, so the kicksecure hook fell back to remote.
local_repo_dir="${work}/aptrepo-whonix-only"
mkdir -p -- "${local_repo_dir}/whonix/dists/trixie"
flavor="kicksecure-18"
lr_rc=0
(build_local_repo_conf) >/dev/null 2>&1 || lr_rc=$?
if [ "${lr_rc}" -ne 0 ]; then
  check "build_local_repo_conf fails loud when the flavor's derivative is absent" 0
else
  check "build_local_repo_conf fails loud when the flavor's derivative is absent" 1
fi

## F2: the suite comes from the FLAVOR (trixie), never find|head over the repo -- a repo holding
## both bookworm and trixie must not steer the trixie template at bookworm. CANARY: scanning the
## dists dir could emit Suites: bookworm.
local_repo_dir="${work}/aptrepo-multi-suite"
mkdir -p -- "${local_repo_dir}/kicksecure/dists/bookworm" "${local_repo_dir}/kicksecure/dists/trixie"
flavor="kicksecure-18"
lr_conf="$(build_local_repo_conf)"
case "${lr_conf}" in
*'Suites: trixie'*)
  check "build_local_repo_conf takes the suite from the flavor (trixie)" 0
  ;;
*)
  printf '%s\n' "  got='${lr_conf}'" >&2
  check "build_local_repo_conf takes the suite from the flavor (trixie)" 1
  ;;
esac

## A whonix flavor overrides BOTH whonix and kicksecure when both are published locally (the
## whonix template installs kicksecure packages too).
local_repo_dir="${work}/aptrepo-both"
mkdir -p -- "${local_repo_dir}/whonix/dists/trixie" "${local_repo_dir}/kicksecure/dists/trixie"
flavor="whonix-gateway-18"
lr_conf="$(build_local_repo_conf)"
case "${lr_conf}" in
*whonix_repository_sources*kicksecure_repository_sources* | *kicksecure_repository_sources*whonix_repository_sources*)
  check "build_local_repo_conf overrides both whonix and kicksecure for a whonix flavor" 0
  ;;
*)
  printf '%s\n' "  got='${lr_conf}'" >&2
  check "build_local_repo_conf overrides both whonix and kicksecure for a whonix flavor" 1
  ;;
esac

## serve_local_repo must FAIL LOUD (not return 0) when its port is already bound on the bind
## address. CANARY: the pre-fix code had no liveness/readiness check -- it captured $! of the
## already-dead python and returned 0, leaving build() to run apt against a dead repo URL. Uses
## 127.0.0.1 as the bind address so the test needs no docker.
occupy_port="$(local_repo_pick_port 127.0.0.1)"
python3 -m http.server --bind 127.0.0.1 "${occupy_port}" --directory "${work}" >/dev/null 2>&1 &
occupier_pid=$!
occupier_up=0
for ((probe_i = 0; probe_i < 30; probe_i++)); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${occupy_port}") 2>/dev/null; then
    occupier_up=1
    break
  fi
  sleep 0.1
done
local_repo_port="${occupy_port}"
local_repo_server_pid=""
serve_rc=0
serve_local_repo 127.0.0.1 >/dev/null 2>&1 || serve_rc=$?
kill "${occupier_pid}" 2>/dev/null || true
if [ "${occupier_up}" -eq 1 ] && [ "${serve_rc}" -ne 0 ]; then
  check "serve_local_repo fails loud when its port is already bound" 0
else
  printf '%s\n' "  occupier_up=${occupier_up} serve_rc=${serve_rc}" >&2
  check "serve_local_repo fails loud when its port is already bound" 1
fi

printf '%s\n' "" "flavor_config_test: ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ]
