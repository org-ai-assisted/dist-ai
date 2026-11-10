#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-release-test's --local-repo wiring for the whonix cli INST lane (closing the
## build->test loop):
##   - rt_lane_whonix_inst THREADS --local-repo <deriv> to dm-whonix-pair (so the pair enables the
##     fast local repo for check 3), only when --local-repo was set; byte-unchanged otherwise.
##   - it records an HONEST localRepo provenance block (derivative, host repoPath, build sourceSha,
##     the Packages name=version list) and forwards it to the publisher as --provenance-local-repo.
## Drives the REAL rt_lane_whonix_inst (sourced define-only) with: rt_whonix_pair_require stubbed
## (skips the VBox marker dance), a sudo function that drops `-u <acct> --` and runs the rest, a
## dm-whonix-pair RECORDER, a dm-shared-apt-repo repo-path stub pointing at a fixture repo, and an
## image_test_results_publish stub that captures the --provenance-local-repo JSON. No VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

work="$(mktemp --directory --tmpdir dm-release-test-localrepo.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass=0
fail=0
check() {
   if [ "$2" = "true" ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1 (got '${3:-}')"; fi
}

## --- fixtures ---
## A local reprepro 'local' repo whose Packages index lists two derivative packages (name/version
## with epochs + dpkg-shaped versions, to prove the extractor is not naive).
repo_dir="${work}/aptrepo_local/whonix"
pkgs_dir="${repo_dir}/dists/local/main/binary-amd64"
mkdir --parents -- "${pkgs_dir}"
cat > "${pkgs_dir}/Packages" <<'EOF'
Package: anon-apps-config
Version: 7:18.1-1
Architecture: all

Package: whonix-gw-network-conf
Version: 3:18.2-1
Architecture: all
EOF

## Build/admin source home: a dm-source-state file (no git repo) -> sourceSha = its first line.
src_home="${work}/srchome"
mkdir --parents -- "${src_home}/derivative-binary"
printf '%s\n' 'Source-Commit: deadbeefcafe1234' > "${src_home}/derivative-binary/dm-source-state"

## Recorders.
pair_argv="${work}/pair.argv"
prov_file="${work}/provenance.json"
true > "${pair_argv}"
true > "${prov_file}"

pair_stub="${work}/dm-whonix-pair"
cat > "${pair_stub}" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${PAIR_ARGV}"
exit 0
EOF
shared_stub="${work}/dm-shared-apt-repo"
cat > "${shared_stub}" <<EOF
#!/bin/bash
[ "\$1" = 'repo-path' ] && printf '%s\n' "${repo_dir}"
exit 0
EOF
chmod +x "${pair_stub}" "${shared_stub}"

export PAIR_ARGV="${pair_argv}"
## Read as globals by the sourced rt_lane_whonix_inst / rt_build_local_repo_provenance (invisible
## to shellcheck here).
# shellcheck disable=SC2034
DM_WHONIX_PAIR="${pair_stub}"
# shellcheck disable=SC2034
DM_SHARED_APT_REPO="${shared_stub}"
# shellcheck disable=SC2034
DM_SOURCE_HOME="${src_home}"

## sudo: drop `-u <acct> --`, run the rest as this user (so `sudo -u acct -- env ... dm-whonix-pair`
## reaches the recorder, and `sudo -u acct -- mktemp/safe-rm` are real).
# shellcheck disable=SC2317  ## invoked indirectly by the lane
sudo() {
   while [ "$#" -gt 0 ]; do
      case "$1" in
         -u)
            shift 2
            ;;
         --)
            shift
            break
            ;;
         *)
            break
            ;;
      esac
   done
   "$@"
}
## rt_whonix_pair_require: skip the VBox version-marker verification (not under test here).
# shellcheck disable=SC2317  ## invoked indirectly by the lane
rt_whonix_pair_require() { return 0; }
## image_test_results_publish: capture the --provenance-local-repo JSON, print a fake outdir.
# shellcheck disable=SC2317  ## invoked indirectly by rt_publish_result
image_test_results_publish() {
   local prev=""
   local a
   for a in "$@"; do
      [ "${prev}" = "--provenance-local-repo" ] && printf '%s' "${a}" > "${prov_file}"
      prev="${a}"
   done
   printf '%s\n' "${work}/fake-outdir"
}

## Globals the lane + publisher read.
# shellcheck disable=SC2034
interface='cli'
# shellcheck disable=SC2034
desktop='CLI'
# shellcheck disable=SC2034
firmware='bios'
# shellcheck disable=SC2034
rt_origin='downloaded'

## --- run the inst lane WITH --local-repo whonix ---
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
local_repo='whonix'
lane_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || lane_rc=$?
check "inst lane returns 0" "$([ "${lane_rc}" = '0' ] && printf '%s' true || printf '%s' false)" "${lane_rc}"
check "threads --local-repo whonix to dm-whonix-pair" \
   "$(grep --quiet -- '--local-repo whonix' "${pair_argv}" && printf '%s' true || printf '%s' false)"
## The resolved SHARE HOST PATH (repo-path stripped of /aptrepo_local/<deriv>) is passed down so the
## account-run attach pins it rather than re-deriving a slot-less path. repo_dir=<work>/aptrepo_local/
## whonix, so the base is <work>.
check "threads --local-repo-base (resolved share host path) to dm-whonix-pair" \
   "$(grep --quiet -- "--local-repo-base ${work}" "${pair_argv}" && printf '%s' true || printf '%s' false)"
check "still runs --mode functional --interface cli" \
   "$(grep --quiet -- '--mode functional --interface cli' "${pair_argv}" && printf '%s' true || printf '%s' false)"
check "forwards a --provenance-local-repo block to the publisher" \
   "$([ -s "${prov_file}" ] && printf '%s' true || printf '%s' false)"

## localRepo JSON shape (host-side read; single-source repoPath from dm-shared-apt-repo repo-path).
check "localRepo.derivative = whonix" \
   "$([ "$(jq -r '.derivative' -- "${prov_file}" 2>/dev/null)" = 'whonix' ] && printf '%s' true || printf '%s' false)"
check "localRepo.repoPath = the dm-shared-apt-repo repo dir" \
   "$([ "$(jq -r '.repoPath' -- "${prov_file}" 2>/dev/null)" = "${repo_dir}" ] && printf '%s' true || printf '%s' false)"
check "localRepo.sourceSha = dm-source-state first line" \
   "$([ "$(jq -r '.sourceSha' -- "${prov_file}" 2>/dev/null)" = 'deadbeefcafe1234' ] && printf '%s' true || printf '%s' false)"
check "localRepo.packages carries anon-apps-config=7:18.1-1" \
   "$(jq -e '.packages | index("anon-apps-config=7:18.1-1")' -- "${prov_file}" >/dev/null 2>&1 && printf '%s' true || printf '%s' false)"
check "localRepo.packages carries whonix-gw-network-conf=3:18.2-1" \
   "$(jq -e '.packages | index("whonix-gw-network-conf=3:18.2-1")' -- "${prov_file}" >/dev/null 2>&1 && printf '%s' true || printf '%s' false)"

## --- run WITHOUT --local-repo: no thread, no provenance block (byte-unchanged path) ---
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
local_repo=''
nolr_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || nolr_rc=$?
check "no --local-repo: lane returns 0" "$([ "${nolr_rc}" = '0' ] && printf '%s' true || printf '%s' false)" "${nolr_rc}"
check "no --local-repo: dm-whonix-pair NOT handed --local-repo" \
   "$(grep --quiet -- '--local-repo' "${pair_argv}" && printf '%s' false || printf '%s' true)"
check "no --local-repo: NO provenance block forwarded" \
   "$([ ! -s "${prov_file}" ] && printf '%s' true || printf '%s' false)"

## --- G: sourceSha is the BUILD-TIME dm-source-state, never the live checkout HEAD ---
## A source home whose git HEAD DIFFERS from the build-time dm-source-state: the sha must come from
## dm-source-state (the commit the packages were BUILT at), not the advanced HEAD -- a checkout that
## moved after the build no longer matches the packages in the local repo.
g_home="${work}/ghome"
mkdir --parents -- "${g_home}/derivative-binary" "${g_home}/derivative-maker"
printf '%s\n' 'Source-Commit: buildtimesha0000' > "${g_home}/derivative-binary/dm-source-state"
git -C "${g_home}/derivative-maker" init --quiet
git -C "${g_home}/derivative-maker" -c user.email=t@t -c user.name=t commit --quiet --allow-empty -m x
# shellcheck disable=SC2034  ## read as a global by the sourced rt_source_home
DM_SOURCE_HOME="${g_home}"
g_sha="$(rt_local_repo_source_sha)"
check "G: sourceSha is the build-time dm-source-state value, not the live git HEAD or the label line" \
   "$([ "${g_sha}" = 'buildtimesha0000' ] && printf '%s' true || printf '%s' false)" "${g_sha}"
## 'Source-Commit: unrecorded' -> honest empty sha (never the sentinel label).
printf '%s\n' 'Source-Commit: unrecorded' > "${g_home}/derivative-binary/dm-source-state"
unrec_sha="$(rt_local_repo_source_sha)"
check "G: an unrecorded source commit yields an empty sha" \
   "$([ -z "${unrec_sha}" ] && printf '%s' true || printf '%s' false)" "${unrec_sha}"
# shellcheck disable=SC2034
DM_SOURCE_HOME="${src_home}"

## --- #3: a rebuild landing DURING the test window (the repo's Packages changes between the
## pre-upgrade generation capture and the provenance read) must OMIT provenance -- never bind the
## verdict to a generation the guest did not test. Simulate with a dm-whonix-pair that rewrites the
## Packages index (as a concurrent rebuild would) while the "guest upgrade" runs. ---
true > "${pair_argv}"
true > "${prov_file}"
mutating_pair="${work}/dm-whonix-pair-mutate"
cat > "${mutating_pair}" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "\${PAIR_ARGV}"
printf '%s\n' 'Package: anon-apps-config' 'Version: 9:99.9-9' 'Architecture: all' > "${pkgs_dir}/Packages"
exit 0
EOF
chmod +x "${mutating_pair}"
# shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
DM_WHONIX_PAIR="${mutating_pair}"
# shellcheck disable=SC2034
local_repo='whonix'
mut_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || mut_rc=$?
check "#3: lane still returns 0 when the generation changed mid-test" \
   "$([ "${mut_rc}" = '0' ] && printf '%s' true || printf '%s' false)" "${mut_rc}"
check "#3: provenance OMITTED when the repo generation changed mid-test" \
   "$([ ! -s "${prov_file}" ] && printf '%s' true || printf '%s' false)"
# shellcheck disable=SC2034
DM_WHONIX_PAIR="${pair_stub}"

## --- 1565: the root-side repo-path lookup FAILS (empty) -> the lane is INCONCLUSIVE (SETUP_RC)
## BEFORE invoking dm-whonix-pair, never attaching a slot-less repo that disagrees with provenance. ---
true > "${pair_argv}"
true > "${prov_file}"
empty_shared="${work}/dm-shared-apt-repo-empty"
cat > "${empty_shared}" <<'EOF'
#!/bin/bash
## repo-path prints nothing (lookup failed); every subcommand no-ops.
exit 0
EOF
chmod +x "${empty_shared}"
# shellcheck disable=SC2034
DM_SHARED_APT_REPO="${empty_shared}"
# shellcheck disable=SC2034
local_repo='whonix'
lf_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || lf_rc=$?
check "1565: lane is SETUP_RC (2) when the repo-path lookup fails" \
   "$([ "${lf_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${lf_rc}"
check "1565: dm-whonix-pair NOT invoked on a failed repo-path lookup" \
   "$([ ! -s "${pair_argv}" ] && printf '%s' true || printf '%s' false)"
# shellcheck disable=SC2034
DM_SHARED_APT_REPO="${shared_stub}"

## --- finding 6: an UNEXPECTED provenance-build failure on a --local-repo run must publish
## INCONCLUSIVE (SETUP_RC), NEVER a published-repo masquerade -- a local-repo run recorded with NO
## localRepo block is indistinguishable from one that tested the published repos. Distinct from the
## benign generation-change omit above (which stays rc 0): a provenance TOOL failure is an
## environment bug, not a benign race. Test BOTH jq error codes, especially exit 2 -- jq's (and
## awk's) usage/system-error status: an earlier design reused exit 2 as the "generation omit"
## sentinel, so a real jq/awk error (also exit 2) masqueraded as the benign omit. The generation
## here is UNCHANGED (non-mutating pair) and the gen capture uses sha256sum/awk, not jq, so the lane
## reaches the provenance build and fails only there. ---
stubbin="${work}/stubbin"
mkdir --parents -- "${stubbin}"
for jq_rc in 1 2; do
   true > "${pair_argv}"
   true > "${prov_file}"
   printf '%s\n' '#!/bin/sh' "exit ${jq_rc}" > "${stubbin}/jq"
   chmod +x -- "${stubbin}/jq"
   # shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
   local_repo='whonix'
   jqfail_rc=0
   ( export PATH="${stubbin}:${PATH}"; rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || jqfail_rc=$?
   check "finding 6 (jq exit ${jq_rc}): dm-whonix-pair WAS invoked (lane reached the provenance build)" \
      "$(grep --quiet -- '--local-repo whonix' "${pair_argv}" && printf '%s' true || printf '%s' false)"
   check "finding 6 (jq exit ${jq_rc}): a failed provenance build publishes INCONCLUSIVE (SETUP_RC 2), not a published-repo masquerade" \
      "$([ "${jqfail_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${jqfail_rc}"
done

## --- finding 6 (variant): computing the generation id itself (sha256sum | awk) failing must ALSO
## publish INCONCLUSIVE, not be swallowed as the benign unverifiable-generation omit. An awk that
## exits non-zero makes rt_local_repo_gen_id fail; the caller must treat that as a tool/env error. ---
true > "${pair_argv}"
true > "${prov_file}"
printf '%s\n' '#!/bin/sh' 'exit 2' > "${stubbin}/awk"
chmod +x -- "${stubbin}/awk"
# shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
local_repo='whonix'
awkfail_rc=0
( export PATH="${stubbin}:${PATH}"; rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || awkfail_rc=$?
check "finding 6 (gen-id awk failure): a failed generation-id computation publishes INCONCLUSIVE (SETUP_RC 2), not a published-repo masquerade" \
   "$([ "${awkfail_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${awkfail_rc}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0
