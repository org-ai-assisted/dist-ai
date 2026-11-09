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
printf '%s\n' 'deadbeefcafe1234' > "${src_home}/derivative-binary/dm-source-state"

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

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0
