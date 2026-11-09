#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-whonix-pair's --local-repo contract (the functional CLI/inst fast-local-upgrade seam):
##   - --local-repo kicksecure|whonix parses; an unknown/absent value is REJECTED (SETUP_RC).
##   - it is REJECTED (SETUP_RC) in leak mode AND in functional GUI -- repo-add-local needs root,
##     which only the split-free CLI edition's `user` has; never a silent skip. Accepted only with
##     --mode functional --interface cli.
##   - functional CLI: boot_workstation_user ATTACHES the 'shared' repo via dm-shared-apt-repo
##     (host-side, before startvm), and ws_func_enable_local_repo runs repo-add-local in-guest as
##     `user` over vbox-exec-local. Asserted BEHAVIORALLY with stubs that record the delegated argv.
## Sources the REAL script define-only (EOF guard); no VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
tool="${here}/../../bin/dm-whonix-pair"
[ -x "${tool}" ] || { printf '%s\n' "FAIL: dm-whonix-pair not found at ${tool}" >&2; exit 1; }

# shellcheck source=../../bin/dm-whonix-pair
source "${tool}"

pass=0
fail=0
assert() {
   local label="$1"
   shift
   if "$@"; then
      pass=$(( pass + 1 )); printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 )); printf '%s\n' "FAIL: ${label}"
   fi
}

## --- parse contract ---
assert "local_repo defaults empty" test -z "${local_repo}"

local_repo=''
parse_args --local-repo whonix
assert "--local-repo whonix parses" test "${local_repo}" = 'whonix'

local_repo=''
parse_args --local-repo kicksecure
assert "--local-repo kicksecure parses" test "${local_repo}" = 'kicksecure'

## an unknown value is REJECTED (SETUP_RC=2); die exits, so run in a subshell + capture rc.
bogus_rc=0
( parse_args --local-repo bogus ) >/dev/null 2>&1 || bogus_rc=$?
assert "--local-repo bogus rejected (SETUP_RC)" test "${bogus_rc}" -eq 2

## --local-repo with NO value must fail SETUP_RC (2), not crash with a bare $2-unbound.
noval_rc=0
( parse_args --local-repo ) >/dev/null 2>&1 || noval_rc=$?
assert "--local-repo with no value rejected (SETUP_RC)" test "${noval_rc}" -eq 2

## --local-repo-base (the orchestrator-passed share host path) parses into local_repo_base.
assert "local_repo_base defaults empty" test -z "${local_repo_base}"
local_repo_base=''
parse_args --local-repo-base /srv/derivative-maker/SLOT
assert "--local-repo-base parses" test "${local_repo_base}" = '/srv/derivative-maker/SLOT'
baseval_rc=0
( parse_args --local-repo-base ) >/dev/null 2>&1 || baseval_rc=$?
assert "--local-repo-base with no value rejected (SETUP_RC)" test "${baseval_rc}" -eq 2

## --- mode/interface gate: stub both drivers + skip the VM lock, drive main ---
export DM_VM_LOCK_HELD=1
# shellcheck disable=SC2317  ## called indirectly via main
main_functional() { return 0; }
# shellcheck disable=SC2317  ## called indirectly via main
main_functional_cli() { return 0; }

## leak + --local-repo -> rejected with the gate message (NOT a bare "unknown argument").
leak_out=''
leak_rc=0
leak_out="$( main --mode leak --local-repo whonix 2>&1 )" || leak_rc=$?
assert "leak + --local-repo rejected (SETUP_RC)" test "${leak_rc}" -eq 2
assert "leak rejection names the functional+cli constraint" \
   grep -q 'valid only with --mode functional' <<< "${leak_out}"

## functional GUI + --local-repo -> rejected (user cannot obtain root under the split).
gui_rc=0
( main --mode functional --interface gui --local-repo whonix ) >/dev/null 2>&1 || gui_rc=$?
assert "functional GUI + --local-repo rejected (SETUP_RC)" test "${gui_rc}" -eq 2

## functional CLI + --local-repo -> accepted (dispatch reaches the stubbed CLI driver, rc 0).
cli_rc=0
main --mode functional --interface cli --local-repo whonix >/dev/null 2>&1 || cli_rc=$?
assert "functional CLI + --local-repo accepted" test "${cli_rc}" -eq 0

## --- behavioral: attach (host) + in-guest enable, via stubs that record the delegated argv ---
rec_attach="$(mktemp)"
rec_exec="$(mktemp)"
shared_stub="$(mktemp)"
exec_stub="$(mktemp)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --force -- "${rec_attach}" "${rec_exec}" "${shared_stub}" "${exec_stub}"; }
trap cleanup EXIT

cat > "${shared_stub}" <<'STUB'
#!/bin/bash
## Record the LOCAL_APT_REPOSITORY_BASE env (the orchestrator-pinned share path) ALONGSIDE argv:
## the account-run attach must receive the base so it never re-derives a slot-less (wrong) path.
printf 'base=%s args=%s\n' "${LOCAL_APT_REPOSITORY_BASE:-}" "$*" >> "${REC_ATTACH}"
exit 0
STUB
cat > "${exec_stub}" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${REC_EXEC}"
exit 0
STUB
chmod +x "${shared_stub}" "${exec_stub}"
export REC_ATTACH="${rec_attach}" REC_EXEC="${rec_exec}"
## Read as globals by the sourced boot_workstation_user / gc_run (invisible to shellcheck).
# shellcheck disable=SC2034
DM_SHARED_APT_REPO="${shared_stub}"
# shellcheck disable=SC2034
VBOX_EXEC_LOCAL="${exec_stub}"

## boot_workstation_user's VM-side steps are not under test here -- stub them so only the attach
## delegation runs; VBOXMANAGE is a no-op so startvm succeeds.
# shellcheck disable=SC2034  ## read as a global by the sourced boot_workstation_user
VBOXMANAGE='true'
# shellcheck disable=SC2317  ## called indirectly by boot_workstation_user
restore_fresh() { :; }
# shellcheck disable=SC2317  ## called indirectly by boot_workstation_user
wait_guestcontrol_ready() { return 0; }
# shellcheck disable=SC2034  ## read as ${ws}/${gw} inside the sourced functions
ws='TESTWS'
# shellcheck disable=SC2034
gw='TESTGW'
local_repo='whonix'
## With a base pinned by the orchestrator, the attach must receive it as LOCAL_APT_REPOSITORY_BASE
## so the account-run attach maps THAT slotted repo, not a re-derived slot-less path.
local_repo_base='/srv/derivative-maker/SLOT'
boot_workstation_user >/dev/null 2>&1
assert "boot_workstation_user attaches the shared repo via dm-shared-apt-repo" \
   grep -q 'args=attach TESTWS' "${rec_attach}"
assert "attach receives the orchestrator-pinned LOCAL_APT_REPOSITORY_BASE" \
   grep -q 'base=/srv/derivative-maker/SLOT ' "${rec_attach}"

## With NO base (non-slotted single-session host), the attach still runs, but with an EMPTY
## LOCAL_APT_REPOSITORY_BASE -- dm-shared-apt-repo then derives the path from the env.
true > "${rec_attach}"
local_repo_base=''
boot_workstation_user >/dev/null 2>&1
assert "no base -> attach runs with an empty LOCAL_APT_REPOSITORY_BASE (env-derived)" \
   grep -q 'base= args=attach TESTWS' "${rec_attach}"
local_repo_base='/srv/derivative-maker/SLOT'

ws_func_enable_local_repo >/dev/null 2>&1
assert "ws_func_enable_local_repo runs repo-add-local for the derivative in-guest" \
   grep -q 'repo-add-local whonix' "${rec_exec}"
assert "ws_func_enable_local_repo runs it as the boot user role" \
   grep -q -- '--role user' "${rec_exec}"
assert "ws_func_enable_local_repo refreshes apt after enabling the repo" \
   grep -q 'apt-get --quiet update' "${rec_exec}"

## with --local-repo UNSET, boot_workstation_user must NOT attach (byte-unchanged path).
true > "${rec_attach}"
local_repo=''
boot_workstation_user >/dev/null 2>&1
assert "no --local-repo -> boot_workstation_user does not attach a share" \
   test ! -s "${rec_attach}"

## --- #1: ws_func_verify_local_repo_installed force-installs the local payload and asserts it is
##     actually installed (a same-version rebuild is a check-3 NO-OP -> false green otherwise).
##     EXECUTE the real guest snippet against stub apt-get/dpkg-query/dsudo + a fixture Packages, so
##     the shell logic is tested, not just the command string. ---
vstub="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup_all() { cleanup; safe-rm --recursive --force -- "${vstub}"; }
trap cleanup_all EXIT

## Fixture local Packages at the exact in-guest path the snippet reads.
pkgs_dir="${vstub}/mnt/aptrepo_local/whonix/dists/local/main/binary-amd64"
mkdir --parents -- "${pkgs_dir}"
cat > "${pkgs_dir}/Packages" <<'EOF'
Package: anon-apps-config
Version: 7:18.1-1
Architecture: all

Package: whonix-gw-network-conf
Version: 3:18.2-1
Architecture: all
EOF

## Stub tools on PATH: dpkg-query reads an installed-version map; apt-get records argv + succeeds;
## dsudo execs the rest.
stub_bin="${vstub}/bin"
mkdir --parents -- "${stub_bin}"
cat > "${stub_bin}/dpkg-query" <<'STUB'
#!/bin/bash
fmt=""; name=""
for a in "$@"; do
   case "$a" in -f=*) fmt="${a#-f=}" ;; -*) : ;; *) name="$a" ;; esac
done
ver="$(awk -v n="${name}" '$1==n{print $2}' "${DPKG_MAP}")"
[ -n "${ver}" ] || exit 1
case "${fmt}" in
   *Status*) printf 'install ok installed\n' ;;
   *Version*) printf '%s\n' "${ver}" ;;
esac
STUB
cat > "${stub_bin}/apt-get" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${APT_LOG}"
exit 0
STUB
cat > "${stub_bin}/dsudo" <<'STUB'
#!/bin/bash
exec "$@"
STUB
chmod +x "${stub_bin}/dpkg-query" "${stub_bin}/apt-get" "${stub_bin}/dsudo"

## gc_run: capture the guest command, then EXECUTE it (so the real snippet logic runs here).
# shellcheck disable=SC2317  ## called indirectly by ws_func_verify_local_repo_installed
gc_run() { printf '%s' "$2" > "${GC_CMD}"; bash -c "$2"; }

export PATH="${stub_bin}:${PATH}"
export DPKG_MAP="${vstub}/dpkg.map"
export APT_LOG="${vstub}/apt.log"
export GC_CMD="${vstub}/gc.cmd"
# shellcheck disable=SC2034  ## read as globals by the sourced function
GUEST_SHARE_MOUNT="${vstub}/mnt"
# shellcheck disable=SC2034
local_repo='whonix'

## PASS: both local packages installed at the local versions -> verification succeeds, and apt-get
## force-reinstalled them from the 'local' suite.
true > "${APT_LOG}"
printf '%s\n' 'anon-apps-config 7:18.1-1' 'whonix-gw-network-conf 3:18.2-1' > "${DPKG_MAP}"
v_rc=0
( ws_func_verify_local_repo_installed ) >/dev/null 2>&1 || v_rc=$?
assert "verify passes when the local payloads are installed at the local versions" test "${v_rc}" -eq 0
assert "verify force-reinstalls from the local suite (--reinstall -t local)" \
   grep -q -- 'install --reinstall --yes --allow-downgrades -t local' "${APT_LOG}"
assert "verify force-installs the exact local version" \
   grep -q -- 'anon-apps-config=7:18.1-1' "${APT_LOG}"
assert "the generated guest command is syntactically valid" bash -n "${GC_CMD}"

## MISMATCH: an installed package reports a DIFFERENT version than the local build -> INCONCLUSIVE
## (SETUP_RC), never a PASS. This is the false-green the finding closes.
printf '%s\n' 'anon-apps-config 7:18.1-1' 'whonix-gw-network-conf 9:99.9-9' > "${DPKG_MAP}"
mm_rc=0
( ws_func_verify_local_repo_installed ) >/dev/null 2>&1 || mm_rc=$?
assert "verify FAILS SETUP_RC on an installed-vs-local version mismatch" test "${mm_rc}" -eq 2

## NONE installed: no local-repo package is on the system -> INCONCLUSIVE, not a vacuous PASS.
true > "${DPKG_MAP}"
none_rc=0
( ws_func_verify_local_repo_installed ) >/dev/null 2>&1 || none_rc=$?
assert "verify FAILS SETUP_RC when no local-repo package is installed" test "${none_rc}" -eq 2

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
