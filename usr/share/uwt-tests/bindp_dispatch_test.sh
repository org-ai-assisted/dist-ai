#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## uwtwrapper bindp dispatch: the exec chain taken for an application that must
## listen on the external IP (onionshare, ricochet) rather than be socksified.
##
## On the bindp path uwtwrapper does NOT prepend torsocks; it composes
## LD_PRELOAD with the bindp .so (default /usr/lib/libindp.so), sets BIND_ADDR,
## exports both, and execs the uwtexec stage directly. The behavior under test
## (uwtwrapper lines ~389-404):
##   - LD_PRELOAD reaches the uwtexec stage CONTAINING the bindp .so;
##   - BIND_ADDR reaches it SET (127.0.0.1 via the ifconfig fallback);
##   - torsocks is NOT prepended on this path.
##
## The dispatch DECISION itself (uwtwrapper lines ~311-324) keys bindp on the
## hardcoded parents /usr/bin/onionshare, /usr/bin/onionshare-gui,
## /usr/bin/ricochet, and sanity_tests_general then requires
## ${uwtwrapper_parent}.anondist-orig to exist beside that /usr/bin path. That
## file cannot be created hermetically (it lives in root-owned /usr/bin), so the
## match loop is not hermetically reachable -- exactly as the config-file-driven
## branches are unreachable in uwtwrapper_dispatch_test.sh. This lane therefore
## selects the bindp branch via bindp_dispatch=true (a default_if_empty internal
## variable, the same env-selection class the dispatch lane uses for
## uwtwrapper_global / UWT_DEV_PASSTHROUGH) over a hermetic temp parent, and
## asserts the REAL branch body.
##
## Method: drive the REAL uwtwrapper under a hermetic `env -i`. torsocks is a
## PATH stub that records if it ran; the uwtexec stage is a recording stub
## (uwtexec_bin override) that dumps its own exported-variable names and the
## values of LD_PRELOAD / BIND_ADDR, then is terminal. BIND_ADDR is made
## deterministic by forcing the ifconfig fallback: bindp_interface points at a
## nonexistent interface, so ifconfig yields nothing and the code falls back to
## 127.0.0.1 regardless of host networking (and regardless of whether ifconfig
## is even installed).
##
## Targets the installed package by default; set UWT_REPO to test a checkout
## (then HELPER_SCRIPTS_PATH must point at a helper-scripts checkout so the
## wrapper can source strings.bsh / has.bsh). A missing subject or helper
## library is a REQUIRED-dependency environment bug -> exit 1 (FATAL), never a
## skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## bindp selection depends on uwtwrapper's default dispatch state. The wrapper
## sources /etc/uwt.d/*.conf and /usr/local/etc/uwt.d/*.conf from HARDCODED
## paths (deliberately not env-overridable, so a torification wrapper cannot be
## pointed at rogue config). Host config present here would make the test
## non-hermetic.
for host_conf in /etc/uwt.d/*.conf /usr/local/etc/uwt.d/*.conf; do
   [ -e "${host_conf}" ] || continue
   printf '%s\n' "FATAL: host uwt config present ('${host_conf}'); test is not hermetic against it" >&2
   exit 1
done

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   libexec_dir="${UWT_REPO}/usr/libexec/uwt"
else
   libexec_dir='/usr/libexec/uwt'
fi
uwtwrapper="${libexec_dir}/uwtwrapper"

[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${uwtwrapper}" ]; then
   printf '%s\n' "FATAL: uwtwrapper not readable at '${uwtwrapper}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi
if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   ## '|| true': a cleanup failure must not clobber the script's real exit code.
   safe-rm -r -f -- "${test_dir}" || true
}
trap cleanup_handler EXIT

bin_dir="${test_dir}/bin"
mkdir -p -- "${bin_dir}"

## torsocks stub: record that it ran (TORSOCKS_MARK), then exec the rest of the
## chain. On the bindp path it must NOT be invoked, so TORSOCKS_MARK stays
## empty. The stub body is literal shell written to a file; its $-expressions
## expand when the stub runs, not here.
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" ran >> "${TORSOCKS_MARK}"'
   printf '%s\n' 'exec "$@"'
} > "${bin_dir}/torsocks"
chmod 0755 -- "${bin_dir}/torsocks"

## uwtexec stage stub (uwtexec_bin override): record that it ran (UWTEXEC_MARK),
## dump its own exported-variable NAMES (UWTEXEC_NAMES) and the delivered values
## of LD_PRELOAD (UWTEXEC_LDPRELOAD) and BIND_ADDR (UWTEXEC_BINDADDR), then be
## terminal. compgen is a bash builtin, so no coreutils are needed on PATH for
## it. Literal shell written to a file (see SC2016 note above).
uwtexec_stub="${test_dir}/uwtexec_stub"
# shellcheck disable=SC2016
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'printf "%s\n" ran >> "${UWTEXEC_MARK}"'
   printf '%s\n' 'compgen -e | LC_ALL=C sort > "${UWTEXEC_NAMES}"'
   printf '%s\n' 'printf "%s" "${LD_PRELOAD-__UNSET__}" > "${UWTEXEC_LDPRELOAD}"'
   printf '%s\n' 'printf "%s" "${BIND_ADDR-__UNSET__}" > "${UWTEXEC_BINDADDR}"'
   printf '%s\n' 'exit 0'
} > "${uwtexec_stub}"
chmod 0755 -- "${uwtexec_stub}"

## sanity_tests_general requires ${uwtwrapper_parent}.anondist-orig to exist and
## be executable (a dummy is fine: the uwtexec_bin stub is terminal, so the real
## target is never exec'd). Hermetic temp parent, see header.
app_base="${test_dir}/onionshare"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'exit 0'
} > "${app_base}.anondist-orig"
chmod 0755 -- "${app_base}.anondist-orig"

base_path="${bin_dir}:/usr/bin:/bin"

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}
check_contains() {
   local label="$1" haystack="$2" needle="$3"
   if [[ "${haystack}" == *"${needle}"* ]]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${haystack}', want substring '${needle}')"
      fail=$((fail + 1))
   fi
}

## Drive the REAL uwtwrapper down the bindp branch and collect what the uwtexec
## stage received. bindp_interface is a nonexistent iface, forcing BIND_ADDR to
## the 127.0.0.1 fallback deterministically.
t_mark="$(mktemp --tmpdir="${test_dir}")"
u_mark="$(mktemp --tmpdir="${test_dir}")"
names_file="$(mktemp --tmpdir="${test_dir}")"
ld_file="$(mktemp --tmpdir="${test_dir}")"
addr_file="$(mktemp --tmpdir="${test_dir}")"

env -i \
   PATH="${base_path}" \
   HOME="${test_dir}" \
   uwtwrapper_parent="${app_base}" \
   uwtexec_bin="${uwtexec_stub}" \
   HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
   bindp_dispatch=true \
   bindp_interface="uwt-test-nonexistent0" \
   TORSOCKS_MARK="${t_mark}" \
   UWTEXEC_MARK="${u_mark}" \
   UWTEXEC_NAMES="${names_file}" \
   UWTEXEC_LDPRELOAD="${ld_file}" \
   UWTEXEC_BINDADDR="${addr_file}" \
   "${uwtwrapper}"

if [ -s "${t_mark}" ]; then torsocks_ran=yes; else torsocks_ran=no; fi
if [ -s "${u_mark}" ]; then uwtexec_ran=yes; else uwtexec_ran=no; fi
names_got="$(cat -- "${names_file}")"
ld_got="$(cat -- "${ld_file}")"
addr_got="$(cat -- "${addr_file}")"

check          "bindp: uwtexec stage ran"              "${uwtexec_ran}" "yes"
check          "bindp: torsocks NOT prepended"         "${torsocks_ran}" "no"
check_contains "bindp: LD_PRELOAD carries bindp .so"   "${ld_got}" "/usr/lib/libindp.so"
check_contains "bindp: LD_PRELOAD exported to uwtexec" "${names_got}" "LD_PRELOAD"
check_contains "bindp: BIND_ADDR exported to uwtexec"  "${names_got}" "BIND_ADDR"
check          "bindp: BIND_ADDR set (ifconfig fallback)" "${addr_got}" "127.0.0.1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
