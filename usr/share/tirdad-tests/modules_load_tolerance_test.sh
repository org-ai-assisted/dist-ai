#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pin that tirdad loads its kernel module via a SecureBoot-tolerant mechanism,
## not via the strict /usr/lib/modules-load.d/ entry.
##
## WHY this exists: the tirdad module is unsigned and out-of-tree, so under
## Secure Boot (without an enrolled DKMS MOK) the kernel rejects it ("Key was
## rejected by service"). The old packaging listed the module in
## /usr/lib/modules-load.d/30_tirdad.conf, which is processed by the STRICT
## systemd-modules-load.service: one module there that fails to load fails the
## WHOLE service, marking the system degraded. That is NOT ignorable at the
## release gate (systemd-modules-load also loads jitterentropy_rng via
## security-misc's 30_security-misc.conf, so a unit-wide ignore would mask a
## real shipped-module load regression). The operator accepts tirdad being
## absent under Secure Boot, but the system must not go degraded on its account.
##
## The fix: drop the modules-load.d entry and ship a dedicated oneshot
## tirdad-load.service whose ExecStart is prefixed with "-", so a failed
## modprobe (Secure Boot rejection) is non-fatal and the unit stays successful.
## The load is still ATTEMPTED every boot, so tirdad loads normally and under
## Secure Boot when the MOK is enrolled -- only genuine rejection is tolerated.
## Ordering places the modprobe AFTER systemd-modules-load.service and BEFORE
## security-misc's harden-module-loading.service (which sets
## kernel.modules_disabled=1); if it ran after that lockdown, even a loadable
## module would fail. The positive-load guarantee on a normal (non-SB) boot is
## kept by systemcheck's check_tirdad_module (crit when tirdad is absent and
## Secure Boot is off) and exercised end-to-end by the dm-image-boot release
## gate; this unit test pins the packaging that makes that behavior possible.
##
## Source-tree test: set TIRDAD_REPO or run from a checkout; exits 1 (FATAL)
## when the tirdad tree is absent -- a required subject absent is an environment
## bug (R-220). Its required tooling (systemd-analyze) is assumed present -- an
## absent one FAILS, it does not skip: "an unauthorized skip is a failure, not
## green".

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${TIRDAD_REPO:-}"
if [ -z "${repo}" ]; then
   ## usr/share/tirdad-tests/<this> -> candidate is the tirdad checkout only
   ## when run straight from a tirdad tree (not the dist-ai monorepo). The
   ## dist-ai orchestrator always wires TIRDAD_REPO, so this fallback only aids
   ## a direct invocation from within a tirdad checkout's own copy.
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/debian/tirdad-dkms.install" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi
if [ -z "${repo}" ] || [ ! -f "${repo}/debian/tirdad-dkms.install" ]; then
   printf '%s\n' 'FATAL: tirdad-modules-load-tolerance-test: no tirdad source tree (set TIRDAD_REPO).' >&2
   exit 1
fi

if ! type -P systemd-analyze >/dev/null; then
   printf '%s\n' 'FAIL: tirdad-modules-load-tolerance-test: systemd-analyze (systemd) not on PATH; the gate cannot run' >&2
   exit 1
fi

install_file="${repo}/debian/tirdad-dkms.install"
service_file="${repo}/debian/tirdad-dkms.tirdad-load.service"
modprobe_conf="${repo}/debian/30-tirdad.conf"
modules_load_conf="${repo}/debian/30_tirdad.conf"

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $1"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $1"
}

## --- 1. The strict modules-load.d mechanism is GONE ---
## This is the exact packaging that degrades systemd under Secure Boot.
if [ -e "${modules_load_conf}" ]; then
   fail "debian/30_tirdad.conf still present -- the strict modules-load.d entry degrades systemd-modules-load under Secure Boot"
else
   pass 'no debian/30_tirdad.conf (strict modules-load.d config removed)'
fi

if grep --quiet --fixed-strings -- 'modules-load.d' "${install_file}"; then
   fail "debian/tirdad-dkms.install still installs into modules-load.d -- the strict loader must be gone"
else
   pass 'debian/tirdad-dkms.install installs nothing into modules-load.d'
fi

## --- 2. The tolerant load service is shipped ---
if [ -f "${service_file}" ]; then
   pass 'tirdad-load.service shipped (debian/tirdad-dkms.tirdad-load.service)'
else
   fail 'debian/tirdad-dkms.tirdad-load.service missing -- no tolerant load mechanism'
   ## The remaining service-content checks cannot run without the file.
   printf '%s\n' "Result: ${pass_count} pass, ${fail_count} fail, 0 skip"
   [ "${fail_count}" -eq 0 ]
   exit
fi

## --- 3. The modprobe is failure-TOLERANT (leading "-") ---
## Match an ExecStart that runs modprobe for tirdad with the "-" prefix. A plain
## "ExecStart=/sbin/modprobe tirdad" (no "-") would fail the unit on Secure Boot
## rejection -- the regression this guards against.
exec_line="$(grep -E '^\s*ExecStart=' "${service_file}" || true)"
if grep --extended-regexp --quiet '^\s*ExecStart=-[^[:space:]]*modprobe[[:space:]]+tirdad' <<< "${exec_line}"; then
   pass 'ExecStart uses the failure-tolerant "-" prefix on modprobe tirdad'
else
   fail "ExecStart is not a failure-tolerant modprobe of tirdad (got: '${exec_line}') -- Secure Boot rejection would fail the unit"
fi

## --- 4. Ordering: load AFTER modules-load, BEFORE the module-loading lockdown ---
check_directive() {
   local directive="$1" why="$2"
   if grep --extended-regexp --quiet "^\s*${directive}\s*\$" "${service_file}"; then
      pass "${directive} (${why})"
   else
      fail "missing '${directive}' -- ${why}"
   fi
}
check_directive 'After=systemd-modules-load.service' 'run after the strict modules-load has settled'
check_directive 'Before=harden-module-loading.service' 'load tirdad BEFORE security-misc sets kernel.modules_disabled=1'
check_directive 'Before=sysinit.target' 'load during early boot'
check_directive 'WantedBy=sysinit.target' 'the unit is actually pulled into the boot transaction'

## --- 5. The LKRG softdep is left intact (unchanged behavior) ---
if [ -f "${modprobe_conf}" ] \
   && grep --quiet --fixed-strings -- 'softdep' "${modprobe_conf}" \
   && grep --quiet --fixed-strings -- 'etc/modprobe.d/' "${install_file}"; then
   pass 'the /etc/modprobe.d LKRG softdep is still shipped (unchanged)'
else
   fail 'the /etc/modprobe.d/30-tirdad.conf LKRG softdep is no longer shipped'
fi

## --- 6. systemd accepts the unit ---
## systemd-analyze verify loads the unit and reports directive errors. Ordering
## deps on units absent from the search path (harden-module-loading.service,
## shipped by the separate security-misc package) are NOT errors, so a clean
## verify here is a genuine signal. Run on a COPY in an isolated dir so the
## filename is the unit name and no sibling units are pulled in.
verify_dir="$(mktemp --directory)"
cleanup_verify_dir() {
   safe-rm --recursive --force -- "${verify_dir}" || true
}
trap cleanup_verify_dir EXIT
cp -- "${service_file}" "${verify_dir}/tirdad-load.service"
if systemd-analyze verify "${verify_dir}/tirdad-load.service" 2>"${verify_dir}/verify.err"; then
   pass 'systemd-analyze verify accepts tirdad-load.service'
else
   fail "systemd-analyze verify rejects tirdad-load.service: $(cat "${verify_dir}/verify.err")"
fi

printf '%s\n' "Result: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
