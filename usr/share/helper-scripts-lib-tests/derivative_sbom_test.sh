#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## helper-scripts 'derivative-sbom': the shared SBOM generator called by both the
## image build (via the 76_sbom chroot hook) and by a user to regenerate an
## up-to-date SBOM after upgrades.
##
## It is source-able (was_executed guard, strict-mode confined to main()), so this
## test sources it and calls the pure functions directly:
##   - derivative_sbom_identity   derivative name + version from the in-image
##                                marker files (Whonix wins over Kicksecure;
##                                non-derivative falls back to os-release), via
##                                the SBOM_ETC_DIR fixture seam.
##   - derivative_sbom_serial     deterministic (uuidgen --sha1) serial.
##   - derivative_sbom_generate   assembles the debsbom invocation (debsbom is
##                                stubbed to record argv -- never a real scan).
##
## A missing subject or check_runtime.bsh is a HARD FAIL (exit 1). No root, no net.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/bin/derivative-sbom"
   libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
else
   subject='/usr/bin/derivative-sbom'
   libdir='/usr/libexec/helper-scripts'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -r "${libdir}/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable under '${libdir}'" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"; got="$2"; want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"; pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')" >&2; fail=$((fail + 1))
   fi
}

## The subject resolves check_runtime.bsh (was_executed) via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

## Source the real subject. The was_executed guard keeps main from running on
## source; were it to run, debsbom (absent from PATH here) would abort it under
## errexit and fail this source. So a clean source with the functions defined is
## the source-ability proof; the style gate separately verifies the guard shape.
# shellcheck disable=SC1090
src_out="$(source "${subject}" 2>&1)" \
   || { printf '%s\n' "FATAL: sourcing '${subject}' failed: ${src_out}" >&2; exit 1; }
check "sourcing does not auto-run (no output)" "${src_out}" ""
# shellcheck disable=SC1090
source "${subject}"
check "main is defined"                   "$(type -t main)"                   "function"
check "derivative_sbom_identity defined"  "$(type -t derivative_sbom_identity)" "function"
check "derivative_sbom_serial defined"    "$(type -t derivative_sbom_serial)"   "function"
check "derivative_sbom_generate defined"  "$(type -t derivative_sbom_generate)" "function"

## ===== derivative_sbom_identity: the marker discriminator =====
etc="${test_dir}/etc"
mkdir --parents -- "${etc}"
printf '%s\n' 'ID=debian' 'VERSION_ID=13' > "${etc}/os-release"

## Kicksecure marker -> named Kicksecure, NOT the os-release 'debian'.
printf '%s\n' '18' > "${etc}/kicksecure_version"
distro_id=""; distro_version=""
SBOM_ETC_DIR="${etc}" derivative_sbom_identity
check "identity: Kicksecure name from marker" "${distro_id}" "Kicksecure"
check "identity: version from kicksecure_version" "${distro_version}" "18"

## Whonix marker present too -> Whonix wins (Whonix is built on Kicksecure).
printf '%s\n' '17' > "${etc}/whonix_version"
distro_id=""; distro_version=""
SBOM_ETC_DIR="${etc}" derivative_sbom_identity
check "identity: Whonix wins over Kicksecure" "${distro_id}" "Whonix"
check "identity: version from whonix_version" "${distro_version}" "17"

## No derivative marker -> fall back to os-release ID/VERSION_ID.
safe-rm --force -- "${etc}/whonix_version" "${etc}/kicksecure_version"
distro_id=""; distro_version=""
SBOM_ETC_DIR="${etc}" derivative_sbom_identity
check "identity: fallback name from os-release ID" "${distro_id}" "debian"
check "identity: fallback version from os-release VERSION_ID" "${distro_version}" "13"

## A field os-release does NOT set (e.g. VERSION_ID on Debian sid) must read as
## empty, NEVER inherited from the ambient environment.
printf '%s\n' 'ID=debian' > "${etc}/os-release"
distro_id=""; distro_version=""
VERSION_ID="ambient-must-not-leak" SBOM_ETC_DIR="${etc}" derivative_sbom_identity
check "identity: unset VERSION_ID does not inherit ambient env" "${distro_version}" ""
printf '%s\n' 'ID=debian' 'VERSION_ID=13' > "${etc}/os-release"

## ===== derivative_sbom_serial: deterministic, identity- AND timestamp-dependent =====
ts1="2024-01-01T00:00:00+00:00"
ts2="2025-06-15T12:00:00+00:00"
s1="$(derivative_sbom_serial Kicksecure 18 amd64 "${ts1}")"
s2="$(derivative_sbom_serial Kicksecure 18 amd64 "${ts1}")"
s3="$(derivative_sbom_serial Whonix 17 amd64 "${ts1}")"
s4="$(derivative_sbom_serial Kicksecure 18 amd64 "${ts2}")"
check "serial: deterministic for same identity+timestamp" "${s1}" "${s2}"
check "serial: differs for a different identity" "$(if [ "${s1}" != "${s3}" ]; then printf '%s' diff; else printf '%s' same; fi)" "diff"
## A later regeneration (different timestamp, possibly different package set) must
## get a DISTINCT serial so two differing documents are not conflated under one id.
check "serial: differs for a different timestamp" "$(if [ "${s1}" != "${s4}" ]; then printf '%s' diff; else printf '%s' same; fi)" "diff"
check "serial: UUID shape" "$(printf '%s' "${s1}" | grep -cE '^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$')" "1"

## ===== derivative_sbom_generate: the debsbom invocation (debsbom stubbed) =====
## debsbom's own --out appends '.cdx.json', so the wrapper always calls it with
## '--out -' and redirects stdout to the exact target. The stub emits a marker on
## stdout so the test can assert the wrapper placed it at EXACTLY ${out}.
rec="${test_dir}/debsbom.argv"
mockbin="${test_dir}/bin"
mkdir --parents -- "${mockbin}"
cat > "${mockbin}/debsbom" <<EOF
#!/bin/bash
printf '%q ' "\$@" >> "${rec}"
printf '\n' >> "${rec}"
printf '%s\n' 'STUB-SBOM-ON-STDOUT'
exit 0
EOF
chmod +x -- "${mockbin}/debsbom"

printf '%s\n' '18' > "${etc}/kicksecure_version"
want_arch="$(dpkg --print-architecture)"
want_ts="2024-04-05T19:34:38+00:00"
want_serial="$(derivative_sbom_serial Kicksecure 18 "${want_arch}" "${want_ts}")"
gen_out="${test_dir}/gen-out.cdx.json"
PATH="${mockbin}:${PATH}" SBOM_ETC_DIR="${etc}" \
   derivative_sbom_generate "${gen_out}" "${want_ts}"
dbg() {
   [ -f "${rec}" ] && grep --quiet --fixed-strings -- "$(printf '%q ' "$@")" "${rec}"
}
yn() { if "$@"; then printf '%s' yes; else printf '%s' no; fi; }
check "generate: CycloneDX only"          "$(yn dbg --sbom-type cdx)"                 "yes"
check "generate: schema 1.6"              "$(yn dbg --cdx-schema-version 1.6)"         "yes"
check "generate: serial = identity+timestamp" "$(yn dbg --cdx-serialnumber "${want_serial}")" "yes"
check "generate: timestamp passed through" "$(yn dbg --timestamp "${want_ts}")"       "yes"
check "generate: root named Kicksecure"   "$(yn dbg --distro-name Kicksecure)"        "yes"
check "generate: debsbom emits to stdout (--out -)" "$(yn dbg --out -)"               "yes"
check "generate: wrapper wrote EXACTLY --out (no .cdx.json suffix)" "$(yn test -f "${gen_out}")" "yes"
check "generate: no suffixed stray file" "$(yn test -e "${gen_out}.cdx.json")"        "no"
check "generate: output is the SBOM, redirected" "$(cat -- "${gen_out}" 2>/dev/null)" "STUB-SBOM-ON-STDOUT"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
