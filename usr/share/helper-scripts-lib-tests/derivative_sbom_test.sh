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
   ## Best-effort: a cleanup failure must not fire errexit in the trap and flip a
   ## passing case to a non-zero exit (the suite runner keys on the exit code).
   safe-rm --recursive --force -- "${test_dir}" || true
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

## ===== fragment merge: non-dpkg components spliced into components[] =====
## A JSON-emitting debsbom stub (the merge path needs parseable CycloneDX) +
## a fragments dir. This exercises the REAL sbom-fragment-merge from the
## checkout (derivative-sbom invokes it via HELPER_SCRIPTS_PATH).
merge_tool="${HELPER_SCRIPTS_REPO:-}/usr/libexec/helper-scripts/sbom-fragment-merge"
[ -n "${HELPER_SCRIPTS_REPO}" ] || merge_tool="/usr/libexec/helper-scripts/sbom-fragment-merge"
if [ ! -x "${merge_tool}" ]; then
   printf '%s\n' "FATAL: sbom-fragment-merge not executable at '${merge_tool}'" >&2
   exit 1
fi

jsonbin="${test_dir}/jsonbin"
mkdir --parents -- "${jsonbin}"
cat > "${jsonbin}/debsbom" <<'EOF'
#!/bin/bash
printf '%s\n' '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"bash","purl":"pkg:deb/debian/bash@5.2"}]}'
exit 0
EOF
chmod +x -- "${jsonbin}/debsbom"

frag_dir="${test_dir}/fragments.d"
mkdir --parents -- "${frag_dir}"
cat > "${frag_dir}/tor-browser.cdx.json" <<'EOF'
{
  "type": "application",
  "bom-ref": "tor-browser@14.5.3",
  "name": "Tor Browser",
  "version": "14.5.3",
  "purl": "pkg:generic/tor-browser@14.5.3?arch=linux-x86_64"
}
EOF

merged_out="${test_dir}/merged.cdx.json"
PATH="${jsonbin}:${PATH}" SBOM_ETC_DIR="${etc}" SBOM_FRAGMENTS_DIR="${frag_dir}" \
   derivative_sbom_generate "${merged_out}" "${want_ts}"
## Valid-JSON check without inline python: re-parse through the merge tool
## itself (empty fragments dir -> no merge), exit 0 iff the output parses.
vcheck_frag="${test_dir}/vcheck.d"
mkdir --parents -- "${vcheck_frag}"
vrc=0
"${merge_tool}" "${vcheck_frag}" < "${merged_out}" >/dev/null 2>&1 || vrc=$?
check "merge: valid JSON out" "${vrc}" "0"
check "merge: base dpkg component kept" \
   "$(grep -c 'pkg:deb/debian/bash@5.2' "${merged_out}")" "1"
check "merge: TB fragment component spliced in" \
   "$(grep -c 'pkg:generic/tor-browser@14.5.3' "${merged_out}")" "1"

## Re-running with the SAME fragment must not double-insert (dedup by purl).
PATH="${jsonbin}:${PATH}" SBOM_ETC_DIR="${etc}" SBOM_FRAGMENTS_DIR="${frag_dir}" \
   derivative_sbom_generate "${merged_out}" "${want_ts}"
check "merge: dedup keeps one TB component on rerun" \
   "$(grep -c 'pkg:generic/tor-browser@14.5.3' "${merged_out}")" "1"

## A second fragment duplicating a base purl must be dropped, not doubled.
cat > "${frag_dir}/dup.cdx.json" <<'EOF'
{"type":"library","name":"bash","purl":"pkg:deb/debian/bash@5.2"}
EOF
PATH="${jsonbin}:${PATH}" SBOM_ETC_DIR="${etc}" SBOM_FRAGMENTS_DIR="${frag_dir}" \
   derivative_sbom_generate "${merged_out}" "${want_ts}"
check "merge: duplicate-purl fragment deduped against base" \
   "$(grep -c 'pkg:deb/debian/bash@5.2' "${merged_out}")" "1"
safe-rm --force -- "${frag_dir}/dup.cdx.json"

## No fragments -> output is EXACTLY debsbom's own (byte-identical passthrough,
## so a plain image's SBOM is unaffected).
empty_frag="${test_dir}/empty-fragments.d"
mkdir --parents -- "${empty_frag}"
plain_out="${test_dir}/plain.cdx.json"
PATH="${jsonbin}:${PATH}" SBOM_ETC_DIR="${etc}" SBOM_FRAGMENTS_DIR="${empty_frag}" \
   derivative_sbom_generate "${plain_out}" "${want_ts}"
"${jsonbin}/debsbom" > "${test_dir}/debsbom-raw.json"
check "merge: no-fragments output is byte-identical to debsbom" \
   "$(if cmp --silent -- "${plain_out}" "${test_dir}/debsbom-raw.json"; then printf '%s' same; else printf '%s' diff; fi)" "same"

## ===== sbom-fragment-merge: shape handling (invoked directly) =====
whole_frag="${test_dir}/whole-fragments.d"
mkdir --parents -- "${whole_frag}"
## A whole CycloneDX document fragment: its components[] are merged.
cat > "${whole_frag}/doc.cdx.json" <<'EOF'
{"bomFormat":"CycloneDX","components":[{"type":"application","name":"X","purl":"pkg:generic/x@1"}]}
EOF
whole_merged="$("${jsonbin}/debsbom" | "${merge_tool}" "${whole_frag}")"
check "merge-tool: whole-doc fragment components merged" \
   "$(printf '%s' "${whole_merged}" | grep -c 'pkg:generic/x@1')" "1"

## Malformed fragment JSON is a HARD error (never a silently-incomplete SBOM).
bad_frag="${test_dir}/bad-fragments.d"
mkdir --parents -- "${bad_frag}"
printf '%s\n' '{ not json' > "${bad_frag}/bad.cdx.json"
badrc=0
{ "${jsonbin}/debsbom" | "${merge_tool}" "${bad_frag}" >/dev/null 2>&1; } || badrc=$?
check "merge-tool: malformed fragment fails closed (exit 1)" "${badrc}" "1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
