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
## safe-rm is a required dep (dist-ai CI installs it); the cleanup trap's
## 'safe-rm ... || true' tolerates a runtime rm failure but would also MASK
## safe-rm being absent -- assert it up front so a missing dep fails loud.
if ! type -P safe-rm >/dev/null 2>&1; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

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

## Regression: the serial must need NO uuidgen. uuid-runtime is not a dependency
## of helper-scripts and is absent from the CI runner, so a uuidgen-based serial
## aborts the subject (#derivative-sbom uuidgen: command not found). Point PATH at
## a uuidgen shim that RECORDS any invocation and fails like an absent binary; the
## REAL function must return the correct uuid5 (computed in Python), exit 0, and
## never touch the shim -- so the contract "never shells out to uuidgen" is
## asserted directly, not merely inferred from the output. The pinned value equals
## 'uuidgen --sha1 --namespace @url --name <name>' for these inputs, so output is
## unchanged from the old uuidgen implementation.
nouuid="${test_dir}/nouuidbin"
mkdir --parents -- "${nouuid}"
uuidgen_marker="${test_dir}/uuidgen-invoked"
## Unquoted heredoc so the shim bakes in the absolute marker path.
cat > "${nouuid}/uuidgen" <<EOF
#!/bin/bash
touch -- "${uuidgen_marker}"
printf '%s\n' "uuidgen: simulated absent (regression canary)" >&2
exit 127
EOF
chmod +x -- "${nouuid}/uuidgen"
## Prefix-env PATH (not an exported PATH in a subshell) scopes the shim to this
## one call without a subshell modification that shellcheck would flag (SC2030).
serial_no_uuidgen_rc=0
serial_no_uuidgen="$(PATH="${nouuid}:${PATH}" \
   derivative_sbom_serial Kicksecure 18 amd64 "2024-04-05T19:34:38+00:00")" \
   || serial_no_uuidgen_rc=$?
check "serial: computed without uuidgen (uuid5 in python, not uuid-runtime)" \
   "${serial_no_uuidgen}" "17db1f7c-c9f0-5969-b4cf-6f1b45e3b909"
check "serial: the no-uuidgen call succeeds (exit 0)" \
   "${serial_no_uuidgen_rc}" "0"
check "serial: uuidgen never invoked (shim marker absent)" \
   "$(if [ -e "${uuidgen_marker}" ]; then printf '%s' present; else printf '%s' absent; fi)" "absent"

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
## Pin SBOM_FRAGMENTS_DIR at an empty dir: the debsbom stub emits a NON-JSON
## marker, so the default /usr/share/sbom/fragments.d (which on an installed
## host already holds the Tor Browser fragment) would drive the merge path and
## abort. The merge path is exercised separately below with a JSON stub.
nofrag="${test_dir}/no-fragments.d"
mkdir --parents -- "${nofrag}"
PATH="${mockbin}:${PATH}" SBOM_ETC_DIR="${etc}" SBOM_FRAGMENTS_DIR="${nofrag}" \
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
## Exercises the REAL sbom-fragment-merge from the checkout (derivative-sbom
## invokes it via HELPER_SCRIPTS_PATH). jq (a dist-ai suite dependency) proves
## a component is in the top-level components[] array, not merely somewhere in
## the document (e.g. the metadata root component).
merge_tool="${HELPER_SCRIPTS_REPO:-}/usr/libexec/helper-scripts/sbom-fragment-merge"
[ -n "${HELPER_SCRIPTS_REPO}" ] || merge_tool="/usr/libexec/helper-scripts/sbom-fragment-merge"
if [ ! -x "${merge_tool}" ]; then
   printf '%s\n' "FATAL: sbom-fragment-merge not executable at '${merge_tool}'" >&2
   exit 1
fi
if ! type -P jq >/dev/null; then
   printf '%s\n' "FATAL: jq (required dependency) not found" >&2
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

merge_base='{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"bash","purl":"pkg:deb/debian/bash@5.2"}]}'

## Count top-level components whose purl equals $2, in file $1. Captures jq's
## output only on success, so an invalid merged document (jq parse error) reads
## as JQERR -- never a count that could coincidentally match. 'components' MUST
## be an array: an object (schema-invalid) reads as NOT-ARRAY. Both make the
## enclosing check FAIL rather than pass.
purl_count() {
   local out
   if out="$(jq --arg p "$2" \
      '.components | if type=="array" then [.[]|select(.purl==$p)]|length else "NOT-ARRAY" end' \
      "$1" 2>/dev/null)"; then
      printf '%s' "${out}"
   else
      printf '%s' 'JQERR'
   fi
}
## Exit code of a merge of base JSON $1 over fragments dir $2 (errexit-safe).
merge_rc() {
   local rc=0
   printf '%s' "$1" | "${merge_tool}" "$2" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

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
vcheck_frag="${test_dir}/vcheck.d"
mkdir --parents -- "${vcheck_frag}"
vrc=0
"${merge_tool}" "${vcheck_frag}" < "${merged_out}" >/dev/null 2>&1 || vrc=$?
check "merge: valid JSON out" "${vrc}" "0"
check "merge: base dpkg component in components[]" \
   "$(purl_count "${merged_out}" 'pkg:deb/debian/bash@5.2')" "1"
check "merge: TB fragment in components[] (not metadata)" \
   "$(purl_count "${merged_out}" 'pkg:generic/tor-browser@14.5.3?arch=linux-x86_64')" "1"

## Re-merging the output (already holds TB) with the same fragment must not
## double-insert -- genuine dedup across a real re-merge, not an artifact of
## regenerating from the stub.
rerun_out="${test_dir}/rerun.cdx.json"
"${merge_tool}" "${frag_dir}" < "${merged_out}" > "${rerun_out}"
check "merge: dedup keeps one TB component on re-merge" \
   "$(purl_count "${rerun_out}" 'pkg:generic/tor-browser@14.5.3?arch=linux-x86_64')" "1"

## A second fragment duplicating a base purl must be dropped, not doubled.
cat > "${frag_dir}/dup.cdx.json" <<'EOF'
{"type":"library","name":"bash","purl":"pkg:deb/debian/bash@5.2"}
EOF
PATH="${jsonbin}:${PATH}" SBOM_ETC_DIR="${etc}" SBOM_FRAGMENTS_DIR="${frag_dir}" \
   derivative_sbom_generate "${merged_out}" "${want_ts}"
check "merge: duplicate-purl fragment deduped against base" \
   "$(purl_count "${merged_out}" 'pkg:deb/debian/bash@5.2')" "1"
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

## ===== sbom-fragment-merge: shape handling + fail-closed (invoked directly) =====
## A whole CycloneDX document fragment: its components[] are merged AND the base
## components survive.
whole_frag="${test_dir}/whole-fragments.d"
mkdir --parents -- "${whole_frag}"
cat > "${whole_frag}/doc.cdx.json" <<'EOF'
{"bomFormat":"CycloneDX","components":[{"type":"application","name":"X","purl":"pkg:generic/x@1"}]}
EOF
whole_out="${test_dir}/whole.cdx.json"
printf '%s' "${merge_base}" | "${merge_tool}" "${whole_frag}" > "${whole_out}"
check "merge-tool: whole-doc fragment component merged" \
   "$(purl_count "${whole_out}" 'pkg:generic/x@1')" "1"
check "merge-tool: base component survives whole-doc merge" \
   "$(purl_count "${whole_out}" 'pkg:deb/debian/bash@5.2')" "1"

## A valid CycloneDX document with zero top-level components (metadata only) is
## "nothing to add", NOT malformed -- it must not abort the merge/build.
metaonly_frag="${test_dir}/metaonly-fragments.d"
mkdir --parents -- "${metaonly_frag}"
cat > "${metaonly_frag}/m.cdx.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"operating-system","name":"Kicksecure"}}}
EOF
metaonly_out="${test_dir}/metaonly.cdx.json"
metaonly_rc=0
printf '%s' "${merge_base}" | "${merge_tool}" "${metaonly_frag}" > "${metaonly_out}" 2>/dev/null || metaonly_rc=$?
check "merge-tool: metadata-only doc is a no-op (exit 0)" "${metaonly_rc}" "0"
check "merge-tool: metadata-only doc leaves base intact" \
   "$(purl_count "${metaonly_out}" 'pkg:deb/debian/bash@5.2')" "1"

## A bare component that itself carries nested sub-'components' must be kept as
## the parent, NOT mistaken for a document (which would drop the parent).
nested_frag="${test_dir}/nested-fragments.d"
mkdir --parents -- "${nested_frag}"
cat > "${nested_frag}/n.cdx.json" <<'EOF'
{"type":"application","name":"Parent","purl":"pkg:generic/parent@1","components":[{"type":"library","name":"sub","purl":"pkg:generic/sub@1"}]}
EOF
nested_out="${test_dir}/nested.cdx.json"
printf '%s' "${merge_base}" | "${merge_tool}" "${nested_frag}" > "${nested_out}"
check "merge-tool: nested-component fragment kept as parent" \
   "$(purl_count "${nested_out}" 'pkg:generic/parent@1')" "1"
check "merge-tool: nested sub-component not hoisted to top level" \
   "$(purl_count "${nested_out}" 'pkg:generic/sub@1')" "0"

## A dotfile fragment is ignored (matches the bash '*.cdx.json' gate).
dot_frag="${test_dir}/dot-fragments.d"
mkdir --parents -- "${dot_frag}"
cat > "${dot_frag}/.hidden.cdx.json" <<'EOF'
{"type":"application","name":"Hidden","purl":"pkg:generic/hidden@1"}
EOF
dot_out="${test_dir}/dot.cdx.json"
printf '%s' "${merge_base}" | "${merge_tool}" "${dot_frag}" > "${dot_out}"
check "merge-tool: dotfile fragment ignored" \
   "$(purl_count "${dot_out}" 'pkg:generic/hidden@1')" "0"

## bom-ref collision with a DIFFERENT component must fail closed, never emit two
## objects sharing a bom-ref nor silently drop one.
col_frag="${test_dir}/collide-fragments.d"
mkdir --parents -- "${col_frag}"
cat > "${col_frag}/c.cdx.json" <<'EOF'
{"type":"application","name":"Other","bom-ref":"shared-ref"}
EOF
col_base='{"bomFormat":"CycloneDX","components":[{"type":"library","name":"base","purl":"pkg:deb/debian/base@1","bom-ref":"shared-ref"}]}'
check "merge-tool: bom-ref collision (base) fails closed" \
   "$(merge_rc "${col_base}" "${col_frag}")" "1"

## Collision against the metadata root component's bom-ref is detected too.
meta_base='{"bomFormat":"CycloneDX","metadata":{"component":{"type":"operating-system","name":"Kicksecure","bom-ref":"root-ref"}},"components":[]}'
cat > "${col_frag}/c.cdx.json" <<'EOF'
{"type":"application","name":"Other","bom-ref":"root-ref"}
EOF
check "merge-tool: bom-ref collision (metadata root) fails closed" \
   "$(merge_rc "${meta_base}" "${col_frag}")" "1"
safe-rm --recursive --force -- "${col_frag}"

## bom-ref uniqueness is enforced against NESTED components on both sides: a
## fragment's nested child colliding with a base top-level ref, and a base's
## nested child colliding with a fragment's top-level ref, both fail closed.
nest_col_frag="${test_dir}/nestcol-fragments.d"
mkdir --parents -- "${nest_col_frag}"
cat > "${nest_col_frag}/n.cdx.json" <<'EOF'
{"type":"application","name":"Parent","bom-ref":"parent","components":[{"type":"library","name":"child","bom-ref":"shared"}]}
EOF
base_topref='{"bomFormat":"CycloneDX","components":[{"type":"library","name":"base","bom-ref":"shared"}]}'
check "merge-tool: fragment nested bom-ref collision fails closed" \
   "$(merge_rc "${base_topref}" "${nest_col_frag}")" "1"
cat > "${nest_col_frag}/n.cdx.json" <<'EOF'
{"type":"application","name":"New","bom-ref":"shared"}
EOF
base_nestref='{"bomFormat":"CycloneDX","components":[{"type":"application","name":"parent","bom-ref":"parent","components":[{"type":"library","name":"old","bom-ref":"shared"}]}]}'
check "merge-tool: base nested bom-ref collision fails closed" \
   "$(merge_rc "${base_nestref}" "${nest_col_frag}")" "1"
safe-rm --recursive --force -- "${nest_col_frag}"

## An identical component sharing only a bom-ref (no purl) must dedup on a
## re-merge, not be mistaken for a conflict (idempotency).
idem_frag="${test_dir}/idem-fragments.d"
mkdir --parents -- "${idem_frag}"
cat > "${idem_frag}/i.cdx.json" <<'EOF'
{"type":"application","name":"tool","bom-ref":"tool@1"}
EOF
idem_base='{"bomFormat":"CycloneDX","components":[{"type":"application","name":"tool","bom-ref":"tool@1"}]}'
idem_out="${test_dir}/idem.cdx.json"
idem_rc=0
printf '%s' "${idem_base}" | "${merge_tool}" "${idem_frag}" > "${idem_out}" 2>/dev/null || idem_rc=$?
check "merge-tool: identical bom-ref-only component dedups (exit 0)" "${idem_rc}" "0"
check "merge-tool: identical bom-ref-only component not doubled" \
   "$(jq '[.components[]|select(.["bom-ref"]=="tool@1")]|length' "${idem_out}" 2>/dev/null)" "1"

## A schema-valid empty name is accepted (CycloneDX requires name present+string,
## no minimum length).
emptyname_frag="${test_dir}/emptyname-fragments.d"
mkdir --parents -- "${emptyname_frag}"
printf '%s\n' '{"type":"application","name":"","purl":"pkg:generic/en@1"}' > "${emptyname_frag}/e.cdx.json"
check "merge-tool: empty-string name accepted" \
   "$(merge_rc "${merge_base}" "${emptyname_frag}")" "0"

## A non-UTF-8 fragment fails closed CLEANLY (no traceback).
utf_frag="${test_dir}/utf-fragments.d"
mkdir --parents -- "${utf_frag}"
nonutf8_byte=$'\377'
printf '%s' "{${nonutf8_byte}}" > "${utf_frag}/u.cdx.json"
check "merge-tool: non-UTF-8 fragment fails closed" \
   "$(merge_rc "${merge_base}" "${utf_frag}")" "1"

## A document component missing the required type/name fails closed.
notype_frag="${test_dir}/notype-fragments.d"
mkdir --parents -- "${notype_frag}"
printf '%s\n' '{"bomFormat":"CycloneDX","components":[{}]}' > "${notype_frag}/n.cdx.json"
check "merge-tool: component missing type/name fails closed" \
   "$(merge_rc "${merge_base}" "${notype_frag}")" "1"

## The non-standard NaN token (Python accepts it; it is not valid JSON) fails closed.
nan_frag="${test_dir}/nan-fragments.d"
mkdir --parents -- "${nan_frag}"
printf '%s\n' '{"type":"application","name":"N","version":NaN}' > "${nan_frag}/n.cdx.json"
check "merge-tool: NaN fragment fails closed" \
   "$(merge_rc "${merge_base}" "${nan_frag}")" "1"

## A symlinked fragment is refused (could pull a root-only file into the SBOM).
link_frag="${test_dir}/link-fragments.d"
mkdir --parents -- "${link_frag}"
printf '%s\n' '{"type":"application","name":"S","purl":"pkg:generic/secret@1"}' > "${test_dir}/outside.json"
ln --symbolic -- "${test_dir}/outside.json" "${link_frag}/link.cdx.json"
check "merge-tool: symlink fragment refused (fails closed)" \
   "$(merge_rc "${merge_base}" "${link_frag}")" "1"
## Not merely exit 1: the symlinked content must never reach stdout (which
## production redirects into the SBOM), so refusal must precede any read.
link_stdout="$(printf '%s' "${merge_base}" | "${merge_tool}" "${link_frag}" 2>/dev/null || true)"
check "merge-tool: symlink fragment leaks no content" \
   "$(if [[ "${link_stdout}" == *'pkg:generic/secret@1'* ]]; then printf '%s' leak; else printf '%s' clean; fi)" "clean"

## Malformed fragment JSON is a HARD error (never a silently-incomplete SBOM).
bad_frag="${test_dir}/bad-fragments.d"
mkdir --parents -- "${bad_frag}"
printf '%s\n' '{ not json' > "${bad_frag}/bad.cdx.json"
check "merge-tool: malformed fragment fails closed (exit 1)" \
   "$(merge_rc "${merge_base}" "${bad_frag}")" "1"

## A missing/mistyped FRAGMENTS_DIR is misconfiguration -> fail closed, never a
## silently fragment-less (incomplete) SBOM. An existing EMPTY dir is NOT an
## error (zero fragments -> base-only). This pair is the canary: the fail-closed
## asserts are RED on the old code (which silently emitted base-only, exit 0),
## while the empty-dir assert guards against over-correcting into failing on empty.
missing_frag="${test_dir}/does-not-exist.d"
check "merge-tool: non-existent FRAGMENTS_DIR fails closed (exit 1)" \
   "$(merge_rc "${merge_base}" "${missing_frag}")" "1"
notdir_frag="${test_dir}/notdir.cdx.json"
printf '%s\n' 'not a directory' > "${notdir_frag}"
check "merge-tool: non-directory FRAGMENTS_DIR fails closed (exit 1)" \
   "$(merge_rc "${merge_base}" "${notdir_frag}")" "1"
emptydir_frag="${test_dir}/empty-direct.d"
mkdir --parents -- "${emptydir_frag}"
emptydir_out="${test_dir}/empty-direct.cdx.json"
emptydir_rc=0
printf '%s' "${merge_base}" | "${merge_tool}" "${emptydir_frag}" > "${emptydir_out}" 2>/dev/null \
   || emptydir_rc=$?
check "merge-tool: empty-but-existing dir succeeds (exit 0)" "${emptydir_rc}" "0"
check "merge-tool: empty-but-existing dir yields base-only (base survives)" \
   "$(purl_count "${emptydir_out}" 'pkg:deb/debian/bash@5.2')" "1"

## An existing-but-UNLISTABLE fragments dir must fail closed, never silently emit
## a fragment-less SBOM. Canary: Path.glob swallows the listdir OSError (base-only,
## exit 0 on old code); the explicit os.scandir propagates it -> die. (Suite runs
## non-root per its contract; root bypasses the mode bits.)
noread_frag="${test_dir}/noread-fragments.d"
mkdir --parents -- "${noread_frag}"
printf '%s\n' '{"type":"application","name":"nr","purl":"pkg:generic/nr@1"}' > "${noread_frag}/n.cdx.json"
chmod 000 -- "${noread_frag}"
noread_rc="$(merge_rc "${merge_base}" "${noread_frag}")"
chmod 755 -- "${noread_frag}"
check "merge-tool: unlistable fragments dir fails closed (exit 1)" "${noread_rc}" "1"

## A fifo fragment is refused WITHOUT hanging (O_NONBLOCK open + fstat, no
## blocking read). timeout guards against a regression that reintroduces the
## blocking open.
fifo_frag="${test_dir}/fifo-fragments.d"
mkdir --parents -- "${fifo_frag}"
mkfifo -- "${fifo_frag}/f.cdx.json"
fifo_rc=0
printf '%s' "${merge_base}" | timeout --kill-after=10 10 "${merge_tool}" "${fifo_frag}" >/dev/null 2>&1 \
   || fifo_rc=$?
check "merge-tool: fifo fragment refused without hang (exit 1)" "${fifo_rc}" "1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
