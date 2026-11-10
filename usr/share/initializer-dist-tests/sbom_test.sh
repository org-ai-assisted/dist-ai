#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## initializer-dist chroot-scripts-post.d '76_sbom': the image-level SBOM hook.
##
## It is a THIN, build-specific wrapper around the shared 'derivative-sbom'
## helper (whose generation logic is tested in helper-scripts-lib-tests/
## derivative_sbom_test.sh). This test drives the REAL hook end-to-end with
## derivative-sbom stubbed, and asserts ONLY the hook's own concerns:
##   - the reproducibility context: it calls derivative-sbom with --out at the
##     embedded path and --timestamp derived from SOURCE_DATE_EPOCH, then pins
##     the output mtime to SOURCE_DATE_EPOCH;
##   - the skip paths: SKIP_SCRIPTS membership, and a missing SOURCE_DATE_EPOCH
##     (-> no SBOM, since a wall-clock timestamp would break reproducible builds).
##
## A missing subject is a HARD FAIL (exit 1). No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v INITIALIZER_DIST_REPO ] || INITIALIZER_DIST_REPO=""

if [ -n "${INITIALIZER_DIST_REPO}" ]; then
   subject="${INITIALIZER_DIST_REPO}/usr/libexec/initializer-dist/chroot-scripts-post.d/76_sbom"
else
   subject='/usr/libexec/initializer-dist/chroot-scripts-post.d/76_sbom'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set INITIALIZER_DIST_REPO to an initializer-dist checkout, or install initializer-dist" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

## Stub derivative-sbom: record argv and honor --out by creating that file (so
## the hook's follow-up mtime pin has a target). Never a real dpkg scan.
mockbin="${test_dir}/bin"
rec="${test_dir}/rec"
mkdir --parents -- "${mockbin}" "${rec}"
cat > "${mockbin}/derivative-sbom" <<'EOF'
#!/bin/bash
printf '%q ' "$@" >> "${REC_DIR}/derivative-sbom.argv"
printf '\n' >> "${REC_DIR}/derivative-sbom.argv"
out=""
while [ "$#" -gt 0 ]; do
   if [ "$1" = "--out" ]; then out="$2"; shift 2; continue; fi
   shift
done
[ -z "${out}" ] || printf '%s\n' '{"bomFormat":"CycloneDX"}' > "${out}"
exit 0
EOF
chmod +x -- "${mockbin}/derivative-sbom"

outdir="${test_dir}/out"
sbom_out="${outdir}/system.cdx.json"
sde=1712345678
## SOURCE_DATE_EPOCH 1712345678 -> 2024-04-05T19:34:38+00:00 (UTC, LC_ALL=C).
want_ts="2024-04-05T19:34:38+00:00"

run_hook() {
   REC_DIR="${rec}" PATH="${mockbin}:${PATH}" SBOM_OUTPUT_DIR="${outdir}" \
      bash "${subject}" >/dev/null 2>&1
}
reset_state() {
   safe-rm --recursive --force -- "${rec}" "${outdir}"
   mkdir --parents -- "${rec}"
}

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
called_with() {
   [ -f "${rec}/derivative-sbom.argv" ] \
      && grep --quiet --fixed-strings -- "$(printf '%q ' "$@")" "${rec}/derivative-sbom.argv"
}
yn() { if "$@"; then printf '%s' yes; else printf '%s' no; fi; }

## ===================== happy path =====================
reset_state
rc=0
SOURCE_DATE_EPOCH="${sde}" run_hook || rc=$?
check "happy: hook exits 0" "${rc}" "0"
check "happy: delegates to derivative-sbom" "$(yn test -f "${rec}/derivative-sbom.argv")" "yes"
check "happy: writes to the embedded path via --out" "$(yn called_with --out "${sbom_out}")" "yes"
check "happy: timestamp pinned from SOURCE_DATE_EPOCH" "$(yn called_with --timestamp "${want_ts}")" "yes"
check "happy: SBOM present at output path" "$(yn test -f "${sbom_out}")" "yes"
check "happy: output mtime pinned to SOURCE_DATE_EPOCH" "$(stat -c %Y -- "${sbom_out}")" "${sde}"

## ===================== SOURCE_DATE_EPOCH unset -> graceful skip =====================
reset_state
rc=0
## Unset in a subshell: a CI that exports SOURCE_DATE_EPOCH would otherwise leak it
## into run_hook and make this case generate an SBOM instead of exercising the skip.
( unset SOURCE_DATE_EPOCH; run_hook ) || rc=$?
check "no-epoch: hook exits 0 (graceful)" "${rc}" "0"
check "no-epoch: derivative-sbom NOT called" "$(yn test -f "${rec}/derivative-sbom.argv")" "no"
check "no-epoch: no SBOM written" "$(yn test -f "${sbom_out}")" "no"

## ===================== SKIP_SCRIPTS membership -> skip =====================
reset_state
rc=0
SOURCE_DATE_EPOCH="${sde}" SKIP_SCRIPTS='20_sanity 76_sbom 80_cleanup' run_hook || rc=$?
check "skip-scripts: hook exits 0" "${rc}" "0"
check "skip-scripts: derivative-sbom NOT called" "$(yn test -f "${rec}/derivative-sbom.argv")" "no"
## A longer name that merely contains the token is NOT a match (word, not substring).
reset_state
SOURCE_DATE_EPOCH="${sde}" SKIP_SCRIPTS='76_sbom_extra' run_hook || true
check "skip-scripts: substring is not a match -> runs" "$(yn test -f "${rec}/derivative-sbom.argv")" "yes"

## ================================ summary ================================
printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
