#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## initializer-dist chroot-scripts-post.d '76_sbom': the image-level SBOM hook.
##
## Drives the REAL hook end-to-end (it has no functions to source -- a short,
## top-to-bottom script), with its genuine externals stubbed so the run is
## offline, deterministic and rootless:
##   - debsbom  : the SBOM generator. Stubbed to RECORD its argv and create the
##                --out file (so the subject's follow-up mtime pin has a target),
##                never a real dpkg scan.
##   - uuidgen  : stubbed to a fixed UUID + record argv, so the serial-derivation
##                wiring (os-release -> --name) is asserted without depending on
##                a real uuid.
##   - dpkg     : stubbed to a fixed --print-architecture.
## os-release and the output dir are redirected to tmpdir fixtures via the
## subject's SBOM_OSRELEASE_FILE / SBOM_OUTPUT_DIR seams.
##
## Asserts: the reproducibility contract (pinned schema 1.6, serial from
## uuidgen, timestamp from SOURCE_DATE_EPOCH, mtime pin), the os-release-derived
## root component identity + serial name, and the two skip paths (SKIP_SCRIPTS
## membership, and a missing SOURCE_DATE_EPOCH -> graceful no-op, no SBOM).
##
## A missing subject is a HARD FAIL (exit 1), never a skip. No root, no network.

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

## --- stub tree: record argv per command; debsbom also creates its --out file ---
mockbin="${test_dir}/bin"
rec="${test_dir}/rec"
mkdir --parents -- "${mockbin}" "${rec}"

## debsbom: record argv, honor --out by creating that file (a minimal valid
## CycloneDX stub), exit 0. Never scans anything.
cat > "${mockbin}/debsbom" <<'EOF'
#!/bin/bash
printf '%q ' "$@" >> "${REC_DIR}/debsbom.argv"
printf '\n' >> "${REC_DIR}/debsbom.argv"
out=""
while [ "$#" -gt 0 ]; do
   if [ "$1" = "--out" ]; then out="$2"; shift 2; continue; fi
   shift
done
if [ -n "${out}" ]; then
   printf '%s\n' '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}' > "${out}"
fi
exit 0
EOF

## uuidgen: fixed UUID, record argv (to assert the --name the subject builds).
cat > "${mockbin}/uuidgen" <<'EOF'
#!/bin/bash
printf '%q ' "$@" >> "${REC_DIR}/uuidgen.argv"
printf '\n' >> "${REC_DIR}/uuidgen.argv"
printf '%s\n' "11111111-2222-5333-8444-555555555555"
EOF

## dpkg: fixed architecture.
cat > "${mockbin}/dpkg" <<'EOF'
#!/bin/bash
printf '%q ' "$@" >> "${REC_DIR}/dpkg.argv"
printf '\n' >> "${REC_DIR}/dpkg.argv"
[ "$1" = "--print-architecture" ] && printf '%s\n' "amd64"
exit 0
EOF
chmod +x -- "${mockbin}/debsbom" "${mockbin}/uuidgen" "${mockbin}/dpkg"

## os-release fixture: a derivative identity (NOT the CI host's), so the derived
## serial name and root component are deterministic.
osrel="${test_dir}/os-release"
printf '%s\n' 'ID=kicksecure' 'VERSION_ID=18' 'PRETTY_NAME="Kicksecure 18"' > "${osrel}"

outdir="${test_dir}/out"
sbom_out="${outdir}/system.cdx.json"
sde=1712345678
## SOURCE_DATE_EPOCH 1712345678 -> 2024-04-05T19:34:38+00:00 (UTC, LC_ALL=C).
want_ts="2024-04-05T19:34:38+00:00"
want_serial="11111111-2222-5333-8444-555555555555"

## Run the real hook as a fresh process with the externals stubbed and the seams
## pointed at fixtures. Returns the hook's exit code; its set -x trace is dropped.
run_hook() {
   REC_DIR="${rec}" PATH="${mockbin}:${PATH}" \
      SBOM_OUTPUT_DIR="${outdir}" SBOM_OSRELEASE_FILE="${osrel}" \
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

## True if debsbom's recorded argv contains the consecutive sequence of args.
debsbom_called_with() {
   local needle
   needle="$(printf '%q ' "$@")"
   [ -f "${rec}/debsbom.argv" ] && grep --quiet --fixed-strings -- "${needle}" "${rec}/debsbom.argv"
}
yn() { if "$@"; then printf '%s' yes; else printf '%s' no; fi; }

## ===================== Case 1: happy path, reproducibility contract =====================
reset_state
rc=0
SOURCE_DATE_EPOCH="${sde}" run_hook || rc=$?
check "happy: hook exits 0" "${rc}" "0"
check "happy: SBOM written to seam output path" "$(yn test -f "${sbom_out}")" "yes"
check "happy: debsbom was invoked" "$(yn test -f "${rec}/debsbom.argv")" "yes"
check "happy: CycloneDX only (--sbom-type cdx)" "$(yn debsbom_called_with --sbom-type cdx)" "yes"
check "happy: schema pinned to 1.6" "$(yn debsbom_called_with --cdx-schema-version 1.6)" "yes"
check "happy: serial pinned from uuidgen" "$(yn debsbom_called_with --cdx-serialnumber "${want_serial}")" "yes"
check "happy: timestamp from SOURCE_DATE_EPOCH" "$(yn debsbom_called_with --timestamp "${want_ts}")" "yes"
check "happy: root component name from os-release ID" "$(yn debsbom_called_with --distro-name kicksecure)" "yes"
check "happy: root component version from os-release VERSION_ID" "$(yn debsbom_called_with --distro-version 18)" "yes"
check "happy: output path passed via --out" "$(yn debsbom_called_with --out "${sbom_out}")" "yes"
## serial derivation: uuidgen --name is built from os-release id + version + arch.
uuidgen_name="no"
[ -f "${rec}/uuidgen.argv" ] && grep --quiet --fixed-strings -- "$(printf '%q ' --name sbom:kicksecure:18:amd64)" "${rec}/uuidgen.argv" && uuidgen_name="yes"
check "happy: uuidgen name = sbom:<id>:<version>:<arch>" "${uuidgen_name}" "yes"
## mtime pinned to SOURCE_DATE_EPOCH (reproducible reimage preserves regular-file mtimes).
check "happy: output mtime pinned to SOURCE_DATE_EPOCH" "$(stat -c %Y -- "${sbom_out}")" "${sde}"

## ===================== Case 2: SOURCE_DATE_EPOCH unset -> graceful skip =====================
reset_state
rc=0
## Unset in a subshell: a CI that exports SOURCE_DATE_EPOCH would otherwise leak it into
## run_hook and make this case generate an SBOM instead of exercising the missing-epoch path.
( unset SOURCE_DATE_EPOCH; run_hook ) || rc=$?
check "no-epoch: hook exits 0 (graceful)" "${rc}" "0"
check "no-epoch: debsbom NOT invoked" "$(yn test -f "${rec}/debsbom.argv")" "no"
check "no-epoch: no SBOM written" "$(yn test -f "${sbom_out}")" "no"

## ===================== Case 3: SKIP_SCRIPTS membership -> skip =====================
reset_state
rc=0
SOURCE_DATE_EPOCH="${sde}" SKIP_SCRIPTS='20_sanity 76_sbom 80_cleanup' run_hook || rc=$?
check "skip-scripts: hook exits 0" "${rc}" "0"
check "skip-scripts: debsbom NOT invoked" "$(yn test -f "${rec}/debsbom.argv")" "no"
check "skip-scripts: no SBOM written" "$(yn test -f "${sbom_out}")" "no"
## A longer name that merely contains the token is NOT a skip match (word, not substring).
reset_state
rc=0
SOURCE_DATE_EPOCH="${sde}" SKIP_SCRIPTS='76_sbom_extra' run_hook || rc=$?
check "skip-scripts: substring is not a match -> runs" "$(yn test -f "${rec}/debsbom.argv")" "yes"

## ================================ summary ================================
printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
