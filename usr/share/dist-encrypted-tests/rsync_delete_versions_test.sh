#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-encrypted 'rsync-delete-versions': the download-server pruning script
## that archives old release versions by deleting ONLY their large binary images
## (ISOs, disk/VM images, installers) while KEEPING the small files (SBOM,
## signatures, hash lists, buildinfo, torrents) and the version directory.
##
## The script is source-able (was_executed guard, strict confined to main()), so
## this test sources it and drives the pure function directly:
##   - prune_version_dir   deletes only >1M non-sidecar files in a version dir.
## It also RUNS the whole script against a temp tree (RSYNC_DELETE_BASE_DIR) in
## dry-run and with a stubbed safe-rm, to cover the whitelist, the skip-dirs, the
## version-name sanity guard, and the "no files" message.
##
## No root, no network, NEVER a real /var/rsync. A missing subject is an OPTIONAL
## target -> SKIP (77); a missing check_runtime.bsh is a HARD FAIL (exit 1).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v DIST_ENCRYPTED_REPO ] || DIST_ENCRYPTED_REPO=""
if [ -n "${DIST_ENCRYPTED_REPO}" ]; then
   subject="${DIST_ENCRYPTED_REPO}/usr/local/bin/rsync-delete-versions"
else
   subject='/usr/local/bin/rsync-delete-versions'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "rsync-delete-versions not readable at '${subject}' (set DIST_ENCRYPTED_REPO); skipping." >&2
   ## style-ok: allow-skip: dist-encrypted target unavailable (optional component checkout)
   exit 77
fi

## The subject sources check_runtime.bsh (was_executed) via HELPER_SCRIPTS_PATH;
## it is a REQUIRED dependency, so its absence is an environment bug, not a skip.
libdir="${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts"
if [ ! -r "${libdir}/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable under '${libdir}' (set HELPER_SCRIPTS_PATH)" >&2
   exit 1
fi
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH:-}"

test_dir="$(mktemp --directory)"

## A stubbed safe-rm recorder, set up BEFORE the cleanup trap so the trap can
## use safe-rm with no forbidden rm fallback. It also makes 'command -v safe-rm'
## succeed and lets a --force run delete for real within the temp tree.
stub_bin="${test_dir}/bin"
mkdir --parents -- "${stub_bin}"
cat > "${stub_bin}/safe-rm" <<'STUB'
#!/bin/bash
for arg in "$@"; do
   case "${arg}" in
      --*) ;;
      *) rm --force --recursive -- "${arg}" ;;
   esac
done
STUB
chmod +x -- "${stub_bin}/safe-rm"
export PATH="${stub_bin}:${PATH}"

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

## Build a version directory with the standard mix of big images + small
## sidecars (a >1M SBOM among them). Echoed name of the big files for assertions.
make_version() {
   local dir="$1"
   mkdir --parents -- "${dir}"
   dd if=/dev/zero of="${dir}/Whonix.iso" bs=1024k count=2 status=none
   dd if=/dev/zero of="${dir}/Whonix.qcow2.xz" bs=1024k count=2 status=none
   dd if=/dev/zero of="${dir}/WhonixSetup.exe" bs=1024k count=2 status=none
   ## A large (>1M) SBOM: must be KEPT by the name allowlist despite its size.
   dd if=/dev/zero of="${dir}/Whonix.cdx.json" bs=1024k count=2 status=none
   touch -- "${dir}/Whonix.iso.asc"
   touch -- "${dir}/Whonix.iso.sig"
   touch -- "${dir}/Whonix.sha512sums"
   touch -- "${dir}/Whonix.dm-buildinfo"
   touch -- "${dir}/Whonix.torrent"
   printf '%s\n' 'stray' > "${dir}/README.txt"
}

present() { find "$1" -maxdepth 1 -type f -printf '%f\n' | sort | tr '\n' ' '; }

## ===== source-ability: functions defined, no auto-run, no strict leak =====
# shellcheck disable=SC1090
src_out="$(source "${subject}" 2>&1)" \
   || { printf '%s\n' "FATAL: sourcing '${subject}' failed: ${src_out}" >&2; exit 1; }
check "sourcing does not auto-run (no output)" "${src_out}" ""
# shellcheck disable=SC1090
source "${subject}"
check "main is defined"               "$(type -t main)"               "function"
check "prune_version_dir is defined"  "$(type -t prune_version_dir)"  "function"
## No strict-mode leak: a fresh shell (bash <script>, errexit OFF by default)
## that sources the subject must survive a 'false' -- a leaked 'set -o errexit'
## would abort it. A probe script gives that shell without toggling errexit here.
leak_probe="${test_dir}/leak-probe.sh"
## '$1' is literal: it is the generated probe's own argument, not expanded here.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/bash' 'source "$1"' 'false' 'true' > "${leak_probe}"
leak_rc=0
bash "${leak_probe}" "${subject}" || leak_rc=$?
check "no strict-mode leak on source" "${leak_rc}" "0"

## ===== prune_version_dir (pure): the keep/delete filter =====
v="${test_dir}/unit/18.5.0.0"
make_version "${v}"
## Dry-run: lists the big binaries, deletes nothing.
dry_out="$(prune_version_dir "${v}" true)"
check "prune dry-run lists Whonix.iso"      "$(printf '%s' "${dry_out}" | grep -c "Whonix.iso'")" "1"
check "prune dry-run lists Whonix.qcow2.xz" "$(printf '%s' "${dry_out}" | grep -c 'Whonix.qcow2.xz')" "1"
check "prune dry-run deletes nothing"       "$(present "${v}")" \
   "README.txt Whonix.cdx.json Whonix.dm-buildinfo Whonix.iso Whonix.iso.asc Whonix.iso.sig Whonix.qcow2.xz Whonix.sha512sums Whonix.torrent WhonixSetup.exe "
## Force: big binaries gone; the >1M SBOM, every sidecar, the stray small file,
## and the directory itself remain.
prune_version_dir "${v}" false >/dev/null
check "prune --force keeps sidecars + large SBOM + stray, drops images" "$(present "${v}")" \
   "README.txt Whonix.cdx.json Whonix.dm-buildinfo Whonix.iso.asc Whonix.iso.sig Whonix.sha512sums Whonix.torrent "
check "prune --force keeps the version directory" "$(test -d "${v}" && printf '%s' yes || printf '%s' no)" "yes"

## -maxdepth 1: a large file nested in a SUBdirectory is NOT pruned (artifacts
## sit flat in the version dir; this also denies the parent-dir symlink race a
## traversable intermediate directory).
nested="${test_dir}/nested/18.6.0.0"
mkdir --parents -- "${nested}/sub"
dd if=/dev/zero of="${nested}/sub/deep.iso" bs=1024k count=2 status=none
prune_version_dir "${nested}" false >/dev/null
check "prune does not descend into subdirectories (maxdepth 1)" \
   "$(test -f "${nested}/sub/deep.iso" && printf '%s' yes || printf '%s' no)" "yes"

## ===== whole script via RSYNC_DELETE_BASE_DIR (temp tree, never /var/rsync) =====
run_main() {
   ## $1 = base dir, rest = args; prints combined output, sets global run_rc.
   local base="$1"; shift
   run_rc=0
   RSYNC_DELETE_BASE_DIR="${base}" "${subject}" "$@" 2>&1 || run_rc=$?
}

## Default is dry-run: nothing is removed.
base1="${test_dir}/base1"
make_version "${base1}/iso/18.5.0.0"
run_main "${base1}"
check "main default is dry-run (rc 0)" "${run_rc}" "0"
check "main default deletes nothing"   "$(test -f "${base1}/iso/18.5.0.0/Whonix.iso" && printf '%s' yes || printf '%s' no)" "yes"

## --force prunes images, keeps the sidecars.
run_main "${base1}" --force
check "main --force rc 0" "${run_rc}" "0"
check "main --force removes the image"       "$(test -e "${base1}/iso/18.5.0.0/Whonix.iso" && printf '%s' yes || printf '%s' no)" "no"
check "main --force keeps the SBOM sidecar"  "$(test -f "${base1}/iso/18.5.0.0/Whonix.cdx.json" && printf '%s' yes || printf '%s' no)" "yes"

## A whitelisted version is kept ENTIRELY (image not removed even with --force).
base2="${test_dir}/base2"
make_version "${base2}/iso/18.0.9.5"
run_main "${base2}" --force
check "main skips whitelisted version (image kept)" "$(test -f "${base2}/iso/18.0.9.5/Whonix.iso" && printf '%s' yes || printf '%s' no)" "yes"
check "main reports the whitelist skip" "$(printf '%s' "${run_output:=$(RSYNC_DELETE_BASE_DIR="${base2}" "${subject}" --force 2>&1)}" | grep -c 'Skipping whitelisted version')" "1"

## The reserved skip-dirs are left untouched.
base3="${test_dir}/base3"
make_version "${base3}/developer-meta-files/18.5.0.0"
run_main "${base3}" --force
check "main leaves developer-meta-files untouched" "$(test -f "${base3}/developer-meta-files/18.5.0.0/Whonix.iso" && printf '%s' yes || printf '%s' no)" "yes"

## A version directory whose name is not digits-and-dots is rejected (safety).
base4="${test_dir}/base4"
mkdir --parents -- "${base4}/iso/not-a-version"
touch -- "${base4}/iso/not-a-version/x"
run_main "${base4}" --force
check "main rejects a non-numeric version name (rc 1)" "${run_rc}" "1"

## Nothing to prune -> the explicit message.
base5="${test_dir}/base5"
mkdir --parents -- "${base5}/iso/18.5.0.0"
touch -- "${base5}/iso/18.5.0.0/Whonix.sha512sums"
run_main "${base5}" --force
check "main reports no deletions when only sidecars exist" \
   "$(printf '%s' "${run_output_none:=$(RSYNC_DELETE_BASE_DIR="${base5}" "${subject}" --force 2>&1)}" | grep -c 'No files were deleted')" "1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
