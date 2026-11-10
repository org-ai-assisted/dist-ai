#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-encrypted 'rsync-delete-versions': the download-server pruning script
## that archives old release versions by deleting their LARGE files (over 1 MiB
## and not a kept sidecar) while KEEPING the small sidecars (SBOM, signatures,
## hash lists, buildinfo, torrents) and the version directory.
##
## The script is source-able (was_executed guard, strict confined to main()), so
## this test sources it and drives the pure prune_version_dir directly, and also
## RUNS the whole script against a temp tree (RSYNC_DELETE_BASE_DIR).
##
## SAFETY (this drives a DESTRUCTIVE script): the stubbed safe-rm REFUSES any
## path outside the per-run temp tree, TMPDIR is redirected under that tree so
## the subject's own mktemp cannot escape it, and positional args are cleared so
## a (stale) subject sourced at the top cannot inherit a '--force'. Never a real
## /var/rsync, no root, no network. A missing subject is an OPTIONAL target ->
## SKIP (77); a missing check_runtime.bsh is a HARD FAIL (exit 1).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Clear positional args: a stale subject that still runs main "$@" at top level
## must not inherit a '--force' through 'source' when this case is invoked with
## arguments.
set --

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
## Confine the test: safe-rm may only touch paths at or under this root, and the
## subject's own mktemp lands here too (TMPDIR), so nothing can escape the tree.
export RDV_TEST_CONFINE="${test_dir}"
export TMPDIR="${test_dir}/tmp"
## test_dir already exists (mktemp, 0700); --parents only creates the deepest
## 'tmp', which --mode sets -- the SC2174 parent-perms caveat does not apply.
# shellcheck disable=SC2174
mkdir --mode=0700 --parents -- "${TMPDIR}"

## A stubbed safe-rm set up BEFORE the cleanup trap (so the trap needs no rm
## fallback). It REFUSES any argument not under RDV_TEST_CONFINE, so even a
## misbehaving subject that passes a real path (e.g. /var/rsync) deletes
## nothing; within the tree it deletes for real so --force cases are exercised.
stub_bin="${test_dir}/bin"
mkdir --parents -- "${stub_bin}"
cat > "${stub_bin}/safe-rm" <<'STUB'
#!/bin/bash
## Canonicalize both the confine root and each argument so a '..' component or a
## symlink cannot escape the tree via a plain prefix match; delete only the
## resolved real path, and only when it is at or under the real confine root.
confine="$(realpath --canonicalize-missing -- "${RDV_TEST_CONFINE}")"
for arg in "$@"; do
   case "${arg}" in
      --*) continue ;;
   esac
   real="$(realpath --canonicalize-missing -- "${arg}")"
   case "${real}" in
      "${confine}"|"${confine}"/*)
         rm --force --recursive -- "${real}" ;;
      *)
         printf '%s\n' "stub safe-rm: REFUSING path outside test tree: ${arg} -> ${real}" >&2
         exit 1 ;;
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

## Build a version directory with the standard mix of big files + small
## sidecars (a >1M SBOM among them).
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

## ===== source-ability, verified in a PROBE subprocess =====
## A subject that exits on source, or leaks ANY strict option / EXIT trap into a
## non-strict caller, or fails to define the functions, must FAIL this test --
## not kill it or false-pass it. The probe sources the subject in a fresh
## (errexit-off) shell, prints a sentinel only if the source RETURNED, then
## checks every option and the functions. Only a clean probe lets the test
## source the subject in its own shell below.
probe="${test_dir}/source-probe.sh"
cat > "${probe}" <<'PROBE'
#!/bin/bash
source "$1"
printf '%s\n' 'SOURCE_RETURNED'
rc=0
[ "$(type -t main)" = function ] || { printf '%s\n' 'NO_MAIN'; rc=1; }
[ "$(type -t prune_version_dir)" = function ] || { printf '%s\n' 'NO_PRUNE'; rc=1; }
for opt in errexit nounset pipefail errtrace; do
   if [[ -o "${opt}" ]]; then printf '%s\n' "LEAK_${opt}"; rc=1; fi
done
if shopt -q inherit_errexit; then printf '%s\n' 'LEAK_inherit_errexit'; rc=1; fi
[ -z "$(trap -p EXIT)" ] || { printf '%s\n' 'LEAK_EXIT_TRAP'; rc=1; }
exit "${rc}"
PROBE
probe_rc=0
probe_out="$(bash "${probe}" "${subject}")" || probe_rc=$?
check "source returns without exiting" \
   "$(case "${probe_out}" in *SOURCE_RETURNED*) printf '%s' yes ;; *) printf '%s' no ;; esac)" "yes"
check "source defines fns + leaks no strict option/trap (probe rc 0)" "${probe_rc}" "0"

## Source the (probe-verified source-safe) subject to drive the pure function.
# shellcheck disable=SC1090
source "${subject}"

## ===== prune_version_dir (pure): the keep/delete filter =====
v="${test_dir}/unit/18.5.0.0"
make_version "${v}"
dry_out="$(prune_version_dir "${v}" true)"
check "prune dry-run lists Whonix.iso"      "$(printf '%s' "${dry_out}" | grep -c "Whonix.iso'")" "1"
check "prune dry-run lists Whonix.qcow2.xz" "$(printf '%s' "${dry_out}" | grep -c 'Whonix.qcow2.xz')" "1"
check "prune dry-run deletes nothing"       "$(present "${v}")" \
   "README.txt Whonix.cdx.json Whonix.dm-buildinfo Whonix.iso Whonix.iso.asc Whonix.iso.sig Whonix.qcow2.xz Whonix.sha512sums Whonix.torrent WhonixSetup.exe "
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
## One invocation per case; capture BOTH its output and status, and assert both.
run_main() {
   local base="$1"; shift
   run_rc=0
   run_out="$(RSYNC_DELETE_BASE_DIR="${base}" "${subject}" "$@" 2>&1)" || run_rc=$?
}

base1="${test_dir}/base1"
make_version "${base1}/iso/18.5.0.0"
run_main "${base1}"
check "main default is dry-run (rc 0)" "${run_rc}" "0"
check "main default deletes nothing"   "$(test -f "${base1}/iso/18.5.0.0/Whonix.iso" && printf '%s' yes || printf '%s' no)" "yes"

run_main "${base1}" --force
check "main --force rc 0" "${run_rc}" "0"
check "main --force removes the image"       "$(test -e "${base1}/iso/18.5.0.0/Whonix.iso" && printf '%s' yes || printf '%s' no)" "no"
check "main --force keeps the SBOM sidecar"  "$(test -f "${base1}/iso/18.5.0.0/Whonix.cdx.json" && printf '%s' yes || printf '%s' no)" "yes"

## A whitelisted version is kept ENTIRELY (image kept even with --force).
base2="${test_dir}/base2"
make_version "${base2}/iso/18.0.9.5"
run_main "${base2}" --force
check "main skips whitelisted version (rc 0)" "${run_rc}" "0"
check "main skips whitelisted version (image kept)" "$(test -f "${base2}/iso/18.0.9.5/Whonix.iso" && printf '%s' yes || printf '%s' no)" "yes"
check "main reports the whitelist skip" "$(printf '%s' "${run_out}" | grep -c 'Skipping whitelisted version')" "1"

## The reserved skip-dirs are left untouched.
base3="${test_dir}/base3"
make_version "${base3}/developer-meta-files/18.5.0.0"
run_main "${base3}" --force
check "main leaves developer-meta-files untouched (rc 0)" "${run_rc}" "0"
check "main leaves developer-meta-files untouched (image kept)" "$(test -f "${base3}/developer-meta-files/18.5.0.0/Whonix.iso" && printf '%s' yes || printf '%s' no)" "yes"

## A TRAILING-SLASH base_dir must still skip libvirt/test-ssh and prune normally
## (base_dir is canonicalized) -- not abort treating 'test-ssh' as a bad version.
base6="${test_dir}/base6"
make_version "${base6}/ova/9.9.9"
mkdir --parents -- "${base6}/libvirt/test-ssh"
printf '%s\n' 'x' > "${base6}/libvirt/test-ssh/keep"
run_main "${base6}/" --force
check "main with trailing-slash base prunes (rc 0)" "${run_rc}" "0"
check "main skips libvirt/test-ssh (file kept)" "$(test -f "${base6}/libvirt/test-ssh/keep" && printf '%s' yes || printf '%s' no)" "yes"
check "main with trailing-slash base removes the image" "$(test -e "${base6}/ova/9.9.9/Whonix.iso" && printf '%s' yes || printf '%s' no)" "no"

## A version directory whose name is not digits-and-dots is rejected (rc 1).
base4="${test_dir}/base4"
mkdir --parents -- "${base4}/iso/not-a-version"
dd if=/dev/zero of="${base4}/iso/not-a-version/big.iso" bs=1024k count=2 status=none
run_main "${base4}" --force
check "main rejects a non-numeric version name (rc 1)" "${run_rc}" "1"
check "main does not delete under a rejected name" "$(test -f "${base4}/iso/not-a-version/big.iso" && printf '%s' yes || printf '%s' no)" "yes"

## Nothing large -> the explicit message, in the SAME run, and the sidecar stays.
base5="${test_dir}/base5"
mkdir --parents -- "${base5}/iso/18.5.0.0"
touch -- "${base5}/iso/18.5.0.0/Whonix.sha512sums"
run_main "${base5}" --force
check "main no-deletion case rc 0" "${run_rc}" "0"
check "main reports no deletions when only sidecars exist" \
   "$(printf '%s' "${run_out}" | grep -c 'No files were deleted')" "1"
check "main keeps the sidecar in the no-deletion case" \
   "$(test -f "${base5}/iso/18.5.0.0/Whonix.sha512sums" && printf '%s' yes || printf '%s' no)" "yes"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
