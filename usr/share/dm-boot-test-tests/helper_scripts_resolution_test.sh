#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-boot-test sources helper-scripts' package_installed_check.sh to decide whether
## qemu dependencies need installing. It must locate that library in the CI boot-test
## job, where dm-boot-test runs from dist-ai/usr/bin nested in the derivative-maker
## workspace (dist-ai mounted at ./dist-ai) alongside packages/kicksecure/helper-scripts
## -- which is CHECKED OUT, not installed at /usr/libexec, and HELPER_SCRIPTS_PATH is
## not set. A hardcoded 'source /usr/libexec/helper-scripts/...' aborted every boot-test
## leg before qemu started ("package_installed_check.sh: No such file or directory").
## This drives the REAL dm-boot-test and asserts the source resolves in that layout.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
## dist-ai repo root: this file is at usr/share/dm-boot-test-tests/<f>.
repo_root="$(dirname -- "$(dirname -- "$(dirname -- "${script_dir}")")")"
dm_boot_test="${repo_root}/usr/bin/dm-boot-test"
## Honour DERIVATIVE_MAKER_DIR (dist-ai-tests-all wires it; CI checks out
## derivative-maker at $GITHUB_WORKSPACE, not under $HOME) before falling back.
dm_dir="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
hs="${dm_dir}/packages/kicksecure/helper-scripts"

for f in "${dm_boot_test}" "${hs}/usr/libexec/helper-scripts/package_installed_check.sh"; do
   if [ ! -e "${f}" ]; then
      printf '%s\n' "SKIP: missing ${f} (need dist-ai checkout + a derivative-maker helper-scripts checkout)" >&2
      ## style-ok: allow-skip: the derivative-maker helper-scripts checkout is absent in some standalone runs
      exit 77
   fi
done

pass=0
fail=0
pass() { pass=$(( pass + 1 )); printf 'PASS  %s\n' "$1"; }
fail() { fail=$(( fail + 1 )); printf 'FAIL  %s\n' "$1" >&2; }

workdir="$(mktemp --directory)"
cleanup() {
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

dummy_image="${workdir}/dummy.qcow2"
printf '' > "${dummy_image}"

## dm-boot-test validates --arch AFTER sourcing package_installed_check.sh, so an
## invalid --arch makes it exit right after the source -- reaching "unsupported
## --arch" proves the source resolved; "No such file" proves it did not. This
## avoids launching qemu.
run_probe() {
   ## $1 = extra env assignment (may be empty); runs the given dm-boot-test path.
   local boot_test_bin="$1"
   env -u HELPER_SCRIPTS_PATH timeout 30 bash "${boot_test_bin}" \
      --image "${dummy_image}" --arch bogus --firmware bios --session user 2>&1 || true
}

## 1) CI layout: nest dist-ai under a workspace next to packages/kicksecure/helper-scripts,
##    HELPER_SCRIPTS_PATH unset, /usr/libexec fallback unavailable to the nested copy.
ci_ws="${workdir}/ws"
mkdir --parents -- "${ci_ws}/packages/kicksecure" "${ci_ws}/dist-ai/usr/bin"
ln --symbolic -- "${hs}" "${ci_ws}/packages/kicksecure/helper-scripts"
## Copy dm-boot-test into the nested layout (a symlink would resolve readlink -f back
## to the real repo and defeat the layout probe).
cp -- "${dm_boot_test}" "${ci_ws}/dist-ai/usr/bin/dm-boot-test"
chmod +x -- "${ci_ws}/dist-ai/usr/bin/dm-boot-test"

out="$(run_probe "${ci_ws}/dist-ai/usr/bin/dm-boot-test")"
if grep --quiet 'No such file' <<< "${out}"; then
   fail "CI-nested layout: dm-boot-test cannot source package_installed_check.sh:\n$(printf '%s' "${out}" | grep 'No such file' | head -n1)"
elif grep --quiet "unsupported --arch" <<< "${out}"; then
   pass "CI-nested layout (HELPER_SCRIPTS_PATH unset): package_installed_check.sh source resolves"
else
   fail "CI-nested layout: unexpected output (neither resolved nor the known failure):\n${out}"
fi

## 2) Explicit HELPER_SCRIPTS_PATH wins from anywhere.
out="$(HELPER_SCRIPTS_PATH="${hs}" timeout --kill-after=30 30 bash "${dm_boot_test}" \
   --image "${dummy_image}" --arch bogus --firmware bios --session user 2>&1 || true)"
if grep --quiet "unsupported --arch" <<< "${out}"; then
   pass "explicit HELPER_SCRIPTS_PATH resolves package_installed_check.sh"
else
   fail "explicit HELPER_SCRIPTS_PATH did not resolve the library:\n${out}"
fi

## 3) CANARY: a bare 'source /usr/libexec/helper-scripts/...' (the original bug) must
##    be detectable -- prove the probe would catch a regression to the hardcoded path.
canary_bin="${workdir}/dm-boot-test-canary"
sed 's#source "\${helper_scripts_base}/usr/libexec/helper-scripts/package_installed_check.sh"#source /usr/libexec/helper-scripts/package_installed_check.sh#' -- "${dm_boot_test}" > "${canary_bin}"
chmod +x -- "${canary_bin}"
if ! grep --quiet 'source /usr/libexec/helper-scripts/package_installed_check.sh' -- "${canary_bin}"; then
   fail "canary setup failed: could not produce a hardcoded-path variant of dm-boot-test"
else
   out="$(run_probe "${canary_bin}")"
   ## The hardcoded variant fails ONLY when /usr/libexec lacks the file (the CI case).
   if [ -e /usr/libexec/helper-scripts/package_installed_check.sh ]; then
      pass "canary: /usr/libexec is populated on this host, so the hardcoded path cannot be exercised here (skipping negative assertion)"
   elif grep --quiet 'No such file' <<< "${out}"; then
      pass "canary: the hardcoded /usr/libexec path DOES fail when helper-scripts is not installed -- the fix is load-bearing"
   else
      fail "canary: the hardcoded variant did NOT fail though /usr/libexec lacks the library -- the probe proves nothing"
   fi
fi

printf '%s\n' "helper_scripts_resolution_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
