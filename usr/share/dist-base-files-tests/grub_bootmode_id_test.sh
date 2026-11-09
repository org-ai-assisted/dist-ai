#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 10_00_linux_dist must scope the simple-entry GRUB --id by boot_mode_id, so
## USER / SYSMAINT / REMOVE get DISTINCT ids. A shared id ('gnulinux-simple-<dev>'
## for every mode, the pre-fix behaviour) makes id-based boot-mode selection
## (grub-editenv next_entry / default by id) resolve to the FIRST matching entry
## only, so the installed system can never be driven into SYSMAINT by id.
##
## This renders the REAL engine for each token and asserts the emitted id. The
## emit-check suite proves the wrappers EXPORT the tokens (stubbed engine); this
## proves the engine CONSUMES them into a distinct id -- the half a stubbed engine
## cannot see. Canary: on the pre-fix engine every mode renders 'gnulinux-simple-*',
## so the per-mode prefix assertions all fail RED.
##
## Needs grub-mkconfig_lib (grub-common) + bwrap; absent -> SKIP 77 (the dist-ai
## contract for an unavailable runtime). No root, no network, no real device: a
## stub grub-probe answers every query and a fake /boot supplies one kernel.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.bsh

[ -v DIST_BASE_FILES_REPO ] || DIST_BASE_FILES_REPO=""

if [ -n "${DIST_BASE_FILES_REPO}" ]; then
   engine="${DIST_BASE_FILES_REPO}/etc/grub.d/10_00_linux_dist"
else
   engine='/etc/grub.d/10_00_linux_dist'
fi

grub_lib='/usr/share/grub/grub-mkconfig_lib'

missing=''
[ -r "${engine}" ]    || missing="${missing} engine(${engine})"
[ -r "${grub_lib}" ]  || missing="${missing} grub-mkconfig_lib"
has bwrap             || missing="${missing} bwrap"
if [ -n "${missing}" ]; then
   printf '%s\n' "SKIP: missing runtime:${missing}" >&2
   ## style-ok: allow-skip: grub-common/bwrap are an unavailable runtime in the core dist-ai CI job
   exit 77
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  ## reached via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

stub_dir="${work_dir}/stub"
fake_boot="${work_dir}/boot"
mkdir --parents -- "${stub_dir}" "${fake_boot}"
touch -- "${fake_boot}/vmlinuz-1.0.0-test" "${fake_boot}/initrd.img-1.0.0-test"

## Answer every grub-probe --target query with a fixed, plausible value so the
## engine reaches the id line without touching a real device. Literal heredoc:
## the stub body must reach the file verbatim.
cat > "${stub_dir}/grub-probe" <<'STUB'
#!/bin/sh
t=''
for a in "$@"; do case "$a" in --target=*) t="${a#--target=}";; esac; done
case "$t" in
  fs_uuid) echo "1111-2222-3333-4444";;
  hints_string) echo "--hint-bios=hd0,gpt2";;
  device) echo "/dev/sda2";;
  drive) echo "(hd0)";;
  partmap) echo "gpt";;
  fs) echo "ext2";;
  *) echo "";;
esac
STUB
cat > "${stub_dir}/grub-mkrelpath" <<'STUB'
#!/bin/sh
echo "${1:-/}"
STUB
chmod 0755 -- "${stub_dir}/grub-probe" "${stub_dir}/grub-mkrelpath"

render_id() {
   local mode="$1"
   local extra=()
   [ "${mode}" = 'UNSET' ] || extra=( "boot_mode_id=${mode}" )
   bwrap --dev-bind / / --bind "${fake_boot}" /boot \
      -- env --ignore-environment \
      PATH="${stub_dir}:/usr/sbin:/usr/bin:/sbin:/bin" \
      pkgdatadir=/usr/share/grub \
      datarootdir=/usr/share \
      make_boot_entry=true "${extra[@]}" \
      GRUB_DEVICE=/dev/sda2 GRUB_DEVICE_UUID=1111-2222-3333-4444 \
      GRUB_DISABLE_LINUX_UUID=false GRUB_DISABLE_RECOVERY=true \
      GRUB_DISABLE_SUBMENU=false GRUB_DISTRIBUTOR=Kicksecure \
      GRUB_CMDLINE_LINUX='' GRUB_CMDLINE_LINUX_DEFAULT='' \
      GRUB_GFXPAYLOAD_LINUX='' GRUB_TIMEOUT=5 \
      "${engine}" 2>/dev/null \
      | grep --only-matching --extended-regexp "gnulinux-[^' ]+" | head -n 1 \
      || true
   ## '|| true': no id is a legitimate outcome (a mode the engine emits nothing for);
   ## under pipefail+inherit_errexit a no-match grep (exit 1) would otherwise abort the
   ## caller's command substitution and skip the '[ -z id ]' diagnostic + remaining modes.
}

fail=0
checks=0
assert_prefix() {
   local mode="$1" want="$2" id
   id="$(render_id "${mode}")"
   checks=$(( checks + 1 ))
   if [ -z "${id}" ]; then
      printf '%s\n' "FAIL  boot_mode_id=${mode}: engine emitted no id"
      fail=1
   elif [ "${id#"${want}"}" = "${id}" ]; then
      printf '%s\n' "FAIL  boot_mode_id=${mode}: id '${id}' lacks prefix '${want}'"
      fail=1
   else
      printf '%s\n' "PASS  boot_mode_id=${mode}: id '${id}'"
   fi
}

## Unset falls back to 'simple' (non-wrapper invocation stays valid); each mode
## token yields its own distinct prefix.
assert_prefix UNSET           'gnulinux-simple-'
assert_prefix user            'gnulinux-user-'
assert_prefix sysmaint        'gnulinux-sysmaint-'
assert_prefix remove-sysmaint 'gnulinux-remove-sysmaint-'

printf '%s\n' "" "${checks} checks, ${fail} failed"
[ "${fail}" -eq 0 ]
