#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 10_00_linux_dist (simple entry) AND 10_50_linux_dist_advanced (advanced submenu
## + per-kernel entries) must scope EVERY GRUB --id by boot_mode_id, so USER /
## SYSMAINT / REMOVE / LIVE get DISTINCT ids across both engines. A shared id for
## every mode (the pre-fix behaviour: 'gnulinux-simple-<dev>' simple,
## 'gnulinux-advanced-<dev>' submenu) makes id-based boot-mode selection
## (grub-editenv next_entry / default by id) resolve to the FIRST matching entry
## only, so the installed system can never be driven into SYSMAINT by id.
##
## This renders BOTH REAL engines for each token and asserts the emitted id(s). The
## emit-check suite proves the wrappers EXPORT the tokens (stubbed engine); this
## proves the engines CONSUME them into distinct ids -- the half a stubbed engine
## cannot see. Canary: on the pre-fix engines every mode renders 'gnulinux-simple-*'
## / 'gnulinux-advanced-*', so the per-mode prefix assertions fail RED.
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
   engine_advanced="${DIST_BASE_FILES_REPO}/etc/grub.d/10_50_linux_dist_advanced"
else
   engine='/etc/grub.d/10_00_linux_dist'
   engine_advanced='/etc/grub.d/10_50_linux_dist_advanced'
fi

grub_lib='/usr/share/grub/grub-mkconfig_lib'

missing=''
[ -r "${engine}" ]          || missing="${missing} engine(${engine})"
[ -r "${engine_advanced}" ] || missing="${missing} engine(${engine_advanced})"
[ -r "${grub_lib}" ]        || missing="${missing} grub-mkconfig_lib"
has bwrap                   || missing="${missing} bwrap"
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

## Render one engine under the stubbed grub environment for a boot_mode_id token
## (UNSET = export nothing, exercising the ':-simple' fallback) and print every
## emitted menuentry/submenu --id, one per line.
render_ids() {
   local engine_path="$1" mode="$2"
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
      "${engine_path}" 2>/dev/null \
      | grep --only-matching --extended-regexp "gnulinux-[^' ]+" \
      || true
   ## '|| true': no id is a legitimate outcome (a mode the engine emits nothing for);
   ## under pipefail+inherit_errexit a no-match grep (exit 1) would otherwise abort the
   ## caller's command substitution and skip the '[ -z id ]' diagnostic + remaining modes.
}

fail=0
checks=0

## Every COMPLETE id must belong to exactly one mode. The per-mode PREFIX checks alone cannot
## catch an alias where one mode's prefix is a prefix of another's (gnulinux-live- is a prefix
## of gnulinux-live-sysmaint-), so a 'live' entry wrongly emitting a 'live-sysmaint'-shaped id
## would still pass the 'live' prefix. record_mode_id fails the moment an id maps to a 2nd mode.
declare -A id_owner
distinct_ok=1
recorded=0
record_mode_id() {
   local mode="$1" id="$2" prev
   prev="${id_owner[${id}]:-}"
   if [ -n "${prev}" ] && [ "${prev}" != "${mode}" ]; then
      printf '%s\n' "FAIL  complete id '${id}' emitted under BOTH '${prev}' and '${mode}' -- modes alias"
      distinct_ok=0
      fail=1
   fi
   ## Count distinct ids via a counter, NOT '${#id_owner[@]}' -- an empty associative array
   ## trips 'set -o nounset' on that expansion (bash), which would abort the summary below.
   [ -n "${prev}" ] || recorded=$(( recorded + 1 ))
   id_owner["${id}"]="${mode}"
}

## 10_00_linux_dist emits one top-level menuentry: assert its --id prefix.
assert_simple_prefix() {
   local mode="$1" want="$2" id
   id="$(render_ids "${engine}" "${mode}" | head -n 1)"
   checks=$(( checks + 1 ))
   if [ -z "${id}" ]; then
      printf '%s\n' "FAIL  simple boot_mode_id=${mode}: engine emitted no id"
      fail=1
   elif [ "${id#"${want}"}" = "${id}" ]; then
      printf '%s\n' "FAIL  simple boot_mode_id=${mode}: id '${id}' lacks prefix '${want}'"
      fail=1
   else
      record_mode_id "${mode}" "${id}"
      printf '%s\n' "PASS  simple boot_mode_id=${mode}: id '${id}'"
   fi
}

## 10_50_linux_dist_advanced emits a whole submenu: the 'Advanced options' submenu
## --id plus each kernel's advanced entry. EVERY one must carry the per-mode prefix,
## or two modes' advanced submenus (and their inner entries) collide -- the exact
## pre-fix gap this guards, where the advanced engine hardcoded 'gnulinux-advanced-'.
assert_advanced_prefix() {
   local mode="$1" want="$2" ids id n=0
   ids="$(render_ids "${engine_advanced}" "${mode}")"
   checks=$(( checks + 1 ))
   if [ -z "${ids}" ]; then
      printf '%s\n' "FAIL  advanced boot_mode_id=${mode}: engine emitted no id"
      fail=1
      return
   fi
   while IFS= read -r id; do
      n=$(( n + 1 ))
      if [ "${id#"${want}"}" = "${id}" ]; then
         printf '%s\n' "FAIL  advanced boot_mode_id=${mode}: id '${id}' lacks prefix '${want}'"
         fail=1
         return
      fi
      record_mode_id "${mode}" "${id}"
   done <<< "${ids}"
   printf '%s\n' "PASS  advanced boot_mode_id=${mode}: ${n} id(s), all '${want}*'"
}

## The real production tokens (see the 10_0x / 10_20 / 10_55 / 10_60 wrappers). UNSET
## exercises the ':-simple' safety fallback -- no production wrapper leaves it unset.
## persistent-sysmaint vs live-sysmaint proves the SYSMAINT id is distinct per
## persistence, so live and persistent SYSMAINT never share an id. Each token is
## asserted against BOTH engines, since a mode's simple + advanced entries coexist.
for spec in \
   'UNSET:gnulinux-simple-' \
   'user:gnulinux-user-' \
   'live:gnulinux-live-' \
   'persistent-sysmaint:gnulinux-persistent-sysmaint-' \
   'live-sysmaint:gnulinux-live-sysmaint-' \
   'remove-sysmaint:gnulinux-remove-sysmaint-'; do
   assert_simple_prefix   "${spec%%:*}" "${spec#*:}"
   assert_advanced_prefix "${spec%%:*}" "${spec#*:}"
done

## Complete-id distinctness across every mode and both engines (the prefix-alias gap above).
## Canaries RED alongside the prefix checks on the pre-fix mode-blind engines: every mode then
## renders the same 'gnulinux-simple-<dev>' / 'gnulinux-advanced-<dev>', so ids collide here too.
checks=$(( checks + 1 ))
if [ "${recorded}" -eq 0 ]; then
   printf '%s\n' "FAIL  complete-id distinctness: no ids recorded to compare (engines emitted none)"
   fail=1
elif [ "${distinct_ok}" -eq 1 ]; then
   printf '%s\n' "PASS  complete-id distinctness: ${recorded} ids, none shared across modes"
else
   printf '%s\n' "FAIL  complete-id distinctness: an id is emitted under two modes"
fi

printf '%s\n' "" "${checks} checks, ${fail} failed"
[ "${fail}" -eq 0 ]
