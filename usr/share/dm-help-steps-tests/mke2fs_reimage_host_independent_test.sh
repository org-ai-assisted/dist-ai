#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 4350_reimage-raw-reproducible rebuilds the ext4 rootfs so the image is
## reproducible ACROSS BUILD HOSTS. It must drive mke2fs from the pinned
## build-data/mke2fs.conf (via MKE2FS_CONFIG), NOT from the build host's
## /etc/mke2fs.conf, or two hosts with different mke2fs.conf defaults produce
## different images and the build is not reproducible.
##
## This asserts the property directly, on plain image FILES (no loop device, no
## mount, no root):
##   - CANARY: two different host /etc/mke2fs.conf DO change mke2fs's output
##     (the host-dependence the pin closes is real);
##   - the pinned config yields a byte-identical image regardless of host and
##     across runs (reproducible + host-independent);
##   - the result is a valid ext4 (e2fsck -fn) carrying the input files.
## Exercised at a small size and at a >4 GiB size (the 'big' size-type regime a
## real rootfs falls in), since mke2fs selects geometry by filesystem size.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
pinned="${dm_checkout}/build-data/mke2fs.conf"
if [ ! -f "${pinned}" ]; then
   printf '%s\n' "FAIL: pinned mke2fs.conf not found at ${pinned}" >&2
   exit 1
fi

## e2fsprogs is required, not optional: its absence is a broken environment to
## fix (add e2fsprogs to the consumer deps), never a reason to skip. It installs
## into /usr/sbin, which a non-root PATH may omit -- prepend it.
export PATH="/usr/sbin:/sbin:${PATH}"
for tool in /usr/sbin/mke2fs /usr/sbin/e2fsck /usr/sbin/debugfs; do
   if [ ! -x "${tool}" ]; then
      printf '%s\n' "FAIL: required e2fsprogs tool ${tool} missing" >&2
      exit 1
   fi
done

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Deterministic inputs, matching what 4350 relies on.
export SOURCE_DATE_EPOCH=1600000000
fs_uuid="12345678-1234-1234-1234-1234567890ab"

tree="${work_dir}/tree"
mkdir --parents -- "${tree}/etc" "${tree}/usr/bin"
printf 'host\n' > "${tree}/etc/hostname"
printf 'data\n' > "${tree}/usr/bin/thing"
find "${tree}" -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" -- {} +

## Two synthetic host /etc/mke2fs.conf, differing in ext4 features + geometry.
cat > "${work_dir}/hostA.conf" <<'HOSTA'
[defaults]
	base_features = sparse_super,large_file,filetype,resize_inode,dir_index,ext_attr
	default_mntopts = acl,user_xattr
	enable_periodic_fsck = 0
	blocksize = 4096
	inode_size = 256
	inode_ratio = 16384
[fs_types]
	ext4 = {
		features = has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_nlink,extra_isize
	}
HOSTA
cat > "${work_dir}/hostB.conf" <<'HOSTB'
[defaults]
	base_features = sparse_super,large_file,filetype,resize_inode,dir_index,ext_attr
	default_mntopts = acl
	enable_periodic_fsck = 0
	blocksize = 4096
	inode_size = 128
	inode_ratio = 8192
[fs_types]
	ext4 = {
		features = has_journal,extent,huge_file,flex_bg,dir_nlink,extra_isize
	}
HOSTB

## Build one ext4 image FILE with the given MKE2FS_CONFIG; the mke2fs flags mirror
## 4350_reimage-raw-reproducible exactly (features/geometry from the config only).
make_img() {
   local cfg out size
   cfg="$1"
   out="$2"
   size="$3"
   safe-rm --force -- "${out}"
   truncate --size="${size}" -- "${out}"
   env MKE2FS_CONFIG="${cfg}" mke2fs -F -q -t ext4 \
      -U "${fs_uuid}" -E hash_seed="${fs_uuid}" \
      -d "${tree}" "${out}" >/dev/null 2>&1
}

sha() {
   sha256sum "$1" | cut -d' ' -f1
}

check_size() {
   local label size
   label="$1"
   size="$2"

   make_img "${work_dir}/hostA.conf" "${work_dir}/oldA.img" "${size}"
   make_img "${work_dir}/hostB.conf" "${work_dir}/oldB.img" "${size}"
   make_img "${pinned}"              "${work_dir}/new1.img" "${size}"
   make_img "${pinned}"              "${work_dir}/new2.img" "${size}"

   if [ "$( sha "${work_dir}/oldA.img" )" != "$( sha "${work_dir}/oldB.img" )" ]; then
      pass "${label}: canary -- host mke2fs.conf changes the image (host-dependence is real)"
   else
      fail "${label}: canary -- two host configs produced identical images"
   fi

   if [ "$( sha "${work_dir}/new1.img" )" = "$( sha "${work_dir}/new2.img" )" ]; then
      pass "${label}: pinned config is byte-reproducible across runs"
   else
      fail "${label}: pinned config not reproducible"
   fi

   if [ "$( sha "${work_dir}/new1.img" )" != "$( sha "${work_dir}/oldA.img" )" ] \
      && [ "$( sha "${work_dir}/new1.img" )" != "$( sha "${work_dir}/oldB.img" )" ]; then
      pass "${label}: pinned image is decoupled from host config"
   else
      fail "${label}: pinned image matched a host-config image"
   fi

   if e2fsck -fn "${work_dir}/new1.img" >/dev/null 2>&1; then
      pass "${label}: e2fsck -fn clean"
   else
      fail "${label}: e2fsck reported errors"
   fi

   local listing
   listing="$( debugfs -R 'ls -l /etc' "${work_dir}/new1.img" 2>/dev/null || true )"
   if [[ "${listing}" == *hostname* ]]; then
      pass "${label}: input files present in rebuilt fs"
   else
      fail "${label}: expected file missing from rebuilt fs"
   fi
}

## Small (the mke2fs 'default' size-type) and >4 GiB (the 'big' size-type a real
## rootfs uses). The image files are sparse, so only metadata is written.
check_size small 64M
check_size big 5G

summary_line="===== mke2fs reimage host-independent: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
