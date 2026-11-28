#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai end-to-end test for the libvirt-dist shared folder, HOST install +
## GUEST mount: the heavy, root, disposable lane. It runs the REAL root install,
## boots a real Whonix-Workstation disk image, and confirms the 9p share mounts
## inside the guest, a kvmsf GROUP member reaches it, and files round-trip
## host<->guest. The non-invasive sibling shared_folder_test.sh covers only the
## host-side attach; this lane closes the loop by installing for real + booting.
##
## Multi-account model: the root libvirt-dist install creates group kvmsf and the
## shared dir (${LIBVIRT_DIST_SHARED_DIR:-/mnt/shared}) owned root:kvmsf mode 3770
## (setgid + sticky, NO world) -- a system path so both "user" and "sysmaint"
## reach it via the group (a $HOME dir could not be cross-account traversable);
## root (NOT a member) owns it so the sticky bit protects BOTH members. user-setup
## then attaches it (9p accessmode='mapped,fmode=0660,dmode=0770') to the domains.
## So this test:
##   - runs the real install (resolved via LIBVIRT_DIST_REPO) against a temp
##     LIBVIRT_DIST_SHARED_DIR and asserts the dir is owner root, group kvmsf,
##     mode 3770 (NOT the old 0700 $HOME dir, NOT a world-exposed 0777), and that
##     a non-owner kvmsf member cannot chmod it (finding 1);
##   - injects the checkout's mount-shared (VM_CONFIG_DIST_REPO, else the
##     installed /usr copy) into the boot overlay, testing THAT code, not the
##     release image's;
##   - asserts the GUEST-side mounted root is group kvmsf and mode 3770 (NOT 700
##     owner-only), so it FAILS on the old mount-shared and PASSES on the fixed
##     one, and confirms the setgid + sticky bits round-trip through the 9p
##     mapped xattr (accessmode='mapped' would otherwise mask the group on the
##     mounted root; the fix re-applies chown root:kvmsf + chmod 3770 AFTER the
##     mount);
##   - asserts a non-owner kvmsf member can traverse + read + create, and READ a
##     file another member owns (the access requirement);
##   - asserts the sticky bit stops a member unlinking another member's file,
##     and RECORDS that guest-side group-WRITE is not achievable under 9p mapped
##     (new files are group-readable only);
##   - asserts the share is mounted nosuid,nodev,noexec,nosymfollow, that a
##     setuid binary placed in it cannot execute, and that a planted symlink is
##     not followed (blocks cross-account setuid escalation + symlink redirect);
##   - asserts the bare mountpoint UNDER the mount is root:root 0755 and a member
##     cannot create a file on it (no setuid drop when NO share mounts), and that
##     mount-shared's virtiofs branch does no chown/chmod (fixup scoped to 9p);
##   - asserts the HOST backing inode of a guest-written file is group kvmsf and
##     group-readable by a host kvmsf non-owner member (finding 2: fmode/dmode on
##     the attach, else host "sysmaint" could not read what the guest wrote);
##   - asserts the host<->guest canary still round-trips.
##
## Mechanics: user-setup attaches the share; the boot runs the overlay under a
## direct qemu whose 9p device reproduces EXACTLY what libvirt attaches
## (security_model=mapped, mount_tag=shared, path=the shared dir), so the guest
## exercises the identical mnt-shared-kvm.service mount path. A one-shot observer
## unit, seeded into the throwaway OVERLAY (the backing image is never written),
## gathers the evidence into /mnt/shared and powers the guest off, so the lane is
## deterministic with no console scripting. The test runs as root, so the mapped
## mount root's owner is root and the kvmsf member ('user', which mount-shared
## adds to kvmsf) is a genuine NON-owner -- group access, not owner access.
##
## Heavy and privileged: needs KVM/qemu, qemu-nbd (root) to seed the overlay, and
## a Whonix-Workstation qcow2 pointed to by LIBVIRT_DIST_WS_QCOW2. Any of these
## absent -> exit 77 (SKIP), never a failure.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Resolve the shipped user-setup: a checkout via LIBVIRT_DIST_REPO, else the
## installed package. user-setup honours LIBVIRT_DIST_REPO for its own XML too.
if [ -n "${LIBVIRT_DIST_REPO:-}" ] && [ -x "${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist/user-setup" ]; then
  user_setup="${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist/user-setup"
elif [ -x /usr/libexec/libvirt-dist/user-setup ]; then
  user_setup='/usr/libexec/libvirt-dist/user-setup'
else
  printf '%s\n' "SKIP: libvirt-dist user-setup not found (set LIBVIRT_DIST_REPO or install libvirt-dist)" >&2
  exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

## Resolve the ROOT install from the same base: it creates group kvmsf and the
## shared dir (3770 user:kvmsf). This heavy root lane runs it for real.
if [ -n "${LIBVIRT_DIST_REPO:-}" ] && [ -x "${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist/install" ]; then
  install_script="${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist/install"
elif [ -x /usr/libexec/libvirt-dist/install ]; then
  install_script='/usr/libexec/libvirt-dist/install'
else
  printf '%s\n' "SKIP: libvirt-dist install not found (set LIBVIRT_DIST_REPO or install libvirt-dist)" >&2
  exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

## Resolve the mount-shared under test: a vm-config-dist checkout via
## VM_CONFIG_DIST_REPO, else the installed copy. This is the code the boot
## exercises -- it is injected into the overlay, overriding the release image's.
if [ -n "${VM_CONFIG_DIST_REPO:-}" ] && [ -r "${VM_CONFIG_DIST_REPO}/usr/libexec/vm-config-dist/mount-shared" ]; then
  mount_shared_src="${VM_CONFIG_DIST_REPO}/usr/libexec/vm-config-dist/mount-shared"
elif [ -r /usr/libexec/vm-config-dist/mount-shared ]; then
  mount_shared_src='/usr/libexec/vm-config-dist/mount-shared'
else
  printf '%s\n' "SKIP: vm-config-dist mount-shared not found (set VM_CONFIG_DIST_REPO or install vm-config-dist)" >&2
  exit 77  ## style-ok: allow-skip: vm-config-dist is an opt-in component, absent in the core lane
fi

## A Whonix-Workstation qcow2 is required; without it there is nothing to boot.
ws_qcow2="${LIBVIRT_DIST_WS_QCOW2:-}"
if [ -z "${ws_qcow2}" ] || [ ! -r "${ws_qcow2}" ]; then
  printf '%s\n' "SKIP: no readable Whonix-Workstation qcow2 (set LIBVIRT_DIST_WS_QCOW2)" >&2
  exit 77  ## style-ok: allow-skip: the Whonix-Workstation disk image is a multi-GB out-of-band asset, absent in CI
fi

## The libvirt/qemu stack is an opt-in apt set; a lane without it SKIPs (77),
## never fails. Self-contained -- sources no helper-scripts, so it detects tools
## with command -v rather than has():
## style-ok: no-has
missing=''
for cmd in virsh virt-xml qemu-img qemu-system-x86_64 qemu-nbd blkid runuser safe-rm; do
  command -v "${cmd}" >/dev/null 2>&1 || missing="${missing} ${cmd}"
done
if [ -n "${missing}" ]; then
  printf '%s\n' "SKIP: missing required command(s):${missing}" >&2
  exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

## Seeding the overlay (qemu-nbd attach + partition mount) needs root. Running as
## root also makes 'user' a non-owner kvmsf member, so group access is tested.
if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' "SKIP: boot lane needs root to seed the disk image via qemu-nbd" >&2
  exit 77  ## style-ok: allow-skip: a boot+nbd lane cannot run in an unprivileged lane
fi

## Generous TCG budget; a KVM host finishes in a fraction of this.
boot_timeout="${LIBVIRT_DIST_BOOT_TIMEOUT:-1200}"
guest_mem_mib="${LIBVIRT_DIST_BOOT_MEM_MIB:-1536}"

## user-setup defines all three; Whonix-Workstation is the one we boot.
domain_list=(Whonix-Gateway Whonix-Workstation Kicksecure)
domain='Whonix-Workstation'
## A kvmsf member that mount-shared adds to the group; NON-owner once the fix
## makes root own the mounted root, so a pass proves GROUP access, not owner.
member='user'
nbd_dev=''
nbd_mnt=''
test_home=''
share_base=''
overlay=''
test_failures=0
pass_count=0

pass() {
  pass_count=$(( pass_count + 1 ))
  printf '%s\n' "PASS: $*"
}
fail() {
  test_failures=$(( test_failures + 1 ))
  printf '%s\n' "FAIL: $*" >&2
}
note() {
  printf '%s\n' "NOTE: $*"
}

cleanup() {
  local dom
  for dom in "${domain_list[@]}"; do
    virsh -c qemu:///session undefine "${dom}" &>/dev/null || true
  done
  if [ -n "${nbd_mnt}" ] && mountpoint -q "${nbd_mnt}"; then
    umount "${nbd_mnt}" &>/dev/null || true
  fi
  [ -z "${nbd_dev}" ] || qemu-nbd --disconnect "${nbd_dev}" &>/dev/null || true
  [ -z "${nbd_mnt}" ] || rmdir "${nbd_mnt}" &>/dev/null || true
  [ -z "${test_home}" ] || safe-rm --recursive --force -- "${test_home}"
  [ -z "${share_base}" ] || safe-rm --recursive --force -- "${share_base}"
}

## Pick the first free /dev/nbdN (a used one has a non-zero size).
pick_free_nbd() {
  local dev
  modprobe nbd max_part=16 &>/dev/null || true
  for dev in /dev/nbd*; do
    case "${dev}" in
      *p[0-9]*)
        continue
        ;;
    esac
    [ -b "${dev}" ] || continue
    if [ "$(blockdev --getsize64 "${dev}" 2>/dev/null || printf '%s\n' 0)" = '0' ]; then
      printf '%s\n' "${dev}"
      return 0
    fi
  done
  return 1
}

## Seed the overlay: inject the mount-shared under test, plus a one-shot observer
## that records the mounted-root perms, exercises non-owner group access, and
## round-trips a canary, then powers off -- deterministic, no console scripting.
seed_overlay() {
  local root_part probe_sh unit
  nbd_dev="$(pick_free_nbd)" \
    || { printf '%s\n' "SKIP: no free /dev/nbd device" >&2; exit 77; }  ## style-ok: allow-skip: nbd devices may be exhausted on a shared host
  qemu-nbd --connect="${nbd_dev}" "${overlay}"
  ## Settle + re-read the partition table.
  sleep 2
  blockdev --rereadpt "${nbd_dev}" &>/dev/null || true
  partprobe "${nbd_dev}" &>/dev/null || true
  sleep 1
  ## The Whonix/Kicksecure image is GPT: p1 ESP, p2 bios_grub, p3 ext4 root.
  root_part=''
  local part
  for part in "${nbd_dev}p3" "${nbd_dev}p2" "${nbd_dev}p1"; do
    if [ "$(blkid -o value -s TYPE "${part}" 2>/dev/null)" = 'ext4' ]; then
      root_part="${part}"
      break
    fi
  done
  [ -n "${root_part}" ] || { printf '%s\n' "SKIP: no ext4 root partition in the qcow2" >&2; exit 77; }  ## style-ok: allow-skip: an unexpected image layout is not a vm-config-dist defect
  nbd_mnt="$(mktemp --directory)"
  mount "${root_part}" "${nbd_mnt}"

  ## Inject the mount-shared under test into the GUEST overlay, overriding the
  ## release image's copy so the boot exercises the checkout's code. This is not
  ## the "no synthetic copy" anti-pattern: the subject runs inside a booted guest
  ## (a separate kernel + filesystem) whose mnt-shared-kvm.service cannot be
  ## redirected to a host checkout via an env base, so the REAL file (resolved
  ## from VM_CONFIG_DIST_REPO, byte-identical, no re-embedded body) is placed on
  ## the guest rootfs -- the only way to run the checkout's code end to end.
  install -m 0755 -- "${mount_shared_src}" "${nbd_mnt}/usr/libexec/vm-config-dist/mount-shared"

  mkdir --parents "${nbd_mnt}/usr/local/bin"
  probe_sh="${nbd_mnt}/usr/local/bin/libvirt-dist-shared-probe.sh"
  cat > "${probe_sh}" <<'PROBE'
#!/bin/bash
## Test observer: record the mounted-root perms, exercise non-owner group
## access, round-trip a canary, then power off. 'member' is substituted in.
exec >/dev/console 2>&1
mp=/mnt/shared
res="${mp}/PROBE-RESULT.txt"
member='@MEMBER@'
printf 'PROBE-BEGIN\n'
{
  printf 'FINDMNT: '
  findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS "${mp}" 2>&1 \
    || printf '%s is not a mountpoint\n' "${mp}"
  printf 'MOUNTSTAT: '
  stat -c 'owner=%U(%u) group=%G(%g) mode=%a type=%F' "${mp}" 2>&1
  ## Mount hardening: the share must carry nosuid,nodev,noexec,nosymfollow.
  printf 'MOUNTOPTS: '
  findmnt --noheadings --output OPTIONS "${mp}" 2>&1 || printf 'none\n'
  ## noexec/nosuid effective: a setuid-root binary dropped in the share must NOT
  ## execute (so it cannot escalate). cp a tiny real binary, setuid it, run it.
  cp /bin/true "${mp}/suidprobe" 2>/dev/null \
    && chmod 4755 "${mp}/suidprobe" 2>/dev/null
  printf 'SUIDPROBE-STAT: '; stat -c 'mode=%a' "${mp}/suidprobe" 2>&1
  if "${mp}/suidprobe" 2>/dev/null; then
    printf 'SUIDPROBE-EXEC: ran-BAD\n'
  else
    printf 'SUIDPROBE-EXEC: blocked-good\n'
  fi
  ## nosymfollow effective: a symlink planted in the share must NOT be followed
  ## (the 3770 dir is group- but not world-writable, so fs.protected_symlinks
  ## does not cover it). Under nosymfollow, opening the link fails (ELOOP).
  ln --symbolic /etc/hostname "${mp}/symlink-probe" 2>/dev/null
  if cat "${mp}/symlink-probe" >/dev/null 2>&1; then
    printf 'SYMLINK-FOLLOWED: yes-BAD\n'
  else
    printf 'SYMLINK-FOLLOWED: no-good\n'
  fi
  ## Bare-mountpoint hardening: reveal the dir UNDER the 9p mount (a plain
  ## bind of / does not carry the submount) -- it is the mountpoint mount-shared
  ## created before mounting. It must be root:root 0755 (NOT group-writable), so
  ## when NO share mounts a member cannot drop a setuid binary on the suid rootfs.
  mkdir --parents /mnt/bind-probe 2>/dev/null
  if mount --bind / /mnt/bind-probe 2>/dev/null; then
    printf 'BARE-MOUNTPOINT-STAT: '
    stat -c 'owner=%U group=%G mode=%a' /mnt/bind-probe/mnt/shared 2>&1
    if runuser -u "${member}" -- touch /mnt/bind-probe/mnt/shared/member-drop 2>/dev/null; then
      printf 'BARE-MEMBER-CREATE: yes-BAD\n'
      rm -f /mnt/bind-probe/mnt/shared/member-drop 2>/dev/null
    else
      printf 'BARE-MEMBER-CREATE: no-good\n'
    fi
    umount /mnt/bind-probe 2>/dev/null || umount -l /mnt/bind-probe 2>/dev/null
  else
    printf 'BARE-MOUNTPOINT-STAT: bind-failed\n'
    printf 'BARE-MEMBER-CREATE: bind-failed\n'
  fi
  printf 'KVMSF-GROUP: '; getent group kvmsf 2>&1
  printf 'MEMBER-ID: '; id "${member}" 2>&1
  if [ -f "${mp}/HOST-CANARY.txt" ]; then
    printf 'HOST-CANARY-READABLE\n'
  else
    printf 'HOST-CANARY-MISSING\n'
  fi
  if runuser -u "${member}" -- test -x "${mp}" 2>/dev/null; then
    printf 'MEMBER-TRAVERSE-X: yes\n'
  else
    printf 'MEMBER-TRAVERSE-X: no\n'
  fi
  if runuser -u "${member}" -- test -r "${mp}" 2>/dev/null; then
    printf 'MEMBER-READ-R: yes\n'
  else
    printf 'MEMBER-READ-R: no\n'
  fi
  if runuser -u "${member}" -- bash -c "echo member-canary > ${mp}/MEMBER-CANARY.txt" 2>/dev/null; then
    printf 'MEMBER-CREATE: yes\n'
  else
    printf 'MEMBER-CREATE: no\n'
  fi
  printf 'MEMBER-CANARY-STAT: '; stat -c 'owner=%U group=%G mode=%a' "${mp}/MEMBER-CANARY.txt" 2>&1
  ## A file OWNED BY ANOTHER member (root here; group kvmsf via the setgid dir).
  printf 'ROOT-OWNED-STAT: '
  printf 'root-owned\n' > "${mp}/ROOT-OWNED.txt"
  stat -c 'owner=%U group=%G mode=%a' "${mp}/ROOT-OWNED.txt" 2>&1
  ## Access requirement: a non-owner kvmsf member can READ another's file.
  if runuser -u "${member}" -- cat "${mp}/ROOT-OWNED.txt" >/dev/null 2>&1; then
    printf 'MEMBER-READ-ROOTFILE: yes\n'
  else
    printf 'MEMBER-READ-ROOTFILE: no\n'
  fi
  ## Group-WRITE parity (finding 4): can a member APPEND to another's file?
  ## Diagnostic only -- under 9p mapped this is 'no' (umask 0644, no ACL).
  if runuser -u "${member}" -- bash -c "printf x >> ${mp}/ROOT-OWNED.txt" 2>/dev/null; then
    printf 'MEMBER-APPEND-ROOTFILE: yes\n'
  else
    printf 'MEMBER-APPEND-ROOTFILE: no\n'
  fi
  ## Sticky bit (finding 2): a member must NOT be able to unlink another's file.
  ## rm -f returns non-zero on a sticky-denied unlink, so the file survives.
  if runuser -u "${member}" -- rm -f "${mp}/ROOT-OWNED.txt" 2>/dev/null \
    && [ ! -e "${mp}/ROOT-OWNED.txt" ]; then
    printf 'MEMBER-UNLINK-ROOTFILE: yes\n'
  else
    printf 'MEMBER-UNLINK-ROOTFILE: no\n'
  fi
  if printf 'guest-canary\n' > "${mp}/GUEST-CANARY.txt" 2>&1; then
    printf 'GUEST-WRITE-OK\n'
  else
    printf 'GUEST-WRITE-FAIL\n'
  fi
} > "${res}" 2>&1
cat "${res}"
printf 'PROBE-END\n'
sync
sleep 1
systemctl poweroff --no-block 2>/dev/null || poweroff -f
PROBE
  ## Substitute the member account chosen host-side.
  sed -i "s|@MEMBER@|${member}|g" "${probe_sh}"
  chmod 0755 "${probe_sh}"

  unit="${nbd_mnt}/etc/systemd/system/libvirt-dist-shared-probe.service"
  cat > "${unit}" <<'UNIT'
[Unit]
Description=libvirt-dist shared-folder boot probe (test observer)
After=mnt-shared-kvm.service systemd-user-sessions.service network.target
Wants=mnt-shared-kvm.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/libvirt-dist-shared-probe.sh
TimeoutStartSec=180
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  mkdir --parents "${nbd_mnt}/etc/systemd/system/multi-user.target.wants"
  ln --symbolic --force ../libvirt-dist-shared-probe.service \
    "${nbd_mnt}/etc/systemd/system/multi-user.target.wants/libvirt-dist-shared-probe.service"

  sync
  umount "${nbd_mnt}"
  rmdir "${nbd_mnt}"; nbd_mnt=''
  qemu-nbd --disconnect "${nbd_dev}" &>/dev/null
  nbd_dev=''
}

## Read a 'KEY: value' field from the probe result.
probe_field() {
  sed -n "s/^$1: //p" "$2" | head -n 1
}

main() {
  ## Refuse to touch a real Whonix / Kicksecure host's domains.
  local dom
  for dom in "${domain_list[@]}"; do
    if virsh -c qemu:///session dominfo "${dom}" &>/dev/null; then
      printf '%s\n' "FAIL: refusing to overwrite existing qemu:///session domain '${dom}'" >&2
      exit 1
    fi
  done

  trap cleanup EXIT
  test_home="$(mktemp --directory)"
  ## The share must sit on a world-traversable path so a non-owner kvmsf member
  ## ('user') reaches it by the share's OWN perms (the chmod-denial + host-read
  ## checks) rather than being blocked by an ancestor. Under libpam-tmpdir the
  ## default mktemp base is root's 0700 /tmp/user/0, which 'user' cannot enter.
  ## /run is world-traversable (0755) and holds only the tiny canaries; the heavy
  ## overlay stays under test_home. Mirrors production /mnt/shared, whose
  ## ancestors (/, /mnt) are traversable.
  share_base="$(mktemp --directory --tmpdir=/run libvirt-dist-share.XXXXXX)"
  chmod 0711 -- "${share_base}"
  local shared_dir="${share_base}/shared"
  local serial_log="${test_home}/serial.log"
  overlay="${test_home}/overlay.qcow2"
  ## The root install and user-setup both honour this; keep it off the real
  ## /mnt/shared so the lane is self-contained.
  export LIBVIRT_DIST_SHARED_DIR="${shared_dir}"

  ## 1. Run the REAL root install: it creates group kvmsf and the shared dir at
  ##    3770 user:kvmsf (a system path, not a $HOME dir). The sandbox/CI has a
  ##    real 'user' account, so its adduser/chown apply.
  "${install_script}"

  ## 1a. Host-side: the install made the shared dir owner root, group kvmsf, mode
  ##     3770 -- root (NOT a member) owns it so the sticky bit protects BOTH
  ##     members; NOT the old 0700 $HOME dir, NOT a world-exposed 0777.
  local host_owner host_mode host_group
  host_owner="$(stat --format='%U' -- "${shared_dir}")"
  host_mode="$(stat --format='%a' -- "${shared_dir}")"
  host_group="$(stat --format='%G' -- "${shared_dir}")"
  if [ "${host_owner}" = "root" ] && [ "${host_mode}" = "3770" ] && [ "${host_group}" = "kvmsf" ]; then
    pass "install created ${shared_dir} owner root group kvmsf mode 3770 (sticky, no world)"
  else
    fail "install left ${shared_dir} owner=${host_owner} group=${host_group} mode=${host_mode} (want root kvmsf 3770)"
  fi

  ## 1b. finding 1: a non-owner kvmsf member ('user') cannot chmod the root-owned
  ##     share, so it cannot widen perms or defeat the sticky bit.
  local chmod_rc=0
  runuser -u user -- chmod 0755 "${shared_dir}" 2>/dev/null || chmod_rc="$?"
  if [ "${chmod_rc}" -ne 0 ] && [ "$(stat --format='%a' -- "${shared_dir}")" = "3770" ]; then
    pass "non-owner kvmsf member 'user' cannot chmod the root-owned share"
  else
    fail "non-owner 'user' changed the share mode (chmod rc=${chmod_rc}, mode now $(stat --format='%a' -- "${shared_dir}"))"
  fi

  ## 1c. Static: the mount-shared virtiofs branch does NO chown/chmod -- virtiofs
  ##     is passthrough, so a guest fixup would mutate the exported HOST dir; the
  ##     group fixup stays SCOPED to the 9p branch.
  ## Skip '##' comment lines so a comment that merely NAMES chown/chmod (to
  ## explain why they are absent) is not mistaken for a real command.
  local virtiofs_arm
  virtiofs_arm="$(awk '/^ *virtiofs\)/{f=1} f && $0 !~ /^ *##/ {print} f&&/;;/{exit}' "${mount_shared_src}")"
  if ! grep --quiet --extended-regexp 'chown|chmod' <<< "${virtiofs_arm}"; then
    pass "mount-shared virtiofs branch does no chown/chmod (fixup scoped to 9p)"
  else
    fail "mount-shared virtiofs branch contains a chown/chmod (would mutate the host dir)"
  fi

  ## 2. Drive the REAL user-setup: define the domains + attach the 9p share. It
  ##    requires the dir the install created and fails loud otherwise.
  HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" "${user_setup}"

  ## Re-check the host-side attach so a later boot failure is never
  ## misattributed to a bad device.
  local xml
  xml="$(virsh -c qemu:///session dumpxml --inactive "${domain}")"
  if grep --quiet --fixed-strings "dir='${shared_dir}'" <<< "${xml}" \
    && grep --quiet --fixed-strings "accessmode='mapped'" <<< "${xml}"; then
    pass "user-setup attached a mapped 9p share on ${shared_dir}"
  else
    fail "user-setup did not attach a mapped 9p share on ${shared_dir}"
    exit 1
  fi

  ## 2. Writable overlay (backing image stays pristine); inject mount-shared +
  ## observer.
  qemu-img create -f qcow2 -F qcow2 -b "$(readlink --canonicalize -- "${ws_qcow2}")" "${overlay}" >/dev/null
  seed_overlay

  ## 3. Host canary, then boot. The 9p device reproduces the attached one
  ## (mapped / mount_tag=shared / path=$HOME/shared / fmode=0660,dmode=0770) so
  ## the guest runs the identical mnt-shared-kvm.service mount path AND the
  ## host-side inode perms of guest-created files match production (finding 2).
  printf '%s\n' 'host-canary' > "${shared_dir}/HOST-CANARY.txt"
  ## -nographic routes the guest serial console to qemu's stdout, which we
  ## redirect to the log -- '-serial file:' does NOT reliably flush here, and a
  ## hardened Kicksecure boot is silent on serial anyway. -no-reboot makes qemu
  ## exit when the observer powers the guest off.
  local accel='tcg'
  [ -w /dev/kvm ] && accel='kvm'
  timeout --kill-after=10 "${boot_timeout}" qemu-system-x86_64 \
    -machine q35 -accel "${accel}" \
    -m "${guest_mem_mib}" -smp 2 \
    -drive file="${overlay}",if=virtio,format=qcow2 \
    -fsdev local,id=fsdev0,path="${shared_dir}",security_model=mapped,fmode=0660,dmode=0770 \
    -device virtio-9p-pci,fsdev=fsdev0,mount_tag=shared \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -nographic -no-reboot </dev/null >"${serial_log}" 2>&1 || true

  ## 4. Evidence. The observer wrote PROBE-RESULT.txt into the share, so its
  ## mere presence host-side already proves guest->host write works.
  local result="${shared_dir}/PROBE-RESULT.txt"
  if [ ! -f "${result}" ]; then
    fail "guest produced no PROBE-RESULT.txt in the share (boot or mount failed)"
    note "serial tail:"
    tail -n 25 "${serial_log}" 2>/dev/null | sed 's/^/  | /' || true
    exit 1
  fi
  note "guest probe result:"
  sed 's/^/  | /' "${result}"

  ## 4a. Mounted over 9p (trans=virtio).
  if grep --quiet --extended-regexp 'FINDMNT:.*9p' "${result}" \
    && grep --quiet 'trans=virtio' "${result}"; then
    pass "/mnt/shared is mounted over 9p (trans=virtio) in the guest"
  else
    fail "/mnt/shared is not a 9p (trans=virtio) mount in the guest"
  fi

  ## 4b. The fix: mounted root is group kvmsf and mode 3770 (setgid + sticky),
  ## NOT 700 owner-only. This FAILS on the pre-fix mount-shared (700 owner-only)
  ## and confirms the sticky bit round-trips through the 9p mapped xattr.
  local mountstat mode group
  mountstat="$(probe_field MOUNTSTAT "${result}")"
  mode="$(sed -n 's/.*mode=\([0-9]\{3,4\}\).*/\1/p' <<< "${mountstat}")"
  group="$(sed -n 's/.*group=\([^(]*\)(.*/\1/p' <<< "${mountstat}")"
  if [ "${group}" = 'kvmsf' ] && [ "${mode}" = '3770' ]; then
    pass "mounted root is group kvmsf, mode ${mode} (setgid + sticky, not 700 owner-only)"
  else
    fail "mounted root is not group-accessible: ${mountstat} (want group=kvmsf mode=3770)"
  fi

  ## 4c. A non-owner kvmsf member can traverse + read + create.
  if [ "$(probe_field MEMBER-TRAVERSE-X "${result}")" = 'yes' ]; then
    pass "non-owner kvmsf member '${member}' can traverse /mnt/shared"
  else
    fail "non-owner kvmsf member '${member}' cannot traverse /mnt/shared"
  fi
  if [ "$(probe_field MEMBER-READ-R "${result}")" = 'yes' ]; then
    pass "non-owner kvmsf member '${member}' can read /mnt/shared"
  else
    fail "non-owner kvmsf member '${member}' cannot read /mnt/shared"
  fi
  if [ "$(probe_field MEMBER-CREATE "${result}")" = 'yes' ] \
    && [ -f "${shared_dir}/MEMBER-CANARY.txt" ]; then
    pass "non-owner kvmsf member '${member}' can create a file under /mnt/shared"
  else
    fail "non-owner kvmsf member '${member}' cannot create a file under /mnt/shared"
  fi

  ## 4c-bis. Access requirement: a member can READ a file another member owns.
  if [ "$(probe_field MEMBER-READ-ROOTFILE "${result}")" = 'yes' ]; then
    pass "non-owner kvmsf member '${member}' can read another member's file"
  else
    fail "non-owner kvmsf member '${member}' cannot read another member's file"
  fi

  ## 4f. Sticky bit (finding 2): a member must NOT unlink another member's file.
  if [ "$(probe_field MEMBER-UNLINK-ROOTFILE "${result}")" = 'no' ]; then
    pass "sticky bit stops '${member}' unlinking another member's file"
  else
    fail "sticky bit did NOT stop '${member}' unlinking another member's file"
  fi

  ## 4f-bis. Mount hardening: nosuid, nodev, noexec AND nosymfollow.
  local mountopts opt missing_opt=''
  mountopts="$(probe_field MOUNTOPTS "${result}")"
  for opt in nosuid nodev noexec nosymfollow; do
    grep --quiet --extended-regexp "(^|,)${opt}(,|$)" <<< "${mountopts}" \
      || missing_opt="${missing_opt} ${opt}"
  done
  if [ -z "${missing_opt}" ]; then
    pass "share is mounted nosuid,nodev,noexec,nosymfollow (opts: ${mountopts})"
  else
    fail "share mount is missing option(s):${missing_opt} (opts: ${mountopts})"
  fi

  ## 4f-ter. noexec/nosuid effective: a setuid-root binary in the share cannot
  ##         execute, so it cannot escalate across the user<->sysmaint boundary.
  if [ "$(probe_field SUIDPROBE-EXEC "${result}")" = 'blocked-good' ]; then
    pass "a setuid binary in the share cannot execute (noexec/nosuid effective)"
  else
    fail "a setuid binary in the share executed (noexec/nosuid NOT effective)"
  fi

  ## 4f-sym. nosymfollow effective: a symlink planted in the share is not
  ##         followed, so a member cannot redirect another off the share.
  if [ "$(probe_field SYMLINK-FOLLOWED "${result}")" = 'no-good' ]; then
    pass "a symlink in the share is not followed (nosymfollow effective)"
  else
    fail "a symlink in the share WAS followed (nosymfollow NOT effective)"
  fi

  ## 4f-bare. Bare-mountpoint hardening: the dir UNDER the mount is root:root
  ##          0755 (NOT group-writable) and a non-root member cannot create a
  ##          file in it, so when NO share mounts there is no setuid-drop path on
  ##          the suid/exec rootfs.
  local barestat
  barestat="$(probe_field BARE-MOUNTPOINT-STAT "${result}")"
  if [ "${barestat}" = 'owner=root group=root mode=755' ]; then
    pass "bare mountpoint under the share is root:root 0755 (not group-writable)"
  else
    fail "bare mountpoint is not root:root 0755: ${barestat}"
  fi
  if [ "$(probe_field BARE-MEMBER-CREATE "${result}")" = 'no-good' ]; then
    pass "a non-root member cannot create a file on the bare mountpoint (no setuid drop)"
  else
    fail "a non-root member could create a file on the bare mountpoint (setuid-drop path open)"
  fi

  ## 4g. Group-WRITE parity (finding 4): recorded, NOT asserted. Under 9p mapped
  ##     a new file carries the guest umask (0644, group-READABLE) and neither a
  ##     host fmode=/dmode= attach nor a guest default ACL changes that (fmode
  ##     sets only the host backing mode; 9p mapped returns ENOTSUP for setfacl
  ##     -- both verified empirically). So a member reads but cannot APPEND to
  ##     another's file: the known kvm-vs-vbox (umask=0007 -> 0660) difference.
  note "finding 4 group-write (member append to another's file): $(probe_field MEMBER-APPEND-ROOTFILE "${result}") (expected 'no' under 9p mapped; group-readable only)"

  ## 4d. Host->guest: the host canary was readable inside the guest.
  if grep --quiet --fixed-strings 'HOST-CANARY-READABLE' "${result}"; then
    pass "host canary is readable at /mnt/shared inside the guest"
  else
    fail "host canary was not readable inside the guest"
  fi

  ## 4e. Guest->host: the guest canary appears host side (mapped round-trip).
  if grep --quiet --fixed-strings 'GUEST-WRITE-OK' "${result}" \
    && [ -f "${shared_dir}/GUEST-CANARY.txt" ]; then
    pass "guest canary round-tripped to the host under \$HOME/shared"
  else
    fail "guest canary did not round-trip to the host"
  fi

  ## 4h. finding 2 (the key empirical one): under mapped, QEMU creates the HOST
  ##     backing inode for a guest-written file at 0600/0700 by default, so host
  ##     "sysmaint" could not even READ it. fmode=0660,dmode=0770 on the attach
  ##     set the host backing mode; combined with the setgid dir (group kvmsf) a
  ##     guest-created host file is group kvmsf and group-readable, so a host
  ##     kvmsf non-owner member reaches it via the group. Here qemu ran as root
  ##     (boot lane), so the file is root:kvmsf; 'user' is a kvmsf member and
  ##     NON-owner -- the same group-read path host "sysmaint" uses in production.
  local gcanary hinode_group hinode_mode hread_rc=0
  gcanary="${shared_dir}/GUEST-CANARY.txt"
  if [ -f "${gcanary}" ]; then
    hinode_group="$(stat --format='%G' -- "${gcanary}")"
    hinode_mode="$(stat --format='%a' -- "${gcanary}")"
    runuser -u user -- cat "${gcanary}" >/dev/null 2>&1 || hread_rc="$?"
    note "finding 2 host inode of guest-written file: $(stat --format='owner=%U group=%G mode=%a' -- "${gcanary}")"
    if [ "${hinode_group}" = 'kvmsf' ] && [ "${hread_rc}" -eq 0 ]; then
      pass "guest-written host inode is group kvmsf and a host kvmsf member can read it (mode ${hinode_mode})"
    else
      fail "guest-written host inode not group-readable by a kvmsf member: group=${hinode_group} mode=${hinode_mode} read_rc=${hread_rc}"
    fi
  else
    fail "no guest-written host inode to check for finding 2"
  fi

  if [ "${test_failures}" -ne 0 ]; then
    printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
    exit 1
  fi
  printf '%s\n' "OK: guest-side shared-folder group access (${pass_count} assertions)."
}

main "$@"
