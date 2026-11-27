#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai end-to-end test for the libvirt-dist shared folder, GUEST side: it
## boots a real Whonix-Workstation disk image and confirms that the 9p share the
## per-user setup (libvirt-dist user-setup) attaches actually MOUNTS inside the
## guest, that a kvmsf GROUP member reaches it, and that files round-trip
## host<->guest. The structural sibling shared_folder_test.sh verifies only the
## HOST side (define + attach); this lane closes the loop by booting.
##
## It is BOTH an e2e mount lane AND the regression test for the vm-config-dist
## mount-shared group-access fix: accessmode='mapped' presents the host
## $HOME/shared 0700 verbatim on the MOUNTED root, which masks mount-shared's
## pre-mount 'chown root:kvmsf; chmod 770' and leaves the share owner-only. The
## fix re-applies 'chown root:kvmsf; chmod 2770' AFTER a successful mount (mapped
## mode stores it in host xattrs). So this test:
##   - injects the checkout's mount-shared (VM_CONFIG_DIST_REPO, else the
##     installed /usr copy) into the boot overlay, testing THAT code, not the
##     release image's;
##   - asserts the mounted root is group kvmsf and mode 2770/770 (NOT 700
##     owner-only), so it FAILS on the old mount-shared and PASSES on the fixed
##     one;
##   - asserts a non-owner kvmsf member can traverse + read + create under
##     /mnt/shared;
##   - asserts the host<->guest canary still round-trips.
##
## Mechanics: user-setup attaches the share; the boot runs the overlay under a
## direct qemu whose 9p device reproduces EXACTLY what libvirt attaches
## (security_model=mapped, mount_tag=shared, path=$HOME/shared), so the guest
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
  local shared_dir="${test_home}/shared"
  local serial_log="${test_home}/serial.log"
  overlay="${test_home}/overlay.qcow2"

  ## 1. Drive the REAL user-setup: define the domains + attach the 9p share.
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
  ## (mapped / mount_tag=shared / path=$HOME/shared) so the guest runs the
  ## identical mnt-shared-kvm.service mount path.
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
    -fsdev local,id=fsdev0,path="${shared_dir}",security_model=mapped \
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

  ## 4b. The fix: mounted root is group kvmsf and mode 2770/770, NOT 700
  ## owner-only. This FAILS on the pre-fix mount-shared (700 owner-only).
  local mountstat mode group
  mountstat="$(probe_field MOUNTSTAT "${result}")"
  mode="$(sed -n 's/.*mode=\([0-9]\{3,4\}\).*/\1/p' <<< "${mountstat}")"
  group="$(sed -n 's/.*group=\([^(]*\)(.*/\1/p' <<< "${mountstat}")"
  if [ "${group}" = 'kvmsf' ] && { [ "${mode}" = '2770' ] || [ "${mode}" = '770' ]; }; then
    pass "mounted root is group kvmsf, mode ${mode} (group-accessible, not 700 owner-only)"
  else
    fail "mounted root is not group-accessible: ${mountstat} (want group=kvmsf mode=2770/770)"
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

  if [ "${test_failures}" -ne 0 ]; then
    printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
    exit 1
  fi
  printf '%s\n' "OK: guest-side shared-folder group access (${pass_count} assertions)."
}

main "$@"
