#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai behaviour test for libvirt-dist's per-user setup (user-setup) + root
## install, HOST side, no boot. The multi-account model: the root libvirt-dist
## install creates group kvmsf and the shared folder at ${LIBVIRT_DIST_SHARED_DIR
## :-/mnt/shared} owned root:kvmsf mode 3770 (setgid + sticky, NO world) -- a
## system path both "user" and "sysmaint" reach via the group (a $HOME dir could
## not be cross-account traversable); root (NOT a member) owns it so the sticky
## bit protects BOTH members. user-setup no longer creates the dir: it requires
## it and attaches it (9p accessmode='mapped') to all three domains.
##
## Two lanes:
##   ROOT lane (CI/sandbox only, root_host_checks) -- runs the REAL install
##   against a throwaway LIBVIRT_DIST_SHARED_DIR (never real /mnt/shared) and
##   asserts:
##     - install makes the share root:kvmsf 3770;
##     - a non-owner kvmsf member ('user') canNOT chmod the root-owned share
##       (finding 1: sticky-exempt owner must be root, not a member);
##     - install is an idempotent self-heal: a member dropped from kvmsf is
##       re-added by a second install run, and install.service carries no
##       run-once guard (so ExecStart re-applies every boot).
##   UNPRIVILEGED lane (also the dev-host path) -- drives only user-setup's
##   attach via qemu:///session, non-invasive (no real group/mnt mutation):
##     - the shared dir is mode 3770 (setgid + sticky, no world bit);
##     - user-setup attaches ONE 9p accessmode='mapped' filesystem per domain;
##     - a same-source re-run adds no duplicate device (dup guard);
##     - a DIFFERENT-source re-run adds no second <target dir='shared'/> device
##       (agy finding: the guard keys on the target mount tag, not the source);
##     - user-setup FAILS LOUD (non-zero) when the shared dir is missing.
##
## Drives the REAL user-setup via qemu:///session (define/attach never open an
## image, so no VM images and no KVM are needed; user-setup rewrites 'kvm' ->
## 'qemu' itself when KVM is absent). qemu:///session auto-spawns a per-USER
## libvirtd, so it must NOT run as root; when invoked as root the ROOT lane runs
## first, then it re-execs via runuser as a throwaway unprivileged user for the
## attach lane. The heavy guest-side boot lives in boot_shared_mount_test.sh.

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
  install_script="${LIBVIRT_DIST_REPO}/usr/libexec/libvirt-dist/install"
  install_service="${LIBVIRT_DIST_REPO}/usr/lib/systemd/system/libvirt-dist-install.service"
elif [ -x /usr/libexec/libvirt-dist/user-setup ]; then
  user_setup='/usr/libexec/libvirt-dist/user-setup'
  install_script='/usr/libexec/libvirt-dist/install'
  install_service='/usr/lib/systemd/system/libvirt-dist-install.service'
else
  printf '%s\n' "SKIP: libvirt-dist user-setup not found (set LIBVIRT_DIST_REPO or install libvirt-dist)" >&2
  exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

## The libvirt/qemu stack is an opt-in apt set; a lane without it SKIPs (77),
## never fails. Self-contained -- sources no helper-scripts, so it detects tools
## with command -v rather than has():
## style-ok: no-has
missing=''
for cmd in virsh virt-xml qemu-img runuser safe-rm; do
  command -v "${cmd}" >/dev/null 2>&1 || missing="${missing} ${cmd}"
done
if [ -n "${missing}" ]; then
  printf '%s\n' "SKIP: missing required command(s):${missing}" >&2
  exit 77  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
fi

## True when account 'user' is a member of group kvmsf. Avoids `id | grep -q`
## (a quiet grep consuming a pipe masks a producer failure -- R-161).
user_in_kvmsf() {
  local groups_of_user
  groups_of_user="$(id -nG user)"
  case " ${groups_of_user} " in
    *' kvmsf '*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

## Privileged host-logic lane (CI/sandbox): the REAL install's idempotent group
## re-apply and the root-owned 3770 dir need root AND mutate system groups, so
## they run ONLY as root, against a throwaway LIBVIRT_DIST_SHARED_DIR (never the
## real /mnt/shared). Exits non-zero on any failure; returns 0 otherwise.
root_host_checks() {
  local idem_parent idem_dir owner group mode chmod_rc rc=0
  [ -x "${install_script}" ] || { printf '%s\n' "SKIP: libvirt-dist install not found (set LIBVIRT_DIST_REPO or install libvirt-dist)" >&2; exit 77; }  ## style-ok: allow-skip: libvirt/qemu stack is an opt-in apt set, absent in the core lane
  if ! getent passwd user >/dev/null; then
    printf '%s\n' "NOTE: account 'user' absent; skipping the root install-idempotency lane"
    return 0
  fi
  ## Parent 0755 so the non-owner member can TRAVERSE to the share: the chmod
  ## denial below must come from NOT OWNING it, not from an unreachable parent.
  idem_parent="$(mktemp --directory)"
  chmod 0755 -- "${idem_parent}"
  idem_dir="${idem_parent}/shared"

  ## A. install makes the share root:kvmsf 3770 -- root (NOT a member) owns it so
  ##    the sticky bit protects BOTH members from each other.
  LIBVIRT_DIST_SHARED_DIR="${idem_dir}" "${install_script}"
  owner="$(stat --format='%U' -- "${idem_dir}")"
  group="$(stat --format='%G' -- "${idem_dir}")"
  mode="$(stat --format='%a' -- "${idem_dir}")"
  if [ "${owner}" = 'root' ] && [ "${group}" = 'kvmsf' ] && [ "${mode}" = '3770' ]; then
    printf '%s\n' "PASS: install made ${idem_dir} owner root, group kvmsf, mode 3770"
  else
    printf '%s\n' "FAIL: install left ${idem_dir} owner=${owner} group=${group} mode=${mode} (want root kvmsf 3770)" >&2
    rc=1
  fi

  ## A (finding 1). A non-owner kvmsf member cannot chmod the root-owned share
  ##    (not the owner), so it cannot widen perms or defeat the sticky bit.
  chmod_rc=0
  runuser -u user -- chmod 0755 "${idem_dir}" 2>/dev/null || chmod_rc="$?"
  if [ "${chmod_rc}" -ne 0 ] && [ "$(stat --format='%a' -- "${idem_dir}")" = '3770' ]; then
    printf '%s\n' "PASS: non-owner member 'user' cannot chmod the root-owned share"
  else
    printf '%s\n' "FAIL: non-owner 'user' changed the share mode (chmod rc=${chmod_rc}, mode now $(stat --format='%a' -- "${idem_dir}"))" >&2
    rc=1
  fi

  ## C. Idempotent re-apply / self-heal: install.service carries no run-once
  ##    guard, so ExecStart re-runs every boot and an account that was not a
  ##    member yet (created after first boot, or dropped) is re-added. Simulate a
  ##    fresh/drifted account by dropping 'user' from kvmsf, then re-run install.
  user_in_kvmsf \
    || { printf '%s\n' "FAIL: install did not add 'user' to kvmsf" >&2; rc=1; }
  deluser user kvmsf >/dev/null 2>&1 || gpasswd --delete user kvmsf >/dev/null 2>&1 || true
  if user_in_kvmsf; then
    printf '%s\n' "FAIL: could not drop 'user' from kvmsf to simulate a fresh account" >&2
    rc=1
  fi
  LIBVIRT_DIST_SHARED_DIR="${idem_dir}" "${install_script}"
  if user_in_kvmsf; then
    printf '%s\n' "PASS: re-running install re-adds the dropped member to kvmsf (self-heal)"
  else
    printf '%s\n' "FAIL: re-running install did NOT re-add 'user' to kvmsf (no self-heal)" >&2
    rc=1
  fi

  ## C (static). The self-heal depends on install.service having NO run-once
  ##    guard (ConditionPathExists / an install.done touch would stop re-runs).
  if [ -r "${install_service}" ] \
    && ! grep --extended-regexp --quiet 'ConditionPathExists|install\.done' "${install_service}"; then
    printf '%s\n' "PASS: install.service has no run-once guard (re-applies each boot)"
  else
    printf '%s\n' "FAIL: install.service carries a run-once guard (self-heal defeated)" >&2
    rc=1
  fi

  safe-rm --recursive --force -- "${idem_parent}"
  return "${rc}"
}

## qemu:///session needs a non-root user; re-exec as a throwaway one when root.
if [ "$(id -u)" -eq 0 ]; then
  if ! root_host_checks; then
    printf '%s\n' "FAILED: root host-logic assertions" >&2
    exit 1
  fi
  test_user='libvirtdisttest'
  if ! id -u "${test_user}" >/dev/null 2>&1; then
    adduser --disabled-password --gecos '' "${test_user}" >/dev/null 2>&1 \
      || { printf '%s\n' "SKIP: cannot create a non-root user for qemu:///session" >&2; exit 77; }  ## style-ok: allow-skip: qemu:///session needs a non-root user; unprivileged lane cannot create one
  fi
  runtime_dir="/run/user/$(id -u "${test_user}")"
  install -d -m 0700 -o "${test_user}" -g "${test_user}" "${runtime_dir}"
  ## TMPDIR=/tmp: when invoked as root, libpam-tmpdir leaves TMPDIR pointing at
  ## root's private /tmp/user/0, which the throwaway user cannot write -- its
  ## mktemp would fail. /tmp (sticky, world-writable) is always reachable.
  reexec_rc=0
  runuser -u "${test_user}" -- env \
    LIBVIRT_DIST_REPO="${LIBVIRT_DIST_REPO:-}" \
    XDG_RUNTIME_DIR="${runtime_dir}" \
    TMPDIR=/tmp \
    "$(readlink --canonicalize -- "$0")" "$@" || reexec_rc="$?"
  exit "${reexec_rc}"
fi

## --- running as an unprivileged user with a session runtime dir ---

domain_list=(Whonix-Gateway Whonix-Workstation Kicksecure)
test_home=''
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

cleanup() {
  local vm
  for vm in "${domain_list[@]}"; do
    virsh -c qemu:///session undefine "${vm}" &>/dev/null || true
  done
  [ -z "${test_home}" ] || safe-rm --recursive --force -- "${test_home}"
}

## Count filesystem devices on a domain whose source dir is the shared folder.
shared_fs_count() {
  local vm="$1" dir="$2"
  virsh -c qemu:///session dumpxml --inactive "${vm}" \
    | grep --fixed-strings "dir='${dir}'" \
    | grep --count --fixed-strings 'source' || true
}

## Count filesystem devices by the <target dir='shared'/> MOUNT TAG (what the
## dup-guard keys on; libvirt requires it unique or the domain fails to start).
shared_target_count() {
  local vm="$1"
  virsh -c qemu:///session dumpxml --inactive "${vm}" \
    | grep --count --fixed-strings "target dir='shared'" || true
}

main() {
  local vm

  ## Refuse to touch a real Whonix / Kicksecure host's domains.
  for vm in "${domain_list[@]}"; do
    if virsh -c qemu:///session dominfo "${vm}" &>/dev/null; then
      printf '%s\n' "FAIL: refusing to overwrite existing qemu:///session domain '${vm}'" >&2
      exit 1
    fi
  done

  trap cleanup EXIT
  test_home="$(mktemp --directory)"
  local shared_dir="${test_home}/shared"

  ## Stand in for the root install WITHOUT touching real groups or /mnt: a temp
  ## dir at the model's mode 3770 (setgid + sticky). Pointing
  ## LIBVIRT_DIST_SHARED_DIR here drives user-setup's attach against it.
  install --directory --mode 3770 -- "${shared_dir}"
  export LIBVIRT_DIST_SHARED_DIR="${shared_dir}"

  ## Drive the real user-setup (attach only) with an isolated HOME.
  HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" "${user_setup}"

  ## 1. Shared dir is mode 3770 (setgid + sticky, no world bit): never
  ##    world-exposed; sticky so kvmsf members cannot unlink each other's files.
  local mode
  mode="$(stat --format='%a' -- "${shared_dir}")"
  if [ "${mode}" = "3770" ]; then
    pass "shared dir ${shared_dir} is mode 3770 (setgid + sticky, no world bit)"
  else
    fail "shared dir mode is ${mode}, want 3770 (setgid + sticky, no world)"
  fi

  ## 2. Attached once per domain, accessmode='mapped', source=shared_dir.
  for vm in "${domain_list[@]}"; do
    local xml count
    xml="$(virsh -c qemu:///session dumpxml --inactive "${vm}")"
    count="$(shared_fs_count "${vm}" "${shared_dir}")"
    if [ "${count}" = "1" ] \
      && grep --quiet --fixed-strings "accessmode='mapped'" <<< "${xml}"; then
      pass "${vm}: one mapped filesystem on ${shared_dir}"
    else
      fail "${vm}: want 1 mapped filesystem on ${shared_dir}, got count=${count}"
    fi
  done

  ## 3. Dup guard: a second run adds no duplicate filesystem device.
  HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" "${user_setup}"
  for vm in "${domain_list[@]}"; do
    local count
    count="$(shared_fs_count "${vm}" "${shared_dir}")"
    if [ "${count}" = "1" ]; then
      pass "${vm}: re-run did not duplicate the filesystem device"
    else
      fail "${vm}: re-run left ${count} filesystem device(s), want 1"
    fi
  done

  ## 3b. Target-tag dup guard (agy finding): the guard keys on the <target
  ##     dir='shared'/> MOUNT TAG, not the source. Re-running with a DIFFERENT
  ##     source must NOT add a second target='shared' device (two would make the
  ##     domain fail to start: "target 'shared' duplicated"). A count of 1 also
  ##     confirms virsh dumpxml actually emits <target dir='shared'/>.
  local shared_dir2="${test_home}/shared2"
  install --directory --mode 3770 -- "${shared_dir2}"
  HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" \
    LIBVIRT_DIST_SHARED_DIR="${shared_dir2}" "${user_setup}"
  for vm in "${domain_list[@]}"; do
    local tcount
    tcount="$(shared_target_count "${vm}")"
    if [ "${tcount}" = "1" ]; then
      pass "${vm}: different-source re-run added no second target='shared' device"
    else
      fail "${vm}: ${tcount} target='shared' device(s) after different-source re-run, want 1"
    fi
  done

  ## 4. Fail loud: user-setup must refuse a missing shared dir (the root install
  ##    is a prerequisite), not attach a dangling source. Sub-run pointed at a
  ##    nonexistent path; user-setup exits non-zero before defining/attaching.
  local missing_dir="${test_home}/absent" missing_rc=0
  HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" \
    LIBVIRT_DIST_SHARED_DIR="${missing_dir}" "${user_setup}" >/dev/null 2>&1 || missing_rc="$?"
  if [ "${missing_rc}" -ne 0 ]; then
    pass "user-setup fails loud (rc=${missing_rc}) when the shared dir is missing"
  else
    fail "user-setup did not fail on a missing shared dir (want non-zero)"
  fi

  if [ "${test_failures}" -ne 0 ]; then
    printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
    exit 1
  fi
  printf '%s\n' "OK: shared-folder host-side behaviour (${pass_count} assertions)."
}

main "$@"
