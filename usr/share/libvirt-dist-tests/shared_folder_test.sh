#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai behaviour test for libvirt-dist's per-user setup (user-setup) + root
## install, HOST side, no boot. The multi-account model: the root libvirt-dist
## install creates group kvmsf and the shared folder at ${LIBVIRT_DIST_SHARED_DIR
## :-/mnt/shared} owned user:kvmsf mode 3770 (setgid + sticky, NO world) -- a
## system path both "user" and "sysmaint" reach via the group (a $HOME dir could
## not be cross-account traversable). It is owned by the qemu:///session "user",
## NOT root: under 9p accessmode=mapped qemu runs as that user and records guest
## perms as user.virtfs.* xattrs here, and the kernel forbids a NON-owner from
## setting user.* xattrs on a STICKY dir -- a root-owned share would EPERM and
## lose group access. user-setup no longer creates the dir: it requires it and
## attaches it (9p accessmode='mapped,fmode=0640,dmode=0750') to all three domains.
##
## Two lanes:
##   ROOT lane (CI/sandbox only, root_host_checks + xattr_sticky_regression_check)
##   -- runs the REAL install against a throwaway LIBVIRT_DIST_SHARED_DIR (never
##   real /mnt/shared) and asserts:
##     - install makes the share user:kvmsf 3770 (owned by the qemu user);
##     - the mapped-9p ownership rule at the VFS level (no boot): a non-owner
##       kvmsf member is BLOCKED (EPERM) from writing user.virtfs.* xattrs on a
##       ROOT-owned sticky dir but SUCCEEDS on a USER-owned one, with a canary
##       that flipping the user-owned dir to root makes it fail (this is the bug
##       a root-run qemu would mask via CAP_FOWNER);
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

## The SUBJECT (user-setup) is present. Its same-package siblings MUST be too: a
## present-subject-but-missing-tool is a BROKEN env, not an optional absence --
## FAIL (never SKIP, which would hide an incomplete test environment).
if [ ! -x "${install_script}" ] || [ ! -r "${install_service}" ]; then
  printf '%s\n' "FATAL: user-setup found but install (${install_script}) or install.service (${install_service}) missing -- broken libvirt-dist checkout" >&2
  exit 1
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
## re-apply and the user-owned 3770 dir need root AND mutate system groups, so
## they run ONLY as root, against a throwaway LIBVIRT_DIST_SHARED_DIR (never the
## real /mnt/shared). Exits non-zero on any failure; returns 0 otherwise.
root_host_checks() {
  local idem_parent idem_dir owner group mode inst_rc rc=0
  ## install presence is guaranteed by the top-level FATAL check.
  if ! getent passwd user >/dev/null; then
    printf '%s\n' "NOTE: account 'user' absent; skipping the root install-idempotency lane"
    return 0
  fi
  ## Nothing non-root traverses idem_dir (the chmod-denial check was dropped when
  ## the share moved to user-owned), so the default mktemp base is fine.
  idem_parent="$(mktemp --directory)"
  idem_dir="${idem_parent}/shared"

  ## A. install makes the share USER:kvmsf 3770 -- owned by the qemu:///session
  ##    user, NOT root. Under 9p accessmode=mapped qemu runs as that user and
  ##    records guest perms as user.virtfs.* xattrs here; the kernel forbids a
  ##    non-owner from setting user.* xattrs on a STICKY dir, so a root-owned
  ##    share would EPERM and lose group access (see xattr_sticky_regression_check).
  ##    'user' owning + chmod-able is the documented mapped-session trade-off; the
  ##    guest-side view stays 3770-sticky via the mapped xattrs.
  ## rc captured EXPLICITLY: this function is called under `if !`, which disables
  ## errexit inside it, so a failing install would otherwise be silently ignored.
  inst_rc=0
  LIBVIRT_DIST_SHARED_DIR="${idem_dir}" "${install_script}" || inst_rc="$?"
  if [ "${inst_rc}" -ne 0 ]; then
    printf '%s\n' "FAIL: install exited ${inst_rc} (first run)" >&2
    rc=1
  fi
  owner="$(stat --format='%U' -- "${idem_dir}")"
  group="$(stat --format='%G' -- "${idem_dir}")"
  mode="$(stat --format='%a' -- "${idem_dir}")"
  if [ "${owner}" = 'user' ] && [ "${group}" = 'kvmsf' ] && [ "${mode}" = '3770' ]; then
    printf '%s\n' "PASS: install made ${idem_dir} owner user, group kvmsf, mode 3770"
  else
    printf '%s\n' "FAIL: install left ${idem_dir} owner=${owner} group=${group} mode=${mode} (want user kvmsf 3770)" >&2
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
  inst_rc=0
  LIBVIRT_DIST_SHARED_DIR="${idem_dir}" "${install_script}" || inst_rc="$?"
  if [ "${inst_rc}" -ne 0 ]; then
    printf '%s\n' "FAIL: install exited ${inst_rc} (self-heal re-run)" >&2
    rc=1
  fi
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

## The mapped-9p mechanism, at the VFS level (no qemu boot needed -- a root-run
## qemu would MASK this via CAP_FOWNER, which is exactly the bug this guards):
## qemu:///session runs qemu UNPRIVILEGED (as "user") and records guest perms as
## user.virtfs.* xattrs on the host share. The kernel forbids a NON-owner from
## setting user.* xattrs on a STICKY dir (EPERM), so the share MUST be owned by
## the qemu user -- a root-owned sticky share silently loses group access in
## production. Assert the rule directly + CANARY it.
xattr_sticky_regression_check() {
  local base rs us tg='libvirtdist-xattrtest' tu='libvirtdist-xattrprobe' rc=0
  ## Disk-backed fs (tmpfs often lacks user.* xattrs); require support or SKIP.
  base="$(mktemp --directory -- /var/lib/libvirt-dist-xattr.XXXXXX)"
  chmod 0755 -- "${base}"
  if ! setfattr --name user.probe --value x -- "${base}" 2>/dev/null; then
    safe-rm --recursive --force -- "${base}"
    printf '%s\n' "SKIP: /var/lib fs lacks user.* xattr support (cannot test the mapped-9p ownership rule)" >&2
    exit 77  ## style-ok: allow-skip: the mapped user.virtfs xattr rule needs a user-xattr-capable fs
  fi
  setfattr --remove user.probe -- "${base}" 2>/dev/null || true
  ## Setup rc checked EXPLICITLY: called under `if !` disables errexit here, so a
  ## failed groupadd/useradd would otherwise make the setfattr probes fail for the
  ## WRONG reason (missing user) and masquerade as "blocked".
  groupadd --force "${tg}"
  id "${tu}" >/dev/null 2>&1 \
    || useradd --no-create-home --no-user-group --gid "${tg}" "${tu}"
  if ! id "${tu}" >/dev/null 2>&1; then
    printf '%s\n' "FAIL: could not create probe user ${tu} for the xattr rule check" >&2
    safe-rm --recursive --force -- "${base}"
    groupdel "${tg}" >/dev/null 2>&1 || true
    return 1
  fi
  rs="${base}/root_sticky"
  us="${base}/user_sticky"
  mkdir "${rs}" "${us}"
  chown "root:${tg}" "${rs}"; chmod 3770 "${rs}"
  chown "${tu}:${tg}" "${us}"; chmod 3770 "${us}"

  ## 1. ROOT-owned sticky dir: a non-owner member is BLOCKED (EPERM) -- this is
  ##    the production failure a root-owned share would hit.
  if runuser -u "${tu}" -- setfattr --name user.virtfs.mode --value testval -- "${rs}" 2>/dev/null; then
    printf '%s\n' "FAIL: non-owner member set user.virtfs xattr on a ROOT-owned sticky dir (kernel rule gone; a root-owned share would NOT fail)" >&2
    rc=1
  else
    printf '%s\n' "PASS: non-owner member is BLOCKED (EPERM) from user.virtfs xattr on a root-owned sticky dir"
  fi

  ## 2. USER-owned sticky dir: the OWNER member SUCCEEDS -- so the committed
  ##    user:kvmsf share lets the mapped fixup write its xattrs.
  if runuser -u "${tu}" -- setfattr --name user.virtfs.mode --value testval -- "${us}" 2>/dev/null; then
    printf '%s\n' "PASS: owner member CAN set user.virtfs xattr on a user-owned sticky dir (mapped fixup works)"
  else
    printf '%s\n' "FAIL: owner member BLOCKED from user.virtfs xattr on a user-owned sticky dir (share would lose group access)" >&2
    rc=1
  fi

  ## 3. CANARY assertion 2: flip user_sticky to ROOT-owned and confirm the SAME
  ##    setfattr now FAILS -- proving this test detects the exact root-ownership
  ##    regression (a root-run qemu would have masked it).
  chown "root:${tg}" "${us}"
  if runuser -u "${tu}" -- setfattr --name user.virtfs.mode --value testval2 -- "${us}" 2>/dev/null; then
    printf '%s\n' "FAIL: canary -- setfattr still succeeded after flipping the dir to root-owned (test is INSENSITIVE to the regression)" >&2
    rc=1
  else
    printf '%s\n' "PASS: canary -- flipping the dir to root-owned makes the owner-member setfattr FAIL (test catches the regression)"
  fi

  safe-rm --recursive --force -- "${base}"
  userdel "${tu}" >/dev/null 2>&1 || true
  groupdel "${tg}" >/dev/null 2>&1 || true
  return "${rc}"
}

## qemu:///session needs a non-root user; re-exec as a throwaway one when root.
if [ "$(id -u)" -eq 0 ]; then
  if ! root_host_checks; then
    printf '%s\n' "FAILED: root host-logic assertions" >&2
    exit 1
  fi
  if ! xattr_sticky_regression_check; then
    printf '%s\n' "FAILED: mapped-9p xattr ownership regression check" >&2
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

  ## 2b. user-setup's attach must EMIT fmode=0640,dmode=0750 in the domain XML.
  ##     Without this the boot test's fmode check would only exercise the test's
  ##     OWN qemu line, never catching user-setup dropping fmode (so a guest-
  ##     written host inode would be 0600, host "sysmaint" could not read it).
  ##     Quote-agnostic: libvirt may emit single or double quotes.
  for vm in "${domain_list[@]}"; do
    local xml
    xml="$(virsh -c qemu:///session dumpxml --inactive "${vm}")"
    if grep --quiet --extended-regexp "fmode=['\"]0640['\"]" <<< "${xml}" \
      && grep --quiet --extended-regexp "dmode=['\"]0750['\"]" <<< "${xml}"; then
      pass "${vm}: user-setup emitted fmode=0640,dmode=0750 on the mapped share"
    else
      fail "${vm}: mapped share is missing fmode=0640/dmode=0750 in the domain XML"
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
