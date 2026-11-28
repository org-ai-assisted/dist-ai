#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai behaviour test for libvirt-dist's per-user setup (user-setup) + root
## install, HOST side, no boot. The multi-account model: the root libvirt-dist
## install creates group kvmsf and the shared folder at ${LIBVIRT_DIST_SHARED_DIR
## :-/mnt/shared} owned root:kvmsf mode 2770 (setgid + group rwx, NO world,
## NON-sticky) -- a system path both "user" and "sysmaint" reach via the group (a
## $HOME dir could not be cross-account traversable). NON-sticky: under 9p
## accessmode=mapped qemu runs as the kvmsf-member "user" and records guest perms
## as user.virtfs.* xattrs here, and the kernel blocks a non-owner's user.* xattr
## write ONLY on a STICKY dir -- so a sticky share would EPERM and lose group
## access. ROOT-owned: a member cannot chmod the host dir open. user-setup no
## longer creates the dir: it requires it and attaches it (9p
## accessmode='mapped,fmode=0640,dmode=0750') to all three domains.
##
## Two lanes:
##   ROOT lane (CI/sandbox only, root_host_checks + xattr_sticky_regression_check)
##   -- runs the REAL install against a throwaway LIBVIRT_DIST_SHARED_DIR (never
##   real /mnt/shared) and asserts:
##     - install makes the share root:kvmsf 2770 (non-sticky);
##     - the mapped-9p host-dir rule at the VFS level (no boot): on the shipped
##       root:kvmsf 2770 non-sticky dir a non-owner kvmsf member CAN write
##       user.virtfs.* xattrs (canary: setting the sticky bit BLOCKS it, EPERM --
##       the mapped-break); and a member CANNOT chmod the root-owned dir open
##       (canary: a user-owned dir lets the member chmod it -- the chmod-open
##       hole). A root-run qemu would mask the xattr rule via CAP_FOWNER;
##     - install is an idempotent self-heal: a member dropped from kvmsf is
##       re-added by a second install run, and install.service carries no
##       run-once guard (so ExecStart re-applies every boot).
##   UNPRIVILEGED lane (also the dev-host path) -- drives only user-setup's
##   attach via qemu:///session, non-invasive (no real group/mnt mutation):
##     - the shared dir keeps mode 2770 (setgid, no world bit, non-sticky);
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
for cmd in virsh virt-xml qemu-img runuser safe-rm setfattr; do
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
## re-apply and the root:kvmsf 2770 dir need root AND mutate system groups, so
## they run ONLY as root, against a throwaway LIBVIRT_DIST_SHARED_DIR (never the
## real /mnt/shared). Exits non-zero on any failure; returns 0 otherwise.
root_host_checks() {
  local idem_parent idem_dir owner group mode inst_rc rc=0
  ## install presence is guaranteed by the top-level FATAL check.
  if ! getent passwd user >/dev/null; then
    printf '%s\n' "NOTE: account 'user' absent; skipping the root install-idempotency lane"
    return 0
  fi
  ## Nothing non-root traverses idem_dir (the chmod-denial check lives in the
  ## xattr regression lane), so the default mktemp base is fine.
  idem_parent="$(mktemp --directory)"
  idem_dir="${idem_parent}/shared"

  ## A. install makes the share ROOT:kvmsf 2770 -- NON-sticky. Under 9p
  ##    accessmode=mapped qemu runs as the kvmsf-member "user" and records guest
  ##    perms as user.virtfs.* xattrs here; the kernel blocks a non-owner's
  ##    user.* xattr write ONLY on a STICKY dir, so 2770 (no sticky) lets the
  ##    mapped fixup through while ROOT ownership stops a member chmod-ing the
  ##    host dir open to all local uids (see xattr_sticky_regression_check). The
  ##    guest-side view stays 3770-sticky via the mapped xattrs (mount-shared).
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
  if [ "${owner}" = 'root' ] && [ "${group}" = 'kvmsf' ] && [ "${mode}" = '2770' ]; then
    printf '%s\n' "PASS: install made ${idem_dir} owner root, group kvmsf, mode 2770 (non-sticky)"
  else
    printf '%s\n' "FAIL: install left ${idem_dir} owner=${owner} group=${group} mode=${mode} (want root kvmsf 2770)" >&2
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

## The mapped-9p host-dir config, at the VFS level (no qemu boot needed -- a
## root-run qemu would MASK the xattr rule via CAP_FOWNER, exactly the bug this
## guards). qemu:///session runs qemu UNPRIVILEGED (as the kvmsf-member "user")
## and records guest perms as user.virtfs.* xattrs on the host share. Two kernel
## rules decide the one correct host-dir config (root:kvmsf 2770, NON-sticky):
##  - a non-owner's user.* xattr write is blocked ONLY by the STICKY bit (not by
##    ownership), so the share MUST be non-sticky or the mapped fixup EPERMs and
##    loses group access;
##  - chmod needs ownership, so ROOT ownership stops a kvmsf member chmod-ing the
##    host dir open to all local uids (a user-owned share is a local-exposure
##    hole). Assert both directly + CANARY each against its regression.
xattr_sticky_regression_check() {
  local base shipped tg='libvirtdist-xattrtest' tu='libvirtdist-xattrprobe' rc=0
  ## This fn runs under `if !` (errexit OFF), so EVERY setup step's rc is checked
  ## explicitly -- an unchecked failure would make a probe fail for the WRONG
  ## reason and masquerade as a real (or a false-skip) result.
  ## mktemp FIRST: an empty base would make the setfattr probe below fail and look
  ## like "fs lacks xattr support" -- a false SKIP. mktemp failure is FATAL here.
  if ! base="$(mktemp --directory -- /var/lib/libvirt-dist-xattr.XXXXXX)" \
    || [ -z "${base}" ]; then
    printf '%s\n' "FAIL: mktemp could not create the xattr probe dir under /var/lib" >&2
    return 1
  fi
  chmod 0755 -- "${base}"
  ## setfattr is a REQUIRED command (checked at startup), so a failure HERE is a
  ## genuine fs limitation (tmpfs often lacks user.* xattrs), not a missing tool.
  if ! setfattr --name user.probe --value x -- "${base}" 2>/dev/null; then
    safe-rm --recursive --force -- "${base}"
    printf '%s\n' "SKIP: /var/lib fs lacks user.* xattr support (cannot test the mapped-9p host-dir rule)" >&2
    exit 77  ## style-ok: allow-skip: the mapped user.virtfs xattr rule needs a user-xattr-capable fs
  fi
  setfattr --remove user.probe -- "${base}" 2>/dev/null || true
  ## Probe group + user, with MEMBERSHIP asserted: a pre-existing tu with a
  ## different group would skip useradd and NOT be in tg, so the group-write probe
  ## would fail for not-a-member rather than the sticky/ownership rule. usermod
  ## guarantees membership; the case test (pipe-free, R-161) asserts it.
  groupadd --force "${tg}"
  id "${tu}" >/dev/null 2>&1 \
    || useradd --no-create-home --no-user-group --gid "${tg}" "${tu}"
  usermod --append --groups "${tg}" "${tu}" >/dev/null 2>&1 || true
  case " $(id -nG "${tu}" 2>/dev/null) " in
    *" ${tg} "*)
      ;;
    *)
      printf '%s\n' "FAIL: probe user ${tu} is not a member of ${tg} -- cannot test the group-write rule" >&2
      safe-rm --recursive --force -- "${base}"
      userdel "${tu}" >/dev/null 2>&1 || true
      groupdel "${tg}" >/dev/null 2>&1 || true
      return 1
      ;;
  esac
  ## The SHIPPED host-dir config: root:kvmsf 2770 (setgid, group rwx, NON-sticky).
  ## Each setup step's rc checked so a failed chown/chmod cannot make the sticky /
  ## chmod-open conclusions fire for the wrong reason.
  shipped="${base}/shipped"
  if ! mkdir "${shipped}" \
    || ! chown "root:${tg}" "${shipped}" \
    || ! chmod 2770 "${shipped}"; then
    printf '%s\n' "FAIL: could not set up the root:kvmsf 2770 probe dir" >&2
    safe-rm --recursive --force -- "${base}"
    userdel "${tu}" >/dev/null 2>&1 || true
    groupdel "${tg}" >/dev/null 2>&1 || true
    return 1
  fi

  ## 1. SHIPPED (root:kvmsf 2770, non-sticky): a non-owner kvmsf member CAN set
  ##    user.virtfs.* -- so the mapped fixup qemu-as-"user" performs works.
  if runuser -u "${tu}" -- setfattr --name user.virtfs.mode --value testval -- "${shipped}" 2>/dev/null; then
    printf '%s\n' "PASS: non-owner member CAN set user.virtfs xattr on the shipped root:kvmsf 2770 non-sticky dir (mapped fixup works)"
  else
    printf '%s\n' "FAIL: non-owner member BLOCKED from user.virtfs xattr on root:kvmsf 2770 (mapped share would lose group access)" >&2
    rc=1
  fi

  ## 2. CANARY for the STICKY regression: set the sticky bit (-> 3770 root-owned)
  ##    and confirm the SAME xattr write now BLOCKS (EPERM) -- the exact config
  ##    that breaks mapped-9p. Reset to 2770 afterwards for assertion 3.
  chmod 3770 "${shipped}"
  if runuser -u "${tu}" -- setfattr --name user.virtfs.mode --value testval2 -- "${shipped}" 2>/dev/null; then
    printf '%s\n' "FAIL: canary -- xattr write still succeeded after setting the sticky bit (test is INSENSITIVE to the sticky regression)" >&2
    rc=1
  else
    printf '%s\n' "PASS: canary -- setting the sticky bit (3770) BLOCKS the member xattr write (EPERM); test catches the mapped-break regression"
  fi
  chmod 2770 "${shipped}"

  ## 3. CHMOD-OPEN protection (root ownership): a non-owner member CANNOT chmod
  ##    the root-owned 2770 dir open -- only the owner (root) or CAP_FOWNER may.
  if runuser -u "${tu}" -- chmod 0755 "${shipped}" 2>/dev/null; then
    printf '%s\n' "FAIL: non-owner member chmod-ed the ROOT-owned share open (root ownership not protecting it)" >&2
    rc=1
  else
    printf '%s\n' "PASS: non-owner member is BLOCKED (EPERM) from chmod-ing the root-owned 2770 share open"
  fi

  ## 4. CANARY for the CHMOD-OPEN hole: chown the dir to the member (the round-6
  ##    user:kvmsf config) and confirm the member's chmod now SUCCEEDS -- proving
  ##    this test detects the local-exposure regression a user-owned share is.
  chown "${tu}:${tg}" "${shipped}"
  if runuser -u "${tu}" -- chmod 0755 "${shipped}" 2>/dev/null; then
    printf '%s\n' "PASS: canary -- a user-owned share lets the member chmod it open; test catches the chmod-open hole"
  else
    printf '%s\n' "FAIL: canary -- member could NOT chmod even a user-owned dir (test is INSENSITIVE to the chmod-open hole)" >&2
    rc=1
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
  install --directory --mode 2770 -- "${shared_dir}"
  export LIBVIRT_DIST_SHARED_DIR="${shared_dir}"

  ## Drive the real user-setup (attach only) with an isolated HOME.
  HOME="${test_home}" XDG_STATE_HOME="${test_home}/.local/state" "${user_setup}"

  ## 1. Shared dir keeps mode 2770 (setgid, group rwx, no world, NON-sticky):
  ##    mirrors the shipped host dir; user-setup only ATTACHES and must not alter
  ##    it. Host dir is non-sticky by design (the guest view is sticky 3770 via
  ##    the mapped xattrs); world access is never opened.
  local mode
  mode="$(stat --format='%a' -- "${shared_dir}")"
  if [ "${mode}" = "2770" ]; then
    pass "shared dir ${shared_dir} is mode 2770 (setgid, no world bit, non-sticky); user-setup left it unchanged"
  else
    fail "shared dir mode is ${mode}, want 2770 (setgid, no world, non-sticky)"
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
  ##     ANCHORED: extract the <filesystem> block whose <source dir> is shared_dir
  ##     and assert BOTH attrs ON THAT element -- unanchored whole-XML greps would
  ##     false-pass if fmode/dmode landed on a different device or were absent from
  ##     the shared one. Quote-agnostic: libvirt may emit single or double quotes.
  for vm in "${domain_list[@]}"; do
    local xml fsblock
    xml="$(virsh -c qemu:///session dumpxml --inactive "${vm}")"
    fsblock="$(awk -v sd="${shared_dir}" '
      index($0, "<filesystem") { infs = 1; buf = $0; hassrc = 0; next }
      infs { buf = buf ORS $0 }
      infs && (index($0, "dir=\"" sd "\"") || index($0, "dir=\047" sd "\047")) { hassrc = 1 }
      index($0, "</filesystem>") { if (infs && hassrc) { print buf } infs = 0 }
    ' <<< "${xml}")"
    if [ -n "${fsblock}" ] \
      && grep --quiet --extended-regexp "fmode=['\"]0640['\"]" <<< "${fsblock}" \
      && grep --quiet --extended-regexp "dmode=['\"]0750['\"]" <<< "${fsblock}"; then
      pass "${vm}: user-setup emitted fmode=0640,dmode=0750 on the shared-dir mapped device"
    else
      fail "${vm}: the shared-dir <filesystem> device is missing fmode=0640/dmode=0750 in the domain XML"
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
