#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai behaviour test for libvirt-dist's per-user setup (user-setup), HOST
## side, NON-INVASIVE. The multi-account model: the root libvirt-dist install
## creates group kvmsf and the shared folder at ${LIBVIRT_DIST_SHARED_DIR:-
## /mnt/shared} owned user:kvmsf mode 3770 (setgid + sticky, NO world) -- a system path so
## both "user" and "sysmaint" reach it (a $HOME dir could not be cross-account
## traversable). user-setup no longer creates the dir: it requires it and
## attaches it (9p accessmode='mapped') to all three domains.
##
## This lane runs in the normal suite, possibly on a dev host, so it does NOT run
## the root install and does NOT mutate real system groups or real /mnt. Instead
## it points LIBVIRT_DIST_SHARED_DIR at a temp dir it pre-creates at mode 3770
## and drives only user-setup's attach. Under test:
##   - the shared dir is mode 3770 (setgid + sticky, no world bit) -- never world-exposed,
##     sticky so kvmsf members cannot unlink each other's files;
##   - user-setup attaches ONE 9p accessmode='mapped' filesystem per domain whose
##     source is that dir;
##   - a re-run appends no duplicate filesystem device (dup guard);
##   - user-setup FAILS LOUD (non-zero) when the shared dir is missing (it must
##     not attach a dangling source -- the root install is a prerequisite).
##
## Drives the REAL user-setup via qemu:///session (define/attach never open an
## image, so no VM images and no KVM are needed; user-setup rewrites 'kvm' ->
## 'qemu' itself when KVM is absent). qemu:///session auto-spawns a per-USER
## libvirtd, so it must NOT run as root; when invoked as root it re-execs via
## runuser as a throwaway unprivileged user. The heavy guest-side boot + the real
## root install live in boot_shared_mount_test.sh.

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

## qemu:///session needs a non-root user; re-exec as a throwaway one when root.
if [ "$(id -u)" -eq 0 ]; then
  test_user='libvirtdisttest'
  if ! id -u "${test_user}" >/dev/null 2>&1; then
    adduser --disabled-password --gecos '' "${test_user}" >/dev/null 2>&1 \
      || { printf '%s\n' "SKIP: cannot create a non-root user for qemu:///session" >&2; exit 77; }  ## style-ok: allow-skip: qemu:///session needs a non-root user; unprivileged lane cannot create one
  fi
  runtime_dir="/run/user/$(id -u "${test_user}")"
  install -d -m 0700 -o "${test_user}" -g "${test_user}" "${runtime_dir}"
  reexec_rc=0
  runuser -u "${test_user}" -- env \
    LIBVIRT_DIST_REPO="${LIBVIRT_DIST_REPO:-}" \
    XDG_RUNTIME_DIR="${runtime_dir}" \
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
