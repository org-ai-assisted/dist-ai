#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Probe for test_namespace_propagation.py. It MUST be invoked already inside a
## mapped-root mount namespace:
##   unshare --map-root-user --mount -- bash -- namespace_propagation_probe.bash
## The outer namespace models the GLOBAL (boot/init) mount namespace; a nested
## 'unshare --mount' models a pam_namespace-unshared login SESSION. It emits
## KEY=VALUE lines the Python test parses and asserts on. No real root, no host
## mounts touched (everything lives in a mapped-root user+mount namespace).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

opts() {
  findmnt --noheadings --output OPTIONS --target "${1}"
}

base="$(mktemp --directory -t nsprop.XXXXXX)"
cleanup() {
  umount --lazy -- "${base}/home/.tb" 2>/dev/null || true
  umount --lazy -- "${base}/home" 2>/dev/null || true
  safe-rm --recursive --force -- "${base}"
}
trap cleanup EXIT

fh="${base}/home"
mkdir --parents -- "${fh}"

## Model remount-secure in the GLOBAL (boot) namespace: bind /home, make it
## private (MS_PRIVATE), and remount noexec. This is the exact shape remount-secure
## applies ('mount --make-private --options remount,...').
mount --bind -- "${fh}" "${fh}"
mount --make-private -- "${fh}"
mount --options remount,bind,noexec -- "${fh}"
mkdir --parents -- "${fh}/.tb"
printf '%s\n' "GLOBAL_HOME_OPTS=$(opts "${fh}")"
## A fresh ~/.tb is NOT its own mount; it inherits /home's noexec.
printf '%s\n' "GLOBAL_TB_PRE_OPTS=$(opts "${fh}/.tb")"

## [A] mechanism A: a session-local remount INSIDE the session namespace. Run
## first, while the global ~/.tb is still noexec, so this proves the session-local
## remount itself (not an inherited exec state) makes ~/.tb exec for that session.
a_out="${base}/a_out"
## ${1}/${2} are the CHILD shell's positionals (passed after _), not ours.
# shellcheck disable=SC2016
unshare --mount -- bash -c '
  set -o errexit
  set -o nounset
  fh="${1}"
  out="${2}"
  mount --bind -- "${fh}/.tb" "${fh}/.tb"
  mount --options remount,bind,exec -- "${fh}/.tb"
  findmnt --noheadings --output OPTIONS --target "${fh}/.tb" > "${out}"
' _ "${fh}" "${a_out}"
printf '%s\n' "A_SESSION_TB_OPTS=$(cat -- "${a_out}")"
## The session-local remount must NOT leak back into the global namespace
## (/home is private): global ~/.tb stays noexec.
printf '%s\n' "GLOBAL_TB_AFTER_A_OPTS=$(opts "${fh}/.tb")"

## [B] mechanism B / the current privleapd behavior: the SESSION namespace
## unshares first (pam_namespace), THEN the GLOBAL namespace remounts ~/.tb exec.
## Deterministic handshake (no fixed sleeps): the child signals 'ready' once it
## has unshared, the parent remounts and signals 'go', the child then reads. This
## guarantees the global remount happens AFTER the session has its own namespace.
b_ready="${base}/b_ready"
b_go="${base}/b_go"
b_out="${base}/b_out"
## ${1}..${4} are the CHILD shell's positionals (passed after _), not ours.
# shellcheck disable=SC2016
unshare --mount -- bash -c '
  set -o errexit
  set -o nounset
  fh="${1}"
  ready="${2}"
  go="${3}"
  out="${4}"
  touch -- "${ready}"
  for _ in $(seq 1 600); do
    [ -e "${go}" ] && break
    sleep 0.05
  done
  findmnt --noheadings --output OPTIONS --target "${fh}/.tb" > "${out}"
' _ "${fh}" "${b_ready}" "${b_go}" "${b_out}" &
bpid="${!}"
for _ in $(seq 1 600); do
  [ -e "${b_ready}" ] && break
  sleep 0.05
done
## The global-ns exec remount (what privleapd-as-root does at TB launch).
mount --bind -- "${fh}/.tb" "${fh}/.tb"
mount --options remount,bind,exec -- "${fh}/.tb"
touch -- "${b_go}"
wait "${bpid}"
printf '%s\n' "B_GLOBAL_TB_OPTS=$(opts "${fh}/.tb")"
printf '%s\n' "B_SESSION_TB_OPTS=$(cat -- "${b_out}")"

printf '%s\n' "PROBE_OK=1"
