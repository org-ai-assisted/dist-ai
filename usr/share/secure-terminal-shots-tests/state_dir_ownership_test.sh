#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the shots state dir /tmp fallback (used only when XDG_RUNTIME_DIR is absent)
## must not TRUST a pre-existing entry planted by another local user in world-writable /tmp.
## lib-capture creates the dir fresh 0700 or reuses ONLY a plain directory we own; a symlink
## or a regular file planted at the path is REFUSED (sourcing fails), and a loosely-permissioned
## dir we own is tightened to 0700.
##
## Subject: lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR, a checkout default, or the
## installed path. Absent -> exit 1 (FATAL): a required subject is an environment bug (R-220). Creates dirs/symlinks under mktemp
## trees only (its OWN throwaway paths); run it in the sandbox.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/lib-capture.sh" \
   "${script_dir}/../secure-terminal-shots/lib-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/lib-capture.sh" \
   '/usr/share/secure-terminal-shots/lib-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: lib-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

## safe-rm (ships with private-ai-config) does the throwaway-tree cleanup below; the trap
## suppresses its errors, so an absent one would leave the temp tree AND read as a silent
## pass. Require it up front: exit 1 (FATAL, R-220) rather than pretend the run was clean.
if ! type -P safe-rm >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: safe-rm not found (ships with private-ai-config)' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3 (got '$1', want '$2')"
      fail=$(( fail + 1 ))
   fi
}

uid="$(id --user)"
statedir_name="secure-terminal-shots-${uid}"

## Source lib-capture with XDG_RUNTIME_DIR removed (forcing the /tmp fallback) and TMP pointed
## at a controlled throwaway tree. Echoes the source exit code; 0 = accepted, non-0 = refused.
source_with_tmp() {  ## $1=tmp-dir -> echoes the source exit status
   local tmp_dir="$1" rc=0
   # shellcheck source=../secure-terminal-shots/lib-capture.sh
   ( unset XDG_RUNTIME_DIR; TMP="${tmp_dir}"; source "${lib}" ) >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

verdict() {  ## $1=rc -> ACCEPTED (0) or REFUSED (non-0)
   if [ "$1" = '0' ]; then printf '%s' ACCEPTED; else printf '%s' REFUSED; fi
}

## 1. no pre-existing entry: the fallback dir is created fresh, mode 0700.
d1="${work}/fresh"; mkdir -- "${d1}"
check "$(verdict "$(source_with_tmp "${d1}")")" ACCEPTED 'a fresh temp-fallback dir is accepted'
check "$(stat --format='%a' -- "${d1}/${statedir_name}" 2>/dev/null)" 700 \
   'the fresh fallback state dir is created mode 0700'

## 2. a symlink planted at the path (redirection attack) is refused.
d2="${work}/symlink"; mkdir -- "${d2}"
ln --symbolic -- /etc "${d2}/${statedir_name}"
check "$(verdict "$(source_with_tmp "${d2}")")" REFUSED 'a symlink planted at the fallback path is refused'

## 3. a regular file planted at the path is refused.
d3="${work}/file"; mkdir -- "${d3}"
touch -- "${d3}/${statedir_name}"
check "$(verdict "$(source_with_tmp "${d3}")")" REFUSED 'a regular file planted at the fallback path is refused'

## 4. an existing directory we OWN at 0700 is reused (accepted).
d4="${work}/owned700"; mkdir -- "${d4}"
mkdir --mode 0700 -- "${d4}/${statedir_name}"
check "$(verdict "$(source_with_tmp "${d4}")")" ACCEPTED 'an existing owned 0700 state dir is reused'

## 5. an existing directory we OWN but loosely-permissioned is accepted AND tightened to 0700.
d5="${work}/owned755"; mkdir -- "${d5}"
mkdir --mode 0755 -- "${d5}/${statedir_name}"
check "$(verdict "$(source_with_tmp "${d5}")")" ACCEPTED 'an existing owned loose state dir is reused'
check "$(stat --format='%a' -- "${d5}/${statedir_name}" 2>/dev/null)" 700 \
   'a loosely-permissioned owned state dir is tightened to 0700'

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: shots temp-fallback state dir refuses planted entries and stays private'
