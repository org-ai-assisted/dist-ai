#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the REAL vbox-grub-set-next-boot-mode privleap wrapper with a stub vbox-disk-mount
## (records argv) and assert its NARROW contract: it delegates the correct invocation ONLY
## for a caller-owned disk + a valid mode, and REFUSES (never calls the mounter) otherwise.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
if [ -x "${test_dir}/../../libexec/image-test/vbox-grub-set-next-boot-mode" ]; then
   subject="${test_dir}/../../libexec/image-test/vbox-grub-set-next-boot-mode"
else
   subject='/usr/libexec/image-test/vbox-grub-set-next-boot-mode'
fi
[ -x "${subject}" ] || { printf '%s\n' "FATAL: wrapper not found at ${subject}" >&2; exit 1; }

work="$(mktemp --directory --tmpdir vbox-grub-next-test.XXXXXX)"

## The wrapper derives the request dir from the CALLER's passwd home (unspoofable
## PRIVLEAP_CALLER_UID), not an env var, so the request MUST live under the real home.
## Shared slot: refuse an occupied/symlinked one before any write (same discipline as the
## mok-extract test), clean up only files WE create.
uid="$(id -u)"
home="$(getent passwd "${uid}" | cut -d: -f6)"
[ -n "${home}" ] || { printf '%s\n' "FATAL: uid ${uid} has no home directory" >&2; exit 1; }
req="${home}/.cache/vbox-grub-set-next-boot-mode"
req_preexisted='true'
[ -d "${req}" ] || req_preexisted='false'
created='false'

cleanup() {
   if [ "${created}" = 'true' ]; then
      safe-rm --force -- "${req}/disk" "${req}/passphrase" "${req}/mode" "${req}/fakedisk" "${req}/other_owned" 2>/dev/null || true
      if [ "${req_preexisted}" = 'false' ]; then
         rmdir -- "${req}" 2>/dev/null || true
      fi
   fi
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

failures=0
check() {
   if [ "$2" = 'true' ]; then
      printf '%s\n' "ok: $1"
   else
      printf '%s\n' "FAIL: $1" >&2
      failures=$((failures + 1))
   fi
}

[ -L "${req}" ] && { printf '%s\n' "FATAL: ${req} is a symlink; refusing" >&2; exit 1; }
for leaf in disk passphrase mode fakedisk; do
   if [ -e "${req}/${leaf}" ] || [ -L "${req}/${leaf}" ]; then
      printf '%s\n' "FATAL: ${req}/${leaf} exists; refusing to clobber a concurrent request" >&2
      exit 1
   fi
done

mkdir --parents -- "${req}"
created='true'
disk="${req}/fakedisk"
set -o noclobber
printf '%s' '' > "${disk}"
printf '%s\n' "${disk}" > "${req}/disk"
printf '%s' 'irrelevant' > "${req}/passphrase"
printf '%s' 'persistent-sysmaint' > "${req}/mode"
set +o noclobber

## Stub vbox-disk-mount: record argv, do NOT mount. GRUB_SELECT path need not exist (the
## stub never runs it), but set it to a stable sentinel so the delegated argv is assertable.
argv_log="${work}/vdm.argv"
stub="${work}/vbox-disk-mount-stub"
cat > "${stub}" <<STUB
#!/bin/bash
printf '%s\n' "\$@" > "${argv_log}"
exit 0
STUB
chmod +x "${stub}"
helper_sentinel='/SENTINEL/grub-select-next-boot-mode'

run_wrapper() {
   ## $1 = PRIVLEAP_CALLER_UID value; rc returned, stdout/stderr discarded.
   local rc=0
   PRIVLEAP_CALLER_UID="$1" \
      VBOX_DISK_MOUNT="${stub}" \
      GRUB_SELECT_NEXT_BOOT_MODE="${helper_sentinel}" \
      "${subject}" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## 1. Happy path: caller owns the disk + valid mode -> delegates the exact invocation.
safe-rm --force -- "${argv_log}"
rc="$(run_wrapper "${uid}")"
check "caller-owned disk + valid mode: wrapper succeeds (rc=0, got ${rc})" \
   "$([ "${rc}" = '0' ] && printf '%s' true || printf '%s' false)"
argv="$(tr '\n' ' ' < "${argv_log}" 2>/dev/null || true)"
check "delegates: run --disk <realpath> --passphrase-file <req/passphrase> -- <helper> persistent-sysmaint" \
   "$([ "${argv}" = "run --disk $(realpath -- "${disk}") --passphrase-file ${req}/passphrase -- ${helper_sentinel} persistent-sysmaint " ] && printf '%s' true || printf '%s' false)"

## 2. Ownership refusal: a disk owned by someone OTHER than the caller -> refuse, no mount.
## Pick an other-owned path robustly in both runner contexts: non-root uses root-owned
## /bin/true (owner 0 != uid); a root run (uid 0) chowns a file to uid 1 so the owner
## still differs from the caller (else 0 == 0 would spuriously pass).
if [ "${uid}" = '0' ]; then
   other_owned="${req}/other_owned"
   printf '%s' '' > "${other_owned}"
   chown 1 -- "${other_owned}"
else
   other_owned='/bin/true'
fi
printf '%s\n' "${other_owned}" > "${req}/disk"
safe-rm --force -- "${argv_log}"
rc="$(run_wrapper "${uid}")"
check "root-owned disk refused (rc!=0, got ${rc})" \
   "$([ "${rc}" != '0' ] && printf '%s' true || printf '%s' false)"
check "ownership refusal did NOT call vbox-disk-mount" \
   "$([ ! -e "${argv_log}" ] && printf '%s' true || printf '%s' false)"
printf '%s\n' "${disk}" > "${req}/disk"

## 3. Invalid mode (regex metachar) -> refuse, no mount.
printf '%s' 'live.sysmaint' > "${req}/mode"
safe-rm --force -- "${argv_log}"
rc="$(run_wrapper "${uid}")"
check "invalid mode 'live.sysmaint' refused (rc!=0, got ${rc})" \
   "$([ "${rc}" != '0' ] && printf '%s' true || printf '%s' false)"
check "invalid mode did NOT call vbox-disk-mount" \
   "$([ ! -e "${argv_log}" ] && printf '%s' true || printf '%s' false)"
printf '%s' 'persistent-sysmaint' > "${req}/mode"

## 4. No PRIVLEAP_CALLER_UID -> refuse (must be invoked via privleap).
safe-rm --force -- "${argv_log}"
rc="$(run_wrapper "")"
check "empty PRIVLEAP_CALLER_UID refused (rc!=0, got ${rc})" \
   "$([ "${rc}" != '0' ] && printf '%s' true || printf '%s' false)"

## 5. A SYMLINKED request file must be refused -- a symlink in the caller-owned request dir
## could redirect this root read onto a root-only file. Point req/disk at a symlink.
safe-rm --force -- "${req}/disk" "${argv_log}"
ln --symbolic -- "${disk}" "${req}/disk"
rc="$(run_wrapper "${uid}")"
check "symlinked request file refused (rc!=0, got ${rc})" \
   "$([ "${rc}" != '0' ] && printf '%s' true || printf '%s' false)"
check "symlinked request did NOT call vbox-disk-mount" \
   "$([ ! -e "${argv_log}" ] && printf '%s' true || printf '%s' false)"
safe-rm --force -- "${req}/disk"
printf '%s\n' "${disk}" > "${req}/disk"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} vbox-grub-set-next-boot-mode assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all vbox-grub-set-next-boot-mode assertions passed'
