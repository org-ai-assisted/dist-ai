#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-mok-extract streams the per-machine MOK PUBLIC cert back to the caller
## (dm-calamares-install --mok-enroll) over STDOUT, which enrolls it verbatim into the
## UEFI MokListRT. STDOUT is therefore a strict DATA channel: nothing but the DER cert
## may appear on it. A stray line from the inner vbox-disk-extract prepended its
## diagnostic ("vbox-disk-extract: extracted ... -> ...") to the DER, so the enrolled
## MokListRT held "<ascii text>\n<DER>"; the kernel rejected that malformed cert
## (-EBADMSG) and EVERY module signed by the MOK (tirdad, VBox Guest Additions) failed
## "Key was rejected by service" under Secure Boot. This drives the REAL vbox-mok-extract
## with a stub extractor that reproduces that stdout pollution and asserts stdout carries
## EXACTLY the DER -- it FAILS on the unredirected code, PASSES once the inner stdout is
## routed to stderr.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${VBOX_MOK_EXTRACT_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -x "${test_dir}/../../libexec/image-test/vbox-mok-extract" ]; then
      subject="${test_dir}/../../libexec/image-test/vbox-mok-extract"
   else
      subject='/usr/libexec/image-test/vbox-mok-extract'
   fi
fi
[ -x "${subject}" ] || { printf '%s\n' "FATAL: vbox-mok-extract not found at ${subject}" >&2; exit 1; }

work="$(mktemp --directory --tmpdir mok-extract-stdout-test.XXXXXX)"

## vbox-mok-extract derives the request dir from the CALLER's passwd home (unspoofable
## PRIVLEAP_CALLER_UID), not an env var, so the request MUST live under the real home.
## The slot is shared: REFUSE to run when it is already occupied or symlinked (below), so
## the test never clobbers a concurrent real MOK request and never follows a symlink on
## write. Only files WE create are cleaned up (created flag), so a refusal leaves the real
## slot untouched.
uid="$(id -u)"
home="$(getent passwd "${uid}" | cut -d: -f6)"
req="${home}/.cache/vbox-mok-extract"
req_preexisted='true'
[ -d "${req}" ] || req_preexisted='false'
created='false'

cleanup() {
   if [ "${created}" = 'true' ]; then
      safe-rm --force -- "${req}/disk" "${req}/passphrase" "${req}/fakedisk" 2>/dev/null || true
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

## Refuse an occupied or symlinked slot before any write: a symlinked request dir would
## redirect every write, and an existing disk/passphrase/fakedisk means a concurrent real
## MOK request we must not clobber. Runs while created='false', so the early exit leaves
## the slot untouched.
## Residual scope: a request RACING in after this check (or an adversary with write access
## to the real home) is OUT of scope -- req is a fixed real-home path, so full race-safety
## would need an isolated test home/account, DELIBERATELY not done (the threat here is a
## realistic pre-existing-slot accident, not a live MOK enrollment during the sub-second
## test). Do NOT "fix" the residual with an isolated account. The leaf writes below still
## close the write-time window with noclobber (O_EXCL).
[ -L "${req}" ] && { printf '%s\n' "FATAL: ${req} is a symlink; refusing" >&2; exit 1; }
for leaf in disk passphrase fakedisk; do
   if [ -e "${req}/${leaf}" ] || [ -L "${req}/${leaf}" ]; then
      printf '%s\n' "FATAL: ${req}/${leaf} exists; refusing to clobber a concurrent MOK request" >&2
      exit 1
   fi
done

## Request: a caller-owned dummy disk (owner == PRIVLEAP_CALLER_UID passes the wrapper's
## ownership gate) + a passphrase file. The stub ignores both; the owner check is real.
## noclobber makes each create O_EXCL: if the slot was raced after the guard (a leaf
## symlink or file planted post-check), the create FAILS loudly instead of following the
## symlink or clobbering a concurrent request.
mkdir --parents -- "${req}"
created='true'
disk="${req}/fakedisk"
set -o noclobber
printf '%s' '' > "${disk}"
printf '%s\n' "${disk}" > "${req}/disk"
printf '%s' 'irrelevant' > "${req}/passphrase"
set +o noclobber

## Fixed "DER" payload: a leading 0x30 (SEQUENCE) + bytes incl. a NUL and a high byte, so
## a text-mangling channel is caught. base64-decoded (binary, incl. NUL, cannot go through
## a '%s' printf). The test asserts byte-exactness, not X.509 validity.
der="${work}/cert.der"
printf '%s' 'MIIBKgABAv9NT0tDRVJUQk9EWX8A' | base64 --decode > "${der}"

## Stub extractor: reproduces the ORIGINAL bug -- a diagnostic on STDOUT -- and writes the
## DER to --dest. If the wrapper does not isolate stdout, this line pollutes the cert.
stub="${work}/vbox-disk-extract-stub"
cat > "${stub}" <<STUB
#!/bin/bash
dest=''
while [ "\$#" -gt 0 ]; do
   case "\$1" in
      --dest) dest="\$2"; shift 2 ;;
      *) shift ;;
   esac
done
printf '%s\n' "vbox-disk-extract: extracted /var/lib/dkms/mok.pub -> DEST-REDACTED"
cp -- "${der}" "\${dest}"
STUB
chmod +x "${stub}"

out="${work}/out.bin"
PRIVLEAP_CALLER_UID="${uid}" VBOX_DISK_EXTRACT="${stub}" "${subject}" > "${out}" 2>/dev/null

check "wrapper stdout is EXACTLY the DER cert (no diagnostic prefix)" \
   "$(cmp --silent -- "${der}" "${out}" && printf '%s' "true" || printf '%s' "false")"
check "wrapper stdout begins with the DER SEQUENCE byte 0x30" \
   "$([ "$(head -c1 -- "${out}" | od -An -tx1 | tr -d ' ')" = '30' ] && printf '%s' "true" || printf '%s' "false")"
check "no 'vbox-disk-extract: extracted' text leaked onto stdout" \
   "$(LC_ALL=C grep --quiet --text -- 'vbox-disk-extract: extracted' "${out}" && printf '%s' "false" || printf '%s' "true")"

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} mok-extract-stdout assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all mok-extract-stdout assertions passed'
