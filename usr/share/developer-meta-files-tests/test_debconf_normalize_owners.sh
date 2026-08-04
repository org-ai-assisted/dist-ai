#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-tmp-hardcode -- the '/tmp/' in the ucf fixture below is the path
## ucf itself records in config.dat, not a temp file this test creates.

## dm-debconf-normalize-owners must make config.dat 'Owners:' byte-identical
## regardless of which package-name spelling(s) registered each question.
##
## THE PROPERTY THAT MATTERS: a build that recorded 'shim-signed' only, one that
## recorded 'shim-signed:amd64' only, and one that recorded both must all produce
## the SAME normalized output -- that convergence is what makes a local image and
## a CI image byte-identical. Inputs are the exact dual-spelling Owners lines
## observed in a real CI Kicksecure image (shim-signed, libc6, libpam0g).
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
tool="${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-debconf-normalize-owners"
if [ ! -x "${tool}" ]; then
   tool="$( type -P dm-debconf-normalize-owners || true )"
fi
if [ -z "${tool}" ] || [ ! -x "${tool}" ]; then
   printf '%s\n' "SKIP: dm-debconf-normalize-owners not found (set DERIVATIVE_MAKER_DIR)." >&2
   exit 77
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## Normalize a config.dat body (passed on stdin) and echo the resulting
## Owners line(s), so a case can assert on the canonical form directly.
normalize_body() {
   local f="${work_dir}/case.dat"
   cat > "${f}"
   "${tool}" "${f}" >/dev/null
   grep '^Owners:' "${f}"
}

## A realistic stanza wrapper: the normalizer must only touch 'Owners:' lines,
## leaving Name/Template/Value intact.
stanza() {
   ## $1 = owners line content (after 'Owners: ')
   printf '%s\n' \
      "Name: shim-signed/no-valid-sigs" \
      "Template: shim-signed/no-valid-sigs" \
      "Value: " \
      "Owners: $1" \
      "Flags: seen"
}

## --- 1. all three spellings converge to the SAME output ---------------------
out_both="$( stanza 'shim-signed, shim-signed:amd64' | normalize_body )"
out_arch="$( stanza 'shim-signed:amd64'              | normalize_body )"
out_bare="$( stanza 'shim-signed'                    | normalize_body )"
if [ "${out_both}" = "Owners: shim-signed" ] \
   && [ "${out_arch}" = "Owners: shim-signed" ] \
   && [ "${out_bare}" = "Owners: shim-signed" ]; then
   pass 'dual, arch-only and bare-only all converge to "Owners: shim-signed"'
else
   fail "did not converge: both=[${out_both}] arch=[${out_arch}] bare=[${out_bare}]"
fi

## --- 2. a multi-owner line dedupes but keeps distinct packages, in order ----
## The real 'libc6, libc6:amd64, libpam0g:amd64' must become 'libc6, libpam0g'.
out_multi="$( stanza 'libc6, libc6:amd64, libpam0g:amd64' | normalize_body )"
if [ "${out_multi}" = "Owners: libc6, libpam0g" ]; then
   pass 'multi-owner line dedupes arch spellings, keeps distinct packages in order'
else
   fail "multi-owner wrong: [${out_multi}]"
fi

## --- 3. idempotent: a second pass changes nothing ---------------------------
f="${work_dir}/idem.dat"
stanza 'shim-signed, shim-signed:amd64' > "${f}"
"${tool}" "${f}" >/dev/null
first="$( cat "${f}" )"
"${tool}" "${f}" >/dev/null
if [ "${first}" = "$( cat "${f}" )" ]; then
   pass 'idempotent: a second normalization is a no-op'
else
   fail 'second pass changed the file'
fi

## --- 4. non-Owners lines are untouched --------------------------------------
f="${work_dir}/other.dat"
stanza 'shim-signed:amd64' > "${f}"
"${tool}" "${f}" >/dev/null
if grep -q '^Name: shim-signed/no-valid-sigs$' "${f}" \
   && grep -q '^Template: shim-signed/no-valid-sigs$' "${f}" \
   && grep -q '^Flags: seen$' "${f}"; then
   pass 'Name/Template/Flags lines are left untouched'
else
   fail 'a non-Owners line was altered'
fi

## --- 5. a question-name that CONTAINS a slash is not an owner: only 'Owners:'
## lines are rewritten, so templates.dat-style content is safe if ever passed.
f="${work_dir}/slash.dat"
printf '%s\n' 'Owners: shim-signed/no-valid-sigs' > "${f}"
"${tool}" "${f}" >/dev/null
## No ':' present, so it must pass through unchanged (a slash is not stripped).
if [ "$( cat "${f}" )" = "Owners: shim-signed/no-valid-sigs" ]; then
   pass 'an owner without a colon is passed through verbatim'
else
   fail "slash owner altered: [$( cat "${f}" )]"
fi

## --- 6. the file's mode is preserved (atomic replace must not reset it) ------
## debconf's config.dat is 0600; a rename from a default-mode temp would drop it.
f="${work_dir}/mode.dat"
stanza 'shim-signed:amd64' > "${f}"
chmod 0640 "${f}"
"${tool}" "${f}" >/dev/null
mode="$( stat -c '%a' "${f}" )"
if [ "${mode}" = "640" ]; then
   pass 'the file mode is preserved across normalization'
else
   fail "mode changed to ${mode} (expected 640)"
fi

## --- 7. a filename ending in '|' is read as a PATH, not run as a command ----
## Perl's diamond over an @ARGV filename uses 2-argument open, so a name ending
## in '|' would run everything before it as a shell command. A filename cannot
## contain '/', so the probe command writes a marker in the CURRENT directory:
## run the tool from a scratch dir and assert the marker never appears.
meta_dir="${work_dir}/meta"
mkdir -p "${meta_dir}"
## Name = "touch PWNED |": under the old @ARGV code perl would run 'touch PWNED'.
evil_name='touch PWNED |'
( cd "${meta_dir}" && stanza 'shim-signed:amd64' > "${evil_name}" )
( cd "${meta_dir}" && "${tool}" "${evil_name}" >/dev/null )
if [ ! -e "${meta_dir}/PWNED" ] \
   && grep -q '^Owners: shim-signed$' "${meta_dir}/${evil_name}"; then
   pass 'a filename ending in a pipe is read as a path, not executed'
else
   fail 'a metacharacter filename was mishandled (possible command execution)'
fi

## --- 8. CANARY: the tool can fail (bad args) --------------------------------
status=0
"${tool}" >/dev/null 2>&1 || status="$?"
if [ "${status}" -ne 0 ]; then
   pass 'canary: no-argument invocation exits non-zero'
else
   fail 'canary broken: the tool exits 0 with no arguments'
fi

## --- 9. CANARY: the fixture really carries the dual spelling ----------------
if stanza 'shim-signed, shim-signed:amd64' | grep -q 'shim-signed:amd64'; then
   pass 'canary: the fixture carries the arch-qualified spelling under test'
else
   fail 'canary broken: the fixture lost the arch spelling'
fi

## --- 10. transient mktemp path in a substitution variable is normalized ------
## ucf records the temp copy it diffed a conffile against, e.g.
## 'NEW = /tmp/grub.JI3HRI56IT'. The random suffix differs every build (it was
## the last ISO local-vs-CI difference), so two builds must CONVERGE, while a
## real (non-mktemp) value like FILE = /etc/default/grub is left intact. FAILS on
## the pre-fix tool, which normalized only Owners.
ucf_stanza() {
   ## $1 = the random mktemp suffix. KEEP is a decoy: a /tmp value under a
   ## NON-NEW key with a >=6-char suffix, which must survive (the match is
   ## anchored to the NEW key, not to any /tmp path).
   printf '%s\n' \
      "Name: ucf/changeprompt" \
      "Template: ucf/changeprompt" \
      "Value: keep_current" \
      "Owners: ucf" \
      "Variables:" \
      " BASENAME = grub" \
      " FILE = /etc/default/grub" \
      " KEEP = /tmp/cache.release" \
      " NEW = /tmp/grub.$1"
}
ucf_stanza 'JI3HRI56IT' > "${work_dir}/ua.dat"
ucf_stanza 'GvtL9uK0zG' > "${work_dir}/ub.dat"
"${tool}" "${work_dir}/ua.dat" >/dev/null
"${tool}" "${work_dir}/ub.dat" >/dev/null
out_a="$( cat "${work_dir}/ua.dat" )"
out_b="$( cat "${work_dir}/ub.dat" )"
if [ "${out_a}" = "${out_b}" ] \
   && printf '%s\n' "${out_a}" | grep -q '^ NEW = /tmp/grub[.]XXXXXX$' \
   && printf '%s\n' "${out_a}" | grep -q '^ FILE = /etc/default/grub$' \
   && printf '%s\n' "${out_a}" | grep -q '^ KEEP = /tmp/cache[.]release$'; then
   pass 'ucf NEW mktemp path converges; a non-NEW /tmp value and a real value are untouched'
else
   fail "tmp-path normalization: converge/precision failed: a=[${out_a}] b=[${out_b}]"
fi

printf '%s\n' "===== dm-debconf-normalize-owners: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
