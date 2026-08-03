#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

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

## --- 6. CANARY: the tool can fail (bad args) --------------------------------
status=0
"${tool}" >/dev/null 2>&1 || status="$?"
if [ "${status}" -ne 0 ]; then
   pass 'canary: no-argument invocation exits non-zero'
else
   fail 'canary broken: the tool exits 0 with no arguments'
fi

## --- 7. CANARY: the fixture really carries the dual spelling ----------------
if stanza 'shim-signed, shim-signed:amd64' | grep -q 'shim-signed:amd64'; then
   pass 'canary: the fixture carries the arch-qualified spelling under test'
else
   fail 'canary broken: the fixture lost the arch spelling'
fi

printf '%s\n' "===== dm-debconf-normalize-owners: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
