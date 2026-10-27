#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## image-dup-check flags DUPLICATE milestone screenshots within one run -- two or more
## frames that are pixel-for-pixel identical, the signature of a broken/stale capture
## (a modal host dialog, a frontend that never repainted) that image-blank-check passes
## because the frame is non-blank. Drives the REAL tool against synthetic frames (built
## with ImageMagick); no root, no VM.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

checker="${IMAGE_DUP_CHECK_BIN:-}"
if [ -z "${checker}" ]; then
   if [ -f "${test_dir}/../../bin/image-dup-check" ]; then
      checker="${test_dir}/../../bin/image-dup-check"
   else
      checker='/usr/bin/image-dup-check'
   fi
fi
[ -r "${checker}" ] || { printf '%s\n' "FATAL: image-dup-check not found at ${checker}" >&2; exit 1; }

magick_bin='convert'
if type -P magick >/dev/null 2>&1; then
   magick_bin='magick'
fi

workdir="$(mktemp --directory --tmpdir image-dup-check-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## A directory with a 2-frame duplicate cluster + two distinct frames.
mkdir -- "${workdir}/dups"
"${magick_bin}" -size 64x48 xc:'#123456' "${workdir}/dups/01-a.png"
cp -- "${workdir}/dups/01-a.png" "${workdir}/dups/02-b.png"   ## identical copy -> a cluster
"${magick_bin}" -size 64x48 xc:'#101010' "${workdir}/dups/03-c.png"
"${magick_bin}" -size 64x48 xc:'#202020' "${workdir}/dups/04-d.png"

## Content hashing across formats: a PNG and a LOSSLESS WEBP of the SAME pixels must be
## seen as duplicates (proves decoded-RGB hashing, not a byte-hash that formats would split).
mkdir -- "${workdir}/fmt"
"${magick_bin}" -size 80x60 xc:'#2e6b3a' "${workdir}/fmt/same.png"
"${magick_bin}" "${workdir}/fmt/same.png" -define webp:lossless=true "${workdir}/fmt/same.webp"
"${magick_bin}" -size 80x60 xc:'#6b2e3a' "${workdir}/fmt/other.png"

## A 3-frame identical cluster (for --min-cluster) + one distinct.
mkdir -- "${workdir}/triple"
"${magick_bin}" -size 48x48 xc:'#445566' "${workdir}/triple/t1.png"
cp -- "${workdir}/triple/t1.png" "${workdir}/triple/t2.png"
cp -- "${workdir}/triple/t1.png" "${workdir}/triple/t3.png"
"${magick_bin}" -size 48x48 xc:'#665544' "${workdir}/triple/u.png"

## All-distinct frames -> must NOT flag.
mkdir -- "${workdir}/distinct"
"${magick_bin}" -size 50x50 xc:'#111111' "${workdir}/distinct/d1.png"
"${magick_bin}" -size 50x50 xc:'#222222' "${workdir}/distinct/d2.png"
"${magick_bin}" -size 50x50 xc:'#333333' "${workdir}/distinct/d3.png"

## A legitimately-repeating view: two identical frames sharing a dash-suffix token
## ('NN-idle-terminal') -> flagged by default, exempt via --allow idle-terminal.
mkdir -- "${workdir}/legit"
"${magick_bin}" -size 60x40 xc:'#0a0a0a' "${workdir}/legit/11-idle-terminal.png"
cp -- "${workdir}/legit/11-idle-terminal.png" "${workdir}/legit/22-idle-terminal.png"

## Two same-content frames of DIFFERENT size must NOT collide (size is part of identity).
mkdir -- "${workdir}/sizes"
"${magick_bin}" -size 40x40 xc:'#777777' "${workdir}/sizes/s_small.png"
"${magick_bin}" -size 80x80 xc:'#777777' "${workdir}/sizes/s_big.png"

pass=0
fail=0
expect_rc() {
   ## $1 description, $2 expected-rc, $3.. args
   local desc="$1" want="$2"
   shift 2
   local got=0
   "${checker}" "$@" >/dev/null 2>&1 || got=$?
   if [ "${got}" -eq "${want}" ]; then
      printf '%s\n' "PASS: ${desc}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${desc} (rc=${got}, want ${want})" >&2
      fail=$((fail + 1))
   fi
}

expect_rc "a 2-frame duplicate cluster is flagged"           1 "${workdir}/dups"
expect_rc "all-distinct frames are NOT flagged"              0 "${workdir}/distinct"
expect_rc "PNG == lossless WEBP of same pixels is a dup"     1 "${workdir}/fmt"
expect_rc "same content, different SIZE is NOT a dup"        0 "${workdir}/sizes"
## A single file cannot form a cluster.
expect_rc "a single frame is NOT flagged"                    0 "${workdir}/dups/03-c.png"

## --allow excludes a legitimately-repeating view by dash-suffix token.
expect_rc "legit repeat is flagged by default"               1 "${workdir}/legit"
expect_rc "--allow exempts the repeating view"               0 --allow idle-terminal "${workdir}/legit"

## FAIL-CLOSED: a no-alnum token ('' / '.' / '-') must exempt NOTHING.
expect_rc "--allow '' does not exempt (not fail-open)"       1 --allow '' "${workdir}/dups"
expect_rc "--allow . does not exempt (not fail-open)"        1 --allow . "${workdir}/dups"
expect_rc "--allow - does not exempt (not fail-open)"        1 --allow - "${workdir}/dups"

## --min-cluster: a 2-dup is below a threshold of 3; a 3-dup meets it.
expect_rc "2-dup below --min-cluster 3 is NOT flagged"       0 --min-cluster 3 "${workdir}/dups"
expect_rc "3-dup meets --min-cluster 3"                      1 --min-cluster 3 "${workdir}/triple"
expect_rc "--min-cluster 1 is a usage error"                 2 --min-cluster 1 "${workdir}/dups"

## CANARY: a detector that flagged NOTHING would fail every '1' case above; one that
## flagged EVERYTHING would fail every '0' case (all-distinct, different-size, single
## file, the --allow and --min-cluster-3-on-2-dup exemptions). Both directions asserted.

printf '%s\n' "===== image_dup_check_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]
