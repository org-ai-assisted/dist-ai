#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-style's R-003 check: a NEWLY-ADDED shell file must
## indent with 2 spaces. New-file-only BY DESIGN -- existing 2-/3-space scripts
## are left as-is (R-152), a rename of a legacy file is not forced to reindent,
## and the detector is parser-free so it can only MISS (never falsely fail a
## clean 2-space file). The canary: on the pre-R-003 gate a new 3-space file was
## NOT flagged, so the first assertion below fails without the check in place.
##
## This test file itself is 2-space indented -- it dogfoods the rule it pins.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.bsh ; then
  printf '%s\n' "FATAL: helper-scripts has.bsh is not installed (/usr/libexec/helper-scripts/has.bsh)" >&2
  exit 1
fi
# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has safe-rm ; then
  printf '%s\n' "FATAL: safe-rm not on PATH" >&2
  exit 1
fi

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/),
## so editing the in-tree gate tests the in-tree copy, not the installed one.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/dist-ai-style"
if [ ! -x "${GATE}" ]; then
  GATE='/usr/bin/dist-ai-style'
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
  safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

fail=0

## A compliant script body indented with the literal PAD string. Everything but
## the indentation is identical, so R-003 is the only axis under test.
body_indented() {
  local pad
  pad="$1"
  printf '%s\n' \
    '#!/bin/bash' \
    '' \
    'set -o errexit' \
    'set -o nounset' \
    'set -o pipefail' \
    'set -o errtrace' \
    'shopt -s inherit_errexit' \
    'shopt -s shift_verbose' \
    'export LC_ALL=C' \
    '' \
    'main() {' \
    "${pad}local value" \
    "${pad}value='x'" \
    "${pad}printf '%s\\n' \"\${value}\"" \
    '}' \
    '' \
    'main'
}

## Build a repo whose BASE commit already contains a 3-space legacy.sh, so the
## modify/rename cases act on a pre-existing file. Echoes the base sha.
build_base() {
  local repo
  repo="$1"
  mkdir --parents -- "${repo}/usr/bin"
  body_indented '   ' >"${repo}/usr/bin/legacy.sh"
  chmod 0755 -- "${repo}/usr/bin/legacy.sh"
  git -c init.defaultBranch=master -c core.hooksPath=/dev/null \
    init --quiet -- "${repo}"
  git -C "${repo}" -c core.hooksPath=/dev/null add --all
  git -C "${repo}" -c core.hooksPath=/dev/null \
    -c user.name=test -c user.email=test@example.com \
    commit --quiet --message "base"
  git -C "${repo}" rev-parse HEAD
}

## Commit the working tree and run the gate over base...HEAD; sets gate_output.
commit_and_range() {
  local repo base_sha
  repo="$1"
  base_sha="$2"
  git -C "${repo}" -c core.hooksPath=/dev/null add --all
  git -C "${repo}" -c core.hooksPath=/dev/null \
    -c user.name=test -c user.email=test@example.com \
    commit --quiet --message "work"
  gate_output="$( cd -- "${repo}" && "${GATE}" --check --range "${base_sha}" 2>&1 )" \
    || true
}

flagged() {
  printf '%s\n' "${gate_output}" | grep --fixed-strings -- "R-003" >/dev/null
}

assert_flagged() {
  local label
  label="$1"
  if flagged ; then
    printf '%s\n' "PASS: ${label}"
  else
    printf '%s\n' "FAIL: ${label} -- R-003 not raised"
    printf '%s\n' "${gate_output}" | tail -3
    fail=1
  fi
}

assert_clean() {
  local label
  label="$1"
  if flagged ; then
    printf '%s\n' "FAIL: ${label} -- R-003 wrongly raised"
    printf '%s\n' "${gate_output}" | grep --fixed-strings -- "R-003" | head -2
    fail=1
  else
    printf '%s\n' "PASS: ${label}"
  fi
}

## 1. A newly-added 3-space file is flagged. THE CANARY: fails on the old gate.
repo="${test_dir}/new_three"
base_sha="$(build_base "${repo}")"
body_indented '   ' >"${repo}/usr/bin/new_three.sh"
chmod 0755 -- "${repo}/usr/bin/new_three.sh"
commit_and_range "${repo}" "${base_sha}"
assert_flagged "a newly-added 3-space file is flagged"

## 2. A newly-added 2-space file is clean.
repo="${test_dir}/new_two"
base_sha="$(build_base "${repo}")"
body_indented '  ' >"${repo}/usr/bin/new_two.sh"
chmod 0755 -- "${repo}/usr/bin/new_two.sh"
commit_and_range "${repo}" "${base_sha}"
assert_clean "a newly-added 2-space file is not flagged"

## 3. MODIFYING an existing 3-space file does not reindent it (new-file-only).
repo="${test_dir}/modify_legacy"
base_sha="$(build_base "${repo}")"
{ body_indented '   ' ; printf '%s\n' '   true "touched"' ; } >"${repo}/usr/bin/legacy.sh"
commit_and_range "${repo}" "${base_sha}"
assert_clean "modifying an existing 3-space file is left as-is"

## 4. RENAMING a legacy 3-space file (git mv) is an R, not an A -> not flagged.
repo="${test_dir}/rename_legacy"
base_sha="$(build_base "${repo}")"
git -C "${repo}" -c core.hooksPath=/dev/null mv usr/bin/legacy.sh usr/bin/moved.sh
commit_and_range "${repo}" "${base_sha}"
assert_clean "renaming a legacy 3-space file is not forced to reindent"

## 5. A new 3-space file carrying the per-rule override is waived.
repo="${test_dir}/waived"
base_sha="$(build_base "${repo}")"
{ body_indented '   ' ; printf '%s\n' '## style-ok: R-003' ; } >"${repo}/usr/bin/waived.sh"
chmod 0755 -- "${repo}/usr/bin/waived.sh"
commit_and_range "${repo}" "${base_sha}"
assert_clean "a new 3-space file with '## style-ok: R-003' is waived"

## 6. The staged (pre-commit) path flags a new 3-space file too, not only --range.
repo="${test_dir}/staged_three"
base_sha="$(build_base "${repo}")"
body_indented '   ' >"${repo}/usr/bin/staged_three.sh"
chmod 0755 -- "${repo}/usr/bin/staged_three.sh"
git -C "${repo}" -c core.hooksPath=/dev/null add --all
gate_output="$( cd -- "${repo}" && "${GATE}" --check --staged 2>&1 )" || true
assert_flagged "a newly-added 3-space file is flagged in --staged mode"

if [ "${fail}" -ne 0 ]; then
  printf '%s\n' "" "FAILED"
  exit 1
fi
printf '%s\n' "" "OK"
