#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-prepare-release': how it locates
## the derivative-maker source tree when run as the INSTALLED copy.
##
## THE BUG IT GUARDS: run from /usr/bin -- which is what a bare
## 'dm-prepare-release' on PATH resolves to, and what dm-build-official-one's
## Phase 4 invokes -- it hardcoded "$HOME/derivative-maker" (the source carried
## an "XXX: hardcoded path" note). A build whose checkout lives anywhere else
## therefore ran to completion and then died in the RELEASE phase on a bare
##   dm-prepare-release: line 35: .../help-steps/pre: No such file or directory
## from bash's 'source' -- after the entire build. Observed with the tree at
## /workspace in the derivative-maker container.
##
## The fix is an ordered resolution, so this asserts the ORDER, not one path.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

subject=""
for candidate in "${DM_PREPARE_RELEASE:-}" \
   "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-prepare-release" \
   "${HOME}/derivative-maker/packages/kicksecure/developer-meta-files/usr/bin/dm-prepare-release" \
   "/usr/bin/dm-prepare-release"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "SKIP: dm-prepare-release not found (set DM_PREPARE_RELEASE)." >&2
   exit 77
fi

## The resolution block only: from whichever MYDIR-vs-/usr/bin branch opens it to
## the first 'source' that follows. Deliberately matches both the braced and
## unbraced spellings -- a slice that only matched the fixed form would fail to
## extract on the buggy one, and this test would then "fail" without any of its
## assertions having run.
block="$(sed -n '/MYDIR.*=.*"\/usr\/bin"/,/^source /p' -- "${subject}")"
if [ -z "${block}" ]; then
   printf '%s\n' "FAILED: could not extract the tree-resolution block." >&2
   exit 1
fi

## --- the hardcoded path must no longer be the only answer ------------------
case "${block}" in
   *'source_code_folder_dist'*)
      pass "resolution consults source_code_folder_dist, the build's own variable"
      ;;
   *)
      fail "resolution ignores source_code_folder_dist, so a tree outside \$HOME cannot be found"
      ;;
esac

## Order matters: the build's own variable must win over the convention.
## '|| true' on both: a grep that matches nothing exits 1, and under errexit the
## command substitution would abort this script mid-run -- reporting one failure
## and silently skipping every assertion after it, which is exactly what a canary
## run against the buggy file does.
authoritative_at="$(printf '%s\n' "${block}" | grep --line-number --max-count=1 -- 'source_code_folder_dist' | cut -d: -f1 || true)"
fallback_at="$(printf '%s\n' "${block}" | grep --line-number --max-count=1 --extended-regexp -- '\$\{?HOME\}?/derivative-maker' | cut -d: -f1 || true)"
if [ -n "${authoritative_at}" ] && [ -n "${fallback_at}" ]; then
   if [ "${authoritative_at}" -lt "${fallback_at}" ]; then
      pass "source_code_folder_dist is consulted BEFORE the \$HOME convention"
   else
      fail "the \$HOME convention is consulted first, so it wins even when the build named the tree"
   fi
else
   fail "could not locate both branches (authoritative='${authoritative_at}' fallback='${fallback_at}')"
fi

## --- CANARY: the conventional fallback must still exist --------------------
## Without it, the assertions above are satisfied by deleting the fallback, which
## would break every operator who does keep the checkout at ~/derivative-maker.
## Braced or unbraced: the point is that the convention survives, not how it is
## spelled. Matching only one form would report it "removed" from a file that
## still has it, which is a lie in the canary direction.
if printf '%s\n' "${block}" | grep --quiet --extended-regexp -- '\$\{?HOME\}?/derivative-maker'; then
   pass "canary: the ~/derivative-maker convention is still honoured as a fallback"
else
   fail "canary broken: the conventional location was removed, not deprioritised"
fi

## --- a missing tree must be NAMED, not surfaced as a bash sourcing error ---
case "${block}" in
   *'no derivative-maker source tree at'*)
      pass "an unresolvable tree fails with a named error"
      ;;
   *)
      fail "an unresolvable tree still reaches 'source' and dies on bash's 'No such file or directory', after the whole build"
      ;;
esac
case "${block}" in
   *'source_code_folder_dist'*"Set '"*)
      pass "the error says what to set"
      ;;
   *)
      fail "the error does not say how to fix it"
      ;;
esac

## --- behavioural: an unresolvable tree exits non-zero, and says so ----------
## Run the real script with HOME pointed at an empty dir, no source_code_folder_dist,
## and a cwd that is not a checkout: every branch must miss.
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

rc=0
out="$(cd -- "${workdir}" && env --unset=source_code_folder_dist HOME="${workdir}" \
   bash -- "${subject}" --target source 2>&1)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "unresolvable tree: exits non-zero (${rc})"
else
   fail "unresolvable tree: exited 0"
fi
case "${out}" in
   *"No such file or directory"*)
      fail "unresolvable tree: still surfaces bash's raw sourcing error -- ${out}"
      ;;
   *"no derivative-maker source tree at"*)
      pass "unresolvable tree: reports the named error, not a raw sourcing failure"
      ;;
   *)
      fail "unresolvable tree: unexpected output -- ${out}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: prepare-release tree location."
