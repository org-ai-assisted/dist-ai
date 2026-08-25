#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Git-mode gate tests for dist-ai-style: the repo-level orchestration that
## judges a staged index or a commit range and drives the batch checks
## (pre-commit-hooks, the genmkfile-owned changelog convention, the
## commit-message non-ASCII floor). Each case builds a throwaway git repo and
## asserts the exit code AND the finding, so a silent green (a check that runs
## but inspects nothing) is caught. Drives the REAL checkout binary.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
STYLE="${tool_test_dir}/../../bin/dist-ai-style"
[ -x "${STYLE}" ] || STYLE='/usr/bin/dist-ai-style'
for prereq in shfmt python3 safe-rm git check-yaml ; do
   type -P "${prereq}" >/dev/null 2>&1 || {
      printf '%s\n' "FATAL: '${prereq}' not on PATH; this test cannot run." >&2
      exit 1
   }
done

work="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

passc=0
fail=0
note_pass() { printf '%s\n' "PASS: ${1}" ; passc=$(( passc + 1 )) ; }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2 ; fail=$(( fail + 1 )) ; }

## A fresh repo with one empty initial commit; prints its path.
new_repo() {
   local repo
   repo="$(mktemp --directory --tmpdir="${work}")"
   git -C "${repo}" init -q
   git -C "${repo}" config user.email a@b.c
   git -C "${repo}" config user.name t
   git -C "${repo}" commit -q --allow-empty -m init
   printf '%s\n' "${repo}"
}

## A strict-mode-complete, executable shell file -- clean for every per-file rule
## and the shebang-is-executable hook.
mk_clean() {
   printf '%s\n' '#!/bin/bash' 'set -o errexit' 'set -o nounset' \
      'set -o pipefail' 'set -o errtrace' 'shopt -s inherit_errexit' \
      'shopt -s shift_verbose' 'export LC_ALL=C' 'true' > "${1}"
   chmod +x "${1}"
}

## assert <label> <expected-rc> <needle-or-empty> -- run STYLE in ${repo} with
## the remaining args, checking the exit code and (if given) an output needle.
repo=""
assert() {
   local label expect needle rc out
   label="${1}"; expect="${2}"; needle="${3}"; shift 3
   rc=0
   out="$(cd -- "${repo}" && "${STYLE}" "$@" 2>&1)" || rc=$?
   if [ "${rc}" -ne "${expect}" ]; then
      note_fail "${label}: rc=${rc}, expected ${expect}"
      printf '%s\n' "${out}" | sed 's/^/    /' >&2
      return 0
   fi
   if [ -n "${needle}" ] && ! grep --quiet --fixed-strings -- "${needle}" \
      <<< "${out}"; then
      note_fail "${label}: missing '${needle}' in output"
      printf '%s\n' "${out}" | sed 's/^/    /' >&2
      return 0
   fi
   note_pass "${label}"
}

## --- 1. a clean staged shell file passes ------------------------------------
repo="$(new_repo)"
mk_clean "${repo}/clean.sh"
git -C "${repo}" add clean.sh
assert "clean staged file passes" 0 "" --check --staged

## --- 2. a hand-edited debian/changelog without an override FAILs -------------
repo="$(new_repo)"
mkdir -p "${repo}/debian"
printf 'pkg (1.0) unstable; urgency=low\n' > "${repo}/debian/changelog"
git -C "${repo}" add debian/changelog
printf 'add a feature\n' > "${work}/msg_plain"
assert "changelog hand-edit FAILs" 1 "changelog" \
   --check --staged --message-file "${work}/msg_plain"

## --- 3. the mandatory override trailer permits it ---------------------------
printf 'add a feature\n\nChangelog-manual-ok: needed for X\n' \
   > "${work}/msg_ok"
assert "changelog override trailer passes" 0 "" \
   --check --staged --message-file "${work}/msg_ok"

## --- 4. a genmkfile auto-bump (exact subject, family-only diff) passes -------
printf 'bumped changelog version\n' > "${work}/msg_bump"
assert "changelog auto-bump passes" 0 "" \
   --check --staged --message-file "${work}/msg_bump"

## --- 5. a non-ASCII commit message FAILs R-001 ------------------------------
repo="$(new_repo)"
mk_clean "${repo}/ok.sh"
git -C "${repo}" add ok.sh
printf 'add \xc3\xa9 feature\n' > "${work}/msg_utf8"
assert "non-ASCII commit message FAILs" 1 "R-001" \
   --check --staged --message-file "${work}/msg_utf8"

## --- 6. a staged malformed YAML FAILs check-yaml ----------------------------
repo="$(new_repo)"
printf 'foo: [unclosed\n' > "${repo}/bad.yaml"
git -C "${repo}" add bad.yaml
assert "malformed YAML FAILs check-yaml" 1 "check-yaml" --check --staged

## --- 7. --range over a clean commit passes ----------------------------------
repo="$(new_repo)"
mk_clean "${repo}/r.sh"
git -C "${repo}" add r.sh
git -C "${repo}" commit -q -m 'add r.sh'
assert "range over a clean commit passes" 0 "" --check --range HEAD~1

## --- 8. --range catches a hand-edited changelog commit ----------------------
repo="$(new_repo)"
mkdir -p "${repo}/debian"
printf 'pkg (1.0) unstable; urgency=low\n' > "${repo}/debian/changelog"
git -C "${repo}" add debian/changelog
git -C "${repo}" commit -q -m 'hand-edit changelog'
assert "range catches changelog hand-edit" 1 "changelog" \
   --check --range HEAD~1

## --- 9. --paths restricts the staged set ------------------------------------
## A bad file and a clean file are both staged; --paths naming only the clean
## one must pass, naming the bad one must fail. Guards the narrow-to-nothing
## bypass (a filter that quietly checks no file and exits 0).
repo="$(new_repo)"
mk_clean "${repo}/good.sh"
printf '%s\n' '#!/bin/bash' 'rm -rf /x' > "${repo}/bad.sh"
chmod +x "${repo}/bad.sh"
git -C "${repo}" add good.sh bad.sh
assert "paths filter to clean file passes" 0 "" \
   --check --staged --all --paths -- good.sh
assert "paths filter to bad file FAILs" 1 "" \
   --check --staged --all --paths -- bad.sh

## --- 10. check-added-large-files fires on a NEW big file, not a tracked one --
## A file already in the base ref was reviewed when added; only a NEW big file
## is the hook's business. This is the added-vs-tracked carve-out.
repo="$(new_repo)"
{ head -c 600000 /dev/zero | tr '\0' 'a'; printf '%s\n' ''; } > "${repo}/big.dat"
git -C "${repo}" add big.dat
assert "new large file FAILs check-added-large-files" 1 \
   "check-added-large-files" --check --staged
git -C "${repo}" commit -q -m 'add big.dat'
printf 'more\n' >> "${repo}/big.dat"
git -C "${repo}" add big.dat
assert "appending to a tracked large file passes" 0 "" --check --staged --all

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-gate: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "pre-push-gate: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
exit 0
