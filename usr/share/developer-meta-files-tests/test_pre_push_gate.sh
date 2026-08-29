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
   ## Neutralize the OPERATOR's global hooks (core.hooksPath) on the fixture repo:
   ## a fixture commit (e.g. the deliberately oversized big.dat) must not be vetoed
   ## by the developer's own pre-commit style gate, which is not what this tests.
   git -C "${repo}" config core.hooksPath /dev/null
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

## --- 11. bare --staged NOTEs when the working tree diverges from the index --
## The gate judges the staged INDEX blob (the exact committed bytes); a staged
## path edited (not re-staged) afterward is still checked on its blob, so an
## advisory NOTE flags that the working tree has since diverged. The edit here is
## a harmless comment, so the file still passes (rc 0) and only the advisory fires.
repo="$(new_repo)"
mk_clean "${repo}/skew.sh"
git -C "${repo}" add skew.sh
printf '%s\n' '## edited after staging' >> "${repo}/skew.sh"
assert "worktree skew emits an advisory NOTE" 0 "the gate judged the staged blob" \
   --check --staged

## --- 12. --range keys added-large-files on the MERGE BASE, not base tip ------
## A big file added on the feature branch must be caught even when a same-named
## (small) file exists at the base branch's TIP -- it is still new at the fork.
repo="$(new_repo)"
git -C "${repo}" checkout -q -b base
printf 'small\n' > "${repo}/data.bin"
git -C "${repo}" add data.bin
git -C "${repo}" commit -q -m 'base adds small data.bin'
git -C "${repo}" checkout -q -b feature 'HEAD~1'
{ head -c 600000 /dev/zero | tr '\0' 'a'; printf '%s\n' ''; } > "${repo}/data.bin"
git -C "${repo}" add data.bin
git -C "${repo}" commit -q -m 'feature adds big data.bin'
assert "range added-large-files uses the merge base" 1 \
   "check-added-large-files" --check --range base

## --- 13. a non-ASCII commit-range message FAILs R-001 without crashing -------
## The message carries an invalid-UTF-8 byte; R-001 must read the raw bytes and
## FAIL, never crash the tool on a strict decode.
repo="$(new_repo)"
mk_clean "${repo}/u.sh"
git -C "${repo}" add u.sh
git -C "${repo}" commit -q -m "$(printf 'subject with \xff byte')"
assert "non-ASCII range message FAILs R-001" 1 "R-001" --check --range HEAD~1

## --- an untracked fifo must NOT hang the gate (ai-review: _is_shell_file) ----
## Reading a shebang from an untracked fifo (or a symlink to /dev/zero) once
## blocked forever; the untracked scan must complete within a bounded time.
repo="$(new_repo)"
mkfifo "${repo}/pipe-tool"
hang_rc=0
timeout --kill-after=5 20 bash -c 'cd "$1" && "$2" --check --range HEAD' _ \
   "${repo}" "${STYLE}" > /dev/null 2>&1 || hang_rc=$?
if [ "${hang_rc}" -eq 124 ]; then
   note_fail "the gate HUNG on an untracked fifo (timed out)"
else
   note_pass "the gate does not hang on an untracked fifo"
fi

## --- the pre-commit batch judges the staged BLOB, not the working tree --------
## A private key staged then overwritten clean in the working copy must still be
## caught by detect-private-key -- the batch that ran against the working tree
## would see only the decoy and pass, hiding the staged secret.
## The PEM marker is ASSEMBLED at run time -- 'PRIV'+'ATE KEY' -- so no literal
## private-key header lives in THIS tracked file for detect-private-key to flag.
repo="$(new_repo)"
dashes='-----'
pem_kind="RSA PRIV""ATE KEY"
printf '%s\n' "${dashes}BEGIN ${pem_kind}${dashes}" \
   'MIIBOgIBAAJBAKj34GkxFhDabcdEFGHijklMNOP' \
   "${dashes}END ${pem_kind}${dashes}" > "${repo}/id_rsa"
git -C "${repo}" add id_rsa
printf '%s\n' 'a harmless decoy' > "${repo}/id_rsa"
assert "staged private key hidden by a clean working copy is caught" 1 \
   "detect-private-key" --check --staged

## A large file staged then overwritten with a small decoy must still be flagged:
## the size check reads the blob, not the working tree.
repo="$(new_repo)"
head -c 700000 /dev/zero | tr '\0' 'x' > "${repo}/big.dat"
git -C "${repo}" add big.dat
printf '%s\n' 'tiny' > "${repo}/big.dat"
assert "large blob hidden by a small working copy is flagged" 1 \
   "check-added-large-files" --check --staged

## A staged BROKEN symlink must be flagged -- the symlink checks run over the
## mirror's recreated symlinks, not skipped because the mirror has no symlink.
repo="$(new_repo)"
ln -s nonexistent-relative-target "${repo}/badlink"
git -C "${repo}" add badlink
assert "a staged broken symlink is flagged in blob mode" 1 \
   "check-symlinks" --check --staged

## ...but a VALID relative symlink to an already-tracked file must NOT false-fail:
## the mirror materializes the link's TARGET too, so it is not seen as broken
## (running against the working tree would reopen the staged-vs-worktree split).
repo="$(new_repo)"
printf 'data\n' > "${repo}/tracked.txt"
git -C "${repo}" add tracked.txt
git -C "${repo}" commit --quiet --no-verify --message tracked
ln -s tracked.txt "${repo}/goodlink"
git -C "${repo}" add goodlink
assert "a valid staged symlink to a tracked file is not false-flagged" 0 \
   "" --check --staged

## A relative symlink ESCAPING the tree (above root) cannot resolve in the tree,
## so it is broken -- a filesystem check against a /tmp mirror false-PASSED it.
repo="$(new_repo)"
ln -s ../../../../etc/nope "${repo}/esclink"
git -C "${repo}" add esclink
assert "a staged tree-escaping symlink is flagged" 1 \
   "check-symlinks" --check --staged

## A MULTI-HOP chain of valid links (link -> intermediate -> file) must resolve
## -- a one-level-deep materialization false-FAILED it.
repo="$(new_repo)"
printf 'data\n' > "${repo}/endfile"
ln -s endfile "${repo}/mid"
git -C "${repo}" add endfile mid
git -C "${repo}" commit --quiet --no-verify --message chain-base
ln -s mid "${repo}/head"
git -C "${repo}" add head
assert "a valid multi-hop staged symlink chain is not false-flagged" 0 \
   "" --check --staged

## A staged file carrying a merge-conflict marker must be flagged even outside a
## real merge (check-merge-conflict is a no-op without --assume-in-merge).
repo="$(new_repo)"
printf '%s\n' 'a' '<<<<<<< HEAD' 'b' '=======' 'c' '>>>>>>> other' > "${repo}/conflicted.txt"
git -C "${repo}" add conflicted.txt
assert "a staged merge-conflict marker is flagged" 1 \
   "check-merge-conflict" --check --staged

## --- a working-tree scan must read the WORKING-TREE .gitattributes ------------
## In --staged --all (working tree) the binary classification must consult the
## working tree's .gitattributes, NOT the index (--cached). Commit 'id_rsa binary'
## + a placeholder; then DROP the mark in an UNSTAGED .gitattributes edit while
## staging a real PEM. Reading the stale INDEX attr would classify id_rsa binary
## and skip detect-private-key -- a private-key bypass. Marker assembled at run
## time ('PRIV'+'ATE KEY') so no literal key header lives in this tracked file.
repo="$(new_repo)"
dashes='-----'
pem_kind="RSA PRIV""ATE KEY"
printf '%s\n' 'id_rsa binary' > "${repo}/.gitattributes"
printf '%s\n' 'binary placeholder' > "${repo}/id_rsa"
git -C "${repo}" add .gitattributes id_rsa
git -C "${repo}" commit --quiet --no-verify --message attr-base
printf '%s\n' '# no attributes' > "${repo}/.gitattributes"
printf '%s\n' "${dashes}BEGIN ${pem_kind}${dashes}" \
   'MIIBOgIBAAJBAKj34GkxFhDabcdEFGHijklMNOP' \
   "${dashes}END ${pem_kind}${dashes}" > "${repo}/id_rsa"
git -C "${repo}" add id_rsa
assert "staged private key caught despite a stale index binary attr" 1 \
   "detect-private-key" --check --staged --all

## A symlink to the tree ROOT ('.'), or to a parent that stays in-tree ('..' from
## a subdir), resolves -- '.' must count as a present tree path or a valid link
## false-fails.
repo="$(new_repo)"
printf 'data\n' > "${repo}/f.txt"
mkdir -p "${repo}/sub"
ln -s . "${repo}/rootlink"
ln -s .. "${repo}/sub/uplink"
git -C "${repo}" add f.txt rootlink sub/uplink
assert "a staged symlink to the tree root is not false-flagged" 0 \
   "" --check --staged

## A link whose path traverses a DIR-SYMLINK (through -> dirlink/file.txt, dirlink
## -> a real dir) must not false-fail: resolving dir-symlink components is
## best-effort (checkout-time check-symlinks does it), so it is left unflagged.
repo="$(new_repo)"
mkdir -p "${repo}/realdir"
printf 'data\n' > "${repo}/realdir/file.txt"
ln -s realdir "${repo}/dirlink"
ln -s dirlink/file.txt "${repo}/through"
git -C "${repo}" add realdir/file.txt dirlink through
assert "a staged symlink through a dir-symlink is not false-flagged" 0 \
   "" --check --staged

## The pre-commit FIXER must not follow a symlink swapped in after classification
## (a TOCTOU that let a fixer rewrite an arbitrary victim outside the repo). Drive
## precommit._run_fixer directly with a symlink where a regular file was scanned;
## the O_NOFOLLOW copy must refuse it and leave the victim untouched.
fixer_lib="${STYLE%/usr/bin/dist-ai-style}/usr/lib/python3/dist-packages"
[ -d "${fixer_lib}/dist_ai" ] || fixer_lib='/usr/lib/python3/dist-packages'
victim="$(new_repo)/victim.txt"
printf 'VICTIM ORIGINAL no newline' > "${victim}"
ln -s "${victim}" "$(dirname -- "${victim}")/target.sh"
toctou="$(PYTHONPATH="${fixer_lib}" python3 -c '
import sys
from dist_ai import precommit
base, victim = sys.argv[1], sys.argv[2]
list(precommit._run_fixer("end-of-file-fixer", ["target.sh"], base))
print(open(victim).read())
' "$(dirname -- "${victim}")" "${victim}")"
if [ "${toctou}" = 'VICTIM ORIGINAL no newline' ]; then
   note_pass "the pre-commit fixer refuses a symlink swapped in after the scan"
else
   note_fail "the pre-commit fixer followed a swapped-in symlink (victim='${toctou}')"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-gate: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "pre-push-gate: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
exit 0
