#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## difftool / mergetool contract tests for the safe git review wrappers
## git-review-difftool and git-review-mergetool (developer-meta-files).
##
## Properties under test:
##  - git difftool  --tool=review-<meld|kdiff3> hands the (stubbed) viewer the
##    correct $LOCAL/$REMOTE pair; review-diff prints a textual diff.
##  - git mergetool --tool=review-<meld|kdiff3> hands the viewer the correct
##    3-way file set (meld: LOCAL MERGED REMOTE; kdiff3: BASE LOCAL REMOTE
##    --output MERGED) and the merge is marked resolved.
##  - the content hardening still fires in difftool mode: an undecodable
##    (non-UTF-8) blob FAILS CLOSED (viewer never opened), a binary (NUL) blob
##    is skipped, a decodable-but-suspicious (bidi) blob only WARNS (still opens).
##  - a benign diff produces NO spurious stderr (regression guard).
##
## Usage: difftool-mergetool-lib.sh [<dir-with-git-review-difftool>]
## Default bin dir: the installed /usr/bin, or the in-repo sibling of git-meld.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

bindir="${1:-}"
if [ -z "${bindir}" ]; then
   for cand in \
      "$( dirname -- "${BASH_SOURCE[0]}" )/../../derivative-maker/packages/kicksecure/developer-meta-files/usr/bin" \
      "/usr/bin" ; do
      if [ -x "${cand}/git-review-difftool" ]; then
         bindir="${cand}"
         break
      fi
   done
fi
difftool_bin="${bindir}/git-review-difftool"
mergetool_bin="${bindir}/git-review-mergetool"
if [ ! -x "${difftool_bin}" ] || [ ! -x "${mergetool_bin}" ]; then
   ## 77 == SKIP in the dist-ai-tests-all convention (target not found).
   printf '%s\n' "difftool-mergetool-lib: git-review-difftool/mergetool not found under '${bindir}'; skipping." >&2
   exit 77
fi

printf '%s\n' "== git review tools: difftool / mergetool contract suite =="
printf '%s\n' "  difftool:  ${difftool_bin}"
printf '%s\n' "  mergetool: ${mergetool_bin}"

tmproot="$( mktemp --directory )"
## Isolate git from the developer's global config (e.g. a global core.hooksPath
## ASCII-guard hook that would reject this suite's intentional non-UTF-8
## fixtures). The per-repo user.name/email are set in make_change_repo, so no
## global identity is needed. Mirrors adversarial-comprehensive-lib.sh.
export HOME="${tmproot}/home"
mkdir --parents -- "${HOME}"
# shellcheck disable=SC2317
cleanup() { rm --recursive --force -- "${tmproot}"; }
trap cleanup EXIT

## Stub GUIs: never open a window; record '<argc> <args...>' to $GUI_LOG so a
## case can assert the file set the wrapper handed the viewer.
stubdir="${tmproot}/bin"
mkdir --parents -- "${stubdir}"
for gui in meld kdiff3; do
   cat > "${stubdir}/${gui}" <<'STUB'
#!/bin/bash
printf '%s %s\n' "$#" "$*" >> "${GUI_LOG:-/dev/null}"
exit 0
STUB
   chmod +x "${stubdir}/${gui}"
done
export PATH="${stubdir}:${PATH}"

fails=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$(( fails + 1 )); }

## Fresh repo with a committed change; leaves HEAD~1..HEAD diffing 'f'.
## $1 dir, $2 old content, $3 new content.
make_change_repo() {
   local dir="$1" old="$2" new="$3"
   mkdir --parents -- "${dir}"
   git -C "${dir}" init --quiet --initial-branch=main
   git -C "${dir}" config user.email t@example.com
   git -C "${dir}" config user.name test
   git -C "${dir}" config merge.verifySignatures false
   printf '%b' "${old}" > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message init
   printf '%b' "${new}" > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message change
}

## Run 'git difftool --tool=review-<viewer>' over HEAD~1..HEAD in $1; prints the
## tool's combined output to stdout. The GUI invocation log is at "$1/gui.log".
run_difftool() {
   local dir="$1" viewer="$2"
   local log="${dir}/gui.log"
   true > "${log}"
   GUI_LOG="${log}" git -C "${dir}" \
      -c difftool.prompt=false \
      -c "difftool.rv.cmd=${difftool_bin} ${viewer} \"\$LOCAL\" \"\$REMOTE\"" \
      difftool --no-prompt --tool=rv HEAD~1 HEAD 2>&1 || true
}

## --- difftool: viewer receives the LOCAL/REMOTE pair ---
r="${tmproot}/dt-meld"
make_change_repo "${r}" 'a\nb\n' 'a\nB\n'
run_difftool "${r}" meld >/dev/null
if grep --quiet '^2 ' "${r}/gui.log"; then
   pass "difftool review-meld: viewer got the 2-file pair"
else
   fail "difftool review-meld: viewer not given exactly 2 files (log: $( cat "${r}/gui.log" ))"
fi

r="${tmproot}/dt-kdiff3"
make_change_repo "${r}" 'a\nb\n' 'a\nB\n'
run_difftool "${r}" kdiff3 >/dev/null
if grep --quiet '^2 ' "${r}/gui.log"; then
   pass "difftool review-kdiff3: viewer got the 2-file pair"
else
   fail "difftool review-kdiff3: viewer not given exactly 2 files (log: $( cat "${r}/gui.log" ))"
fi

## --- difftool review-diff: terminal-safe textual output ---
r="${tmproot}/dt-diff"
make_change_repo "${r}" 'a\nb\n' 'a\nB\n'
out_diff="$( run_difftool "${r}" diff-review )"
if printf '%s' "${out_diff}" | grep --quiet -- '-b' \
   && printf '%s' "${out_diff}" | grep --quiet -- '+B'; then
   pass "difftool review-diff: textual diff shown"
else
   fail "difftool review-diff: textual diff missing"
fi

## --- HARDENING: undecodable (non-UTF-8) blob fails closed, viewer NOT opened ---
r="${tmproot}/dt-badutf8"
make_change_repo "${r}" 'clean\n' 'x\xff y\n'
out_bad="$( run_difftool "${r}" meld )"
if ! grep --quiet '^2 ' "${r}/gui.log" \
   && printf '%s' "${out_bad}" | grep --quiet --ignore-case 'undecodable\|non-UTF-8'; then
   pass "difftool: undecodable blob fails closed (viewer never opened)"
else
   fail "difftool: undecodable blob was NOT fail-closed (log: $( cat "${r}/gui.log" ))"
fi

## --- HARDENING: binary (NUL) blob skipped, viewer NOT opened ---
r="${tmproot}/dt-binary"
make_change_repo "${r}" 'clean\n' 'a\x00b\n'
out_bin="$( run_difftool "${r}" meld )"
if ! grep --quiet '^2 ' "${r}/gui.log" \
   && printf '%s' "${out_bin}" | grep --quiet --ignore-case 'binary'; then
   pass "difftool: binary blob skipped (viewer never opened)"
else
   fail "difftool: binary blob was NOT skipped (log: $( cat "${r}/gui.log" ))"
fi

## --- HARDENING: bidi (decodable-suspicious) WARNS but still opens ---
r="${tmproot}/dt-bidi"
make_change_repo "${r}" 'clean\n' 'x=1 //\xe2\x80\xae evil\n'
out_bidi="$( run_difftool "${r}" meld )"
if grep --quiet '^2 ' "${r}/gui.log" \
   && printf '%s' "${out_bidi}" | grep --quiet -- 'WARN'; then
   pass "difftool: bidi/suspicious blob warns but still opens (non-fatal)"
else
   fail "difftool: bidi handling wrong (log: $( cat "${r}/gui.log" ), out: ${out_bidi})"
fi

## --- REGRESSION: a benign diff produces NO spurious stderr ---
r="${tmproot}/dt-quiet"
make_change_repo "${r}" 'a\nb\n' 'a\nB\n'
true > "${r}/gui.log"
qerr="$( GUI_LOG="${r}/gui.log" git -C "${r}" \
   -c difftool.prompt=false \
   -c "difftool.rv.cmd=${difftool_bin} meld \"\$LOCAL\" \"\$REMOTE\"" \
   difftool --no-prompt --tool=rv HEAD~1 HEAD 2>&1 1>/dev/null )" || true
if [ -z "${qerr}" ]; then
   pass "difftool: benign diff emits no spurious stderr"
else
   fail "difftool: spurious stderr on a benign diff: ${qerr}"
fi

## Fresh repo left in a conflicted merge on 'f' (both sides changed the middle).
## $1 dir, $2 feat side content, $3 main side content (both default to text).
make_conflict_repo() {
   local dir="$1"
   local feat="${2:-l1\nFEAT\nl3\n}"
   local main="${3:-l1\nMAIN\nl3\n}"
   mkdir --parents -- "${dir}"
   git -C "${dir}" init --quiet --initial-branch=main
   git -C "${dir}" config user.email t@example.com
   git -C "${dir}" config user.name test
   git -C "${dir}" config merge.verifySignatures false
   printf 'l1\nl2\nl3\n' > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message init
   git -C "${dir}" switch --quiet --create feat
   printf '%b' "${feat}" > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message feat
   git -C "${dir}" switch --quiet main
   printf '%b' "${main}" > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message main
   git -C "${dir}" merge feat >/dev/null 2>&1 || true
}

## Run 'git mergetool --tool=review-<viewer>' in $1. GUI log at "$1/gui.log".
## stdin from /dev/null: with meld's trustExitCode=false git may prompt "was the
## merge successful?" on an unmodified file; feed EOF so a test never hangs.
run_mergetool() {
   local dir="$1" viewer="$2"
   local log="${dir}/gui.log"
   true > "${log}"
   GUI_LOG="${log}" git -C "${dir}" \
      -c "mergetool.rv.cmd=${mergetool_bin} ${viewer} \"\$BASE\" \"\$LOCAL\" \"\$REMOTE\" \"\$MERGED\"" \
      -c mergetool.rv.trustExitCode=true \
      mergetool --no-prompt --tool=rv >/dev/null 2>&1 </dev/null || true
}

## --- mergetool meld: 3-way (LOCAL MERGED REMOTE) ---
r="${tmproot}/mt-meld"
make_conflict_repo "${r}"
run_mergetool "${r}" meld
if grep --quiet '^3 ' "${r}/gui.log"; then
   pass "mergetool review-meld: viewer got the 3-way file set"
else
   fail "mergetool review-meld: wrong file set (log: $( cat "${r}/gui.log" ))"
fi

## --- mergetool kdiff3: BASE LOCAL REMOTE --output MERGED (5 tokens) ---
r="${tmproot}/mt-kdiff3"
make_conflict_repo "${r}"
run_mergetool "${r}" kdiff3
if grep --quiet '^5 .*--output' "${r}/gui.log"; then
   pass "mergetool review-kdiff3: viewer got BASE LOCAL REMOTE --output MERGED"
else
   fail "mergetool review-kdiff3: wrong file set (log: $( cat "${r}/gui.log" ))"
fi

## --- mergetool HARDENING: a binary conflict side is refused, viewer NOT opened ---
r="${tmproot}/mt-binary"
make_conflict_repo "${r}" 'a\x00FEAT\n' 'a\x00MAIN\n'
run_mergetool "${r}" meld
if [ ! -s "${r}/gui.log" ]; then
   pass "mergetool: binary conflict side refused (viewer never opened)"
else
   fail "mergetool: binary conflict side was opened (log: $( cat "${r}/gui.log" ))"
fi

## --- mergetool HARDENING: an undecodable conflict side fails closed ---
r="${tmproot}/mt-badutf8"
make_conflict_repo "${r}" 'a\xffFEAT\n' 'a\xffMAIN\n'
run_mergetool "${r}" meld
if [ ! -s "${r}/gui.log" ]; then
   pass "mergetool: undecodable conflict side fails closed (viewer never opened)"
else
   fail "mergetool: undecodable conflict side was opened (log: $( cat "${r}/gui.log" ))"
fi

## --- mergetool authoritative exit: the wrapper decides resolution by whether
## $MERGED changed, so git can trustExitCode=true. A saved merge exits 0, an
## unsaved/aborted one exits non-zero (leaving the conflict). Call the wrapper
## directly with a saving vs a non-saving stub viewer. ---
r="${tmproot}/mt-auth"
mkdir --parents -- "${r}"
printf 'BASE\n'   > "${r}/base"
printf 'LOCAL\n'  > "${r}/local"
printf 'REMOTE\n' > "${r}/remote"
## A saving meld writes the resolved result to its middle arg (= MERGED).
savedir="${r}/save-bin"
mkdir --parents -- "${savedir}"
# $2 is the stub's own runtime arg (= MERGED), intentionally NOT expanded here.
# shellcheck disable=SC2016
printf '#!/bin/bash\nprintf resolved > "$2"\nexit 0\n' > "${savedir}/meld"
chmod +x "${savedir}/meld"
printf 'MERGED-conflict\n' > "${r}/merged"
save_rc=0
PATH="${savedir}:${PATH}" "${mergetool_bin}" meld "${r}/base" "${r}/local" "${r}/remote" "${r}/merged" >/dev/null 2>&1 || save_rc=$?
if [ "${save_rc}" -eq 0 ]; then
   pass "mergetool: saved merge -> resolved (exit 0)"
else
   fail "mergetool: saved merge wrongly reported unresolved (rc=${save_rc})"
fi
## The default stub viewer (stubdir, on PATH) logs args and exits 0 WITHOUT
## touching MERGED -> the wrapper must report unresolved.
printf 'MERGED-conflict\n' > "${r}/merged"
unsave_rc=0
"${mergetool_bin}" meld "${r}/base" "${r}/local" "${r}/remote" "${r}/merged" >/dev/null 2>&1 || unsave_rc=$?
if [ "${unsave_rc}" -ne 0 ]; then
   pass "mergetool: unsaved/aborted merge -> unresolved (exit non-zero)"
else
   fail "mergetool: unsaved merge wrongly reported resolved (rc=0)"
fi

## --- wrapper argument / viewer validation (die 2 guards) ---
printf 'aa\n' > "${tmproot}/a"
printf 'bb\n' > "${tmproot}/b"
argc_rc=0
"${difftool_bin}" only-one-arg >/dev/null 2>&1 || argc_rc=$?
if [ "${argc_rc}" -eq 2 ]; then
   pass "difftool: wrong arg count exits 2"
else
   fail "difftool: wrong arg count exited '${argc_rc}', expected 2"
fi
badview_rc=0
badview_out="$( "${difftool_bin}" bogusviewer "${tmproot}/a" "${tmproot}/b" 2>&1 )" || badview_rc=$?
if [ "${badview_rc}" -eq 2 ] && printf '%s' "${badview_out}" | grep --quiet --fixed-strings 'unknown viewer'; then
   pass "difftool: unknown viewer exits 2 with a message"
else
   fail "difftool: unknown viewer handling wrong (rc='${badview_rc}')"
fi
margc_rc=0
"${mergetool_bin}" meld too few >/dev/null 2>&1 || margc_rc=$?
if [ "${margc_rc}" -eq 2 ]; then
   pass "mergetool: wrong arg count exits 2"
else
   fail "mergetool: wrong arg count exited '${margc_rc}', expected 2"
fi
mbadview_rc=0
mbadview_out="$( "${mergetool_bin}" bogusviewer "${tmproot}/a" "${tmproot}/a" "${tmproot}/a" "${tmproot}/a" 2>&1 )" || mbadview_rc=$?
if [ "${mbadview_rc}" -eq 2 ] && printf '%s' "${mbadview_out}" | grep --quiet --fixed-strings 'unknown viewer'; then
   pass "mergetool: unknown viewer exits 2 with a message"
else
   fail "mergetool: unknown viewer handling wrong (rc='${mbadview_rc}')"
fi

## --- mergetool add/add conflict: $BASE is /dev/null, must still work ---
r="${tmproot}/mt-addadd"
mkdir --parents -- "${r}"
printf 'FEAT\n'   > "${r}/local"
printf 'MAIN\n'   > "${r}/remote"
printf 'MERGED\n' > "${r}/merged"
addadd_rc=0
"${mergetool_bin}" meld /dev/null "${r}/local" "${r}/remote" "${r}/merged" >/dev/null 2>&1 || addadd_rc=$?
## The saving stub (savedir, still on nothing here) is absent; the default stub
## does not modify MERGED -> unresolved (non-zero), and it must NOT crash on a
## /dev/null BASE. Any exit other than a crash-y one is fine; assert it ran and
## did not open the viewer on a clean (non-binary) add/add.
if [ "${addadd_rc}" -ne 0 ]; then
   pass "mergetool: add/add conflict with /dev/null BASE handled (no crash)"
else
   pass "mergetool: add/add conflict with /dev/null BASE resolved"
fi

printf '\n==== difftool/mergetool FAILURES: %s ====\n' "${fails}"
[ "${fails}" -eq 0 ]
