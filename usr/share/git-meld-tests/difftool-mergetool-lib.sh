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
   : > "${log}"
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
   && printf '%s' "${out_bidi}" | grep --quiet 'WARNING'; then
   pass "difftool: bidi/suspicious blob warns but still opens (non-fatal)"
else
   fail "difftool: bidi handling wrong (log: $( cat "${r}/gui.log" ), out: ${out_bidi})"
fi

## --- REGRESSION: a benign diff produces NO spurious stderr ---
r="${tmproot}/dt-quiet"
make_change_repo "${r}" 'a\nb\n' 'a\nB\n'
: > "${r}/gui.log"
qerr="$( GUI_LOG="${r}/gui.log" git -C "${r}" \
   -c difftool.prompt=false \
   -c "difftool.rv.cmd=${difftool_bin} meld \"\$LOCAL\" \"\$REMOTE\"" \
   difftool --no-prompt --tool=rv HEAD~1 HEAD 2>&1 1>/dev/null )" || true
if [ -z "${qerr}" ]; then
   pass "difftool: benign diff emits no spurious stderr"
else
   fail "difftool: spurious stderr on a benign diff: ${qerr}"
fi

## Fresh repo left in a conflicted merge on 'f' (both sides changed line 2).
make_conflict_repo() {
   local dir="$1"
   mkdir --parents -- "${dir}"
   git -C "${dir}" init --quiet --initial-branch=main
   git -C "${dir}" config user.email t@example.com
   git -C "${dir}" config user.name test
   git -C "${dir}" config merge.verifySignatures false
   printf 'l1\nl2\nl3\n' > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message init
   git -C "${dir}" switch --quiet --create feat
   printf 'l1\nFEAT\nl3\n' > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message feat
   git -C "${dir}" switch --quiet main
   printf 'l1\nMAIN\nl3\n' > "${dir}/f"
   git -C "${dir}" add f
   git -C "${dir}" commit --quiet --message main
   git -C "${dir}" merge feat >/dev/null 2>&1 || true
}

## Run 'git mergetool --tool=review-<viewer>' in $1. GUI log at "$1/gui.log".
run_mergetool() {
   local dir="$1" viewer="$2"
   local log="${dir}/gui.log"
   : > "${log}"
   GUI_LOG="${log}" git -C "${dir}" \
      -c "mergetool.rv.cmd=${mergetool_bin} ${viewer} \"\$BASE\" \"\$LOCAL\" \"\$REMOTE\" \"\$MERGED\"" \
      -c mergetool.rv.trustExitCode=true \
      mergetool --no-prompt --tool=rv >/dev/null 2>&1 || true
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

printf '\n==== difftool/mergetool FAILURES: %s ====\n' "${fails}"
[ "${fails}" -eq 0 ]
