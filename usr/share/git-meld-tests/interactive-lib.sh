#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Interactive-consent tests for the terminal-safe reviewer git-diff-review.
## Contract, TWO terminal prompts in order:
##   1. Before the per-file diffs, "proceed to the per-file diffs? [y/N]" lets
##      the operator ack the changed-file list first. It fires ONLY in a genuine
##      interactive session (flag set AND both stdin/stdout terminals). Declining
##      ABORTS non-zero WITHOUT scanning -- never a scanned-clean-looking exit 0
##      (the per-file dispatch is the only place content is scanned).
##   2. During a diff, on FATAL (undecodable / non-UTF-8) content it prompts
##      "continue past neutralized content? [y/N]" and must CONTINUE on 'y'
##      (exit 0) and FAIL CLOSED on 'n' (non-zero).
## Only git-diff-review sets git_review_outputs_to_terminal (the proceed gate)
## and git_review_display_fatal_content (the fatal prompt); the non-interactive
## path is covered elsewhere. Needs a pseudo-tty, so it drives the wrapper
## through git-meld-tests-pty.py, which takes a comma-separated answer per prompt
## ('y,n' = proceed, then decline the fatal content).
##
## Usage: interactive-lib.sh [<dir-with-git-diff-review>]

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.bsh

mydir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
bindir="${1:-/usr/bin}"
gdr="${bindir}/git-diff-review"
pyhelper="${mydir}/git-meld-tests-pty.py"

if [ ! -x "${gdr}" ] || ! has python3 || [ ! -f "${pyhelper}" ]; then
   printf '%s\n' "FATAL: interactive-lib: git-diff-review / python3 / pty helper missing." >&2
   exit 1
fi

printf '%s\n' "== git-diff-review interactive-consent suite =="
printf '%s\n' "  git-diff-review: ${gdr}"

work="$( mktemp --directory )"
export HOME="${work}/home"
mkdir --parents -- "${HOME}"
git config --global user.email t@example.com
git config --global user.name test
git config --global init.defaultBranch master
# shellcheck disable=SC2317
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

fails=0
pass() { printf '%s\n' "  PASS  $1"; }
fail() { printf '%s\n' "  FAIL  $1" >&2; fails=$(( fails + 1 )); }

## Repo whose HEAD~1..HEAD change is undecodable (fatal) content.
repo="${work}/r"
git init -q "${repo}"
cd -- "${repo}"
printf '%s\n' 'ok' > bad.txt
git add -A
git commit -qm base
printf '%s\n' "x "$'\377\376'" y" > bad.txt
git add -A
git commit -qm bad

## The review tools must never spawn a pager. On a terminal git pages the
## diffstat of 'git diff --stat' unless '--no-pager' is given, and the pager then
## waits for a keypress no automated consumer can send. GIT_PAGER points at a
## stub that records the call and otherwise behaves like 'cat', so a regression
## is a named FAIL here instead of a hang.
pager_log="${work}/pager.log"
pager_stub="${work}/pager-stub"
pager_log_q="$(printf '%q' "${pager_log}")"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "printf \"PAGER-CALLED\\n\" >> ${pager_log_q}"
   printf '%s\n' 'exec cat'
} > "${pager_stub}"
chmod +x -- "${pager_stub}"
export GIT_PAGER="${pager_stub}"
true > "${pager_log}"

pty_run() {
   ## $1 = comma-separated answer sequence (one per prompt); echoes the full
   ## PTY_* report from git-meld-tests-pty.py.
   ( cd -- "${repo}" && "${pyhelper}" "$1" "${gdr}" HEAD~1 HEAD 2>/dev/null )
}
pty_field() {
   ## $1 = report, $2 = field name (PTY_EXITCODE / PTY_ANSWERED / PTY_CONTINUED).
   printf '%s' "$1" | sed -n "s/^$2=//p"
}

## 1) Proceed 'y', then continue past the fatal content 'y' -> exit 0, the
## neutralized diff IS rendered.
y_report="$( pty_run 'y,y' )"
y_code="$( pty_field "${y_report}" PTY_EXITCODE )"
if [ "${y_code}" = 0 ]; then
   pass "interactive: proceed+'y' continues past fatal content (exit 0)"
elif [ "${y_code}" = timeout ]; then
   fail "interactive: 'y,y' never returned; the tool is stuck on a prompt or a pager"
else
   fail "interactive: 'y,y' did not continue (exit '${y_code}')"
fi

if [ -s "${pager_log}" ]; then
   fail "a pager was spawned under a tty (missing '--no-pager'); an unattended review would hang"
else
   pass "no pager spawned under a tty"
fi

## 2) Proceed 'y', then DECLINE the fatal content 'n' -> fail closed (non-zero).
## The proceed 'y' is required to even reach the fatal prompt.
n_report="$( pty_run 'y,n' )"
n_code="$( pty_field "${n_report}" PTY_EXITCODE )"
if [ "${n_code}" = timeout ]; then
   fail "interactive: 'y,n' never returned; the tool is stuck on a prompt or a pager"
elif [ -n "${n_code}" ] && [ "${n_code}" != 0 ]; then
   pass "interactive: declining fatal content fails closed (exit '${n_code}')"
else
   fail "interactive: declining fatal content did not fail closed (exit '${n_code}')"
fi

## 3) DECLINE the proceed prompt itself -> must FAIL CLOSED (non-zero) WITHOUT
## scanning. The per-file dispatch is the only place content is scanned, so a
## clean-looking exit 0 here would let a human wave a Trojan-Source change past
## with a success code an automated caller trusts. No diff is rendered
## (PTY_CONTINUED false: no neutralized-diff banner, no '@@' hunk), the prompt
## did fire (PTY_ANSWERED >= 1), and the exit is non-zero. Fails on the exit-0
## variant and on the pre-gate tool (no such prompt; it dumped the diff).
skip_report="$( pty_run 'n' )"
skip_code="$( pty_field "${skip_report}" PTY_EXITCODE )"
skip_cont="$( pty_field "${skip_report}" PTY_CONTINUED )"
skip_answered="$( pty_field "${skip_report}" PTY_ANSWERED )"
if [ "${skip_code}" = timeout ]; then
   fail "interactive: declining the proceed prompt never returned (stuck)"
elif [ "${skip_answered:-0}" = 0 ]; then
   fail "interactive: the proceed prompt never fired (nothing to decline)"
elif [ "${skip_cont}" != False ]; then
   fail "interactive: declining the proceed prompt still rendered/scanned a diff (PTY_CONTINUED='${skip_cont}')"
elif [ -z "${skip_code}" ] || [ "${skip_code}" = 0 ]; then
   fail "interactive: declining the proceed prompt must FAIL CLOSED (non-zero), got '${skip_code}'"
else
   pass "interactive: declining the proceed prompt aborts non-zero without scanning (no false-clean exit 0)"
fi

printf '%s\n' '' "==== interactive FAILURES: ${fails} ===="
[ "${fails}" -eq 0 ]
