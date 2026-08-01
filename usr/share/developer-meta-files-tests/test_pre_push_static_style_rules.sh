#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for the pre-push-static single-grep style checks: assert that
## R-070 (';;' trailing a statement), R-074 (';'-chained break/continue/return),
## R-030/R-031 (a newline printf missing its explicit "" data argument), R-042
## (a blank-line separator), R-034 (echo run as a command), R-011 (set +e),
## R-051 (a quoted inline trap), R-090 (command -v), R-103 (a
## process-replacement exec), R-102 (an extensionless
## 'bash script' operand), R-120 (a separator-glued/adjacent rm), and R-010
## (distinct strict-mode directives) actually FLAG a violating shell file and
## SPARE a compliant one. It drives the real, shipped pre-push-static gate
## (dist-ai) as a subprocess against a throwaway git
## repo, so it exercises the check end to end (regex + file selection + reporting),
## not a private copy of the regex.
##
## Every violation snippet is assembled at RUN TIME -- the ';' comes from a
## variable, never a literal -- so neither this test file nor the repository
## carries a ';'-chained keyword that the gate would (correctly) trip over.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## The gate under test (pre-push-static) now ships in dist-ai itself
## (usr/bin/pre-push-static), so this test no longer needs DMF_REPO.

## Fail closed. A missing prerequisite is an environment defect: staying
## green where the gate cannot run reports success for a test that never
## ran, which is worse than no test at all.
assert_prerequisite() {
   local description

   description="$1"
   shift

   if ! "$@"; then
      printf '%s\n' "FATAL: test_pre_push_static_style_rules: ${description}" >&2
      exit 1
   fi
}

assert_prerequisite \
   'helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)' \
   test -r '/usr/libexec/helper-scripts/has.sh'
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

assert_prerequisite 'git not on PATH' has git
assert_prerequisite 'safe-rm not on PATH' has safe-rm

## pre-push-static self-skips its ENTIRE pre-commit-hooks tier when check-yaml
## is off PATH, so without these the tier assertions below fail as if the gate
## were broken. Name the absent dependency instead (apt-get install
## pre-commit-hooks).
assert_prerequisite \
   'check-yaml not on PATH (apt-get install pre-commit-hooks)' has check-yaml
assert_prerequisite \
   'double-quote-string-fixer not on PATH (apt-get install pre-commit-hooks)' \
   has double-quote-string-fixer

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/).
## That path is correct in both layouts -- installed it resolves to
## /usr/bin/pre-push-static, from a checkout to the checkout's own copy -- so it
## must be tried FIRST. Preferring the installed CLI instead silently tests the
## PACKAGED gate while a developer edits the in-tree one: every new rule then
## reads as "does not fire" and every 'absent' assertion passes vacuously.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi

[ -x "${GATE}" ] \
   || { printf '%s\n' "error: gate not executable at '${GATE}'." >&2; exit 1; }

tmp_root="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${tmp_root}"
}
trap cleanup EXIT

failures=0

## Build a throwaway repo whose HEAD adds sample.sh (a shebang + the given body)
## on top of an empty base, run the gate against that base, and echo its combined
## output. The body is untrusted text placed only in a /tmp repo, never committed
## to developer-meta-files, so it cannot self-trip this repo's own gate.
## gate_output <body> [<shebang>] -- run the gate over a one-file fixture.
## The shebang is a parameter because some rules are dialect-dependent: R-090's
## remedies are bash-only, so a POSIX '/bin/sh' fixture must be able to prove the
## rule does NOT fire there.
gate_output() {
   local body repo base shebang
   body="$1"
   shebang="${2:-#!/bin/bash}"
   repo="$(mktemp --directory --tmpdir="${tmp_root}" repo.XXXXXX)"
   git -C "${repo}" init --quiet
   git -C "${repo}" config user.email 'ci-test@example.com'
   git -C "${repo}" config user.name 'ci-test'
   ## '--no-verify' on the throwaway fixture commits: the gate under test reads
   ## commit/worktree content directly, never via git hooks, so any local hook
   ## (e.g. a developer's whitespace/unicode pre-commit guard) must not get a
   ## veto over a fixture that deliberately carries a violation -- otherwise the
   ## trailing-whitespace fixture cannot even be committed on such a machine.
   git -C "${repo}" commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   printf '%s\n%s\n' "${shebang}" "${body}" > "${repo}/sample.sh"
   git -C "${repo}" add sample.sh
   git -C "${repo}" commit --quiet --no-verify --message sample
   (
      cd -- "${repo}" || exit 1
      "${GATE}" "${base}"
   ) 2>&1 || true
}

## expect_rule <rule-tag> <sample-body> <present|absent>
## Assert the gate output does / does not carry <rule-tag> for the sample body.
expect_rule() {
   local tag body want out got shebang
   tag="$1"
   body="$2"
   want="$3"
   shebang="${4:-#!/bin/bash}"
   out="$(gate_output "${body}" "${shebang}")"
   ## Liveness guard: require the gate's TERMINAL verdict line, not just any
   ## 'pre-push-static:' note. Early notes ('no changed shell files',
   ## 'shellcheck not on PATH; skipping') would otherwise satisfy a weaker
   ## check even if the gate crashed before reaching the rule under test, so
   ## an 'absent' assertion could pass spuriously on a real regression.
   if ! printf '%s\n' "${out}" \
      | grep --quiet --extended-regexp 'all static checks passed|[0-9]+ check\(s\) failed'; then
      printf 'FAIL: gate produced no final verdict for body %s\n' "'${body}'" >&2
      failures=$((failures + 1))
      return 0
   fi
   if printf '%s\n' "${out}" | grep --quiet --fixed-strings -- "${tag}"; then
      got="present"
   else
      got="absent"
   fi
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s %-7s for body %s (%s)\n' "${tag}" "${want}" "'${body}'" "${shebang}"
   else
      printf 'FAIL: %s expected %s but was %s for body %s\n' \
         "${tag}" "${want}" "${got}" "'${body}'" >&2
      failures=$((failures + 1))
   fi
}

## ';' and ';;' assembled here so the literals never appear in tracked source.
sc=';'
dsemi=';;'

## Fragments for the printf-newline assertions, assembled the same way so a
## literal bad-form printf never appears in this tracked file (which the gate
## would, correctly, trip over).
sq="'"
dq='"'
## Literal backslash-n (two chars), single-quoted so it is not interpreted.
nl='\n'
## A literal space and 'rm' as a value, so assertion bodies needing a real
## space-before-'rm' (R-120) or 'command -v' (R-090) do not embed a token
## the gate would flag in THIS tracked file.
sp=' '
del='rm'
## A literal ':' as a value, so the R-130 assertion bodies do not embed a
## token the gate would flag in THIS tracked file.
colon=':'
## A real tab, assembled at run time so no literal trailing tab lives in this
## tracked file (which the gate's own trailing-whitespace check would flag).
tab="$(printf '\t')"
## A real carriage return, for the CRLF trailing-whitespace cases.
cr="$(printf '\r')"
## The hardcoded temp path R-170 forbids, assembled so the literal never
## appears in THIS tracked file (which the gate would, correctly, flag).
tmpp="/$(printf '%s' 'tmp')"
## A real newline, for the multi-line waiver fixture below.
nlreal=$'\n'

## R-074: a ';'-chained break / continue / return must be FLAGGED; the same
## keyword on its own line must be SPARED.
expect_rule "R-074" "hit=1${sc} break"       "present"
expect_rule "R-074" "seen=1${sc} continue"   "present"
expect_rule "R-074" "printf x${sc} return 1" "present"
expect_rule "R-074" "break"                  "absent"

## Whitespace on either side of the ';' is the same violation and must also be
## FLAGGED -- guards against a regex that only anchors on a non-space char
## immediately before the ';'. The bodies below assemble the separator from
## ${sc} at run time, so the literal never appears in this tracked file.
expect_rule "R-074" "hit=1 ${sc} break"      "present"
expect_rule "R-074" "printf y ${sc} return"  "present"

## Word boundary: a keyword that is only a PREFIX of an identifier
## ('return_value', 'continue_calls') must be SPARED, not flagged.
expect_rule "R-074" "x=1${sc}${sp}return_value=1" "absent"

## R-070: ';;' trailing a statement must be FLAGGED; ';;' on its own line spared.
expect_rule "R-070" "esac${dsemi}"           "present"
expect_rule "R-070" "${dsemi}"               "absent"

## R-030/R-031: a newline emitted without an explicit '' data argument must be
## FLAGGED -- both 'printf \n' (newline in the format) and a bare 'printf %s\n'
## (data arg omitted). The compliant 'printf %s\n' "" and a normal data printf
## must be SPARED by this rule (the blank-separator form is R-042's job, below).
expect_rule "R-030/R-031" "printf ${sq}${nl}${sq}"              "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq}"            "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} ${dq}${dq}" "absent"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} hello"      "absent"
## A trailing comment does not supply a data argument, so a commented bare
## form is still a violation; the compliant form stays spared even commented.
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} # blank"        "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} ${dq}${dq} # ok" "absent"

## The compliant 'printf %s\n' "" IS a blank-line separator, so R-042 (not
## R-031) is the rule that owns it -- proves the two checks divide the work
## cleanly rather than both firing or both missing.
expect_rule "R-042" "printf ${sq}%s${nl}${sq} ${dq}${dq}"       "present"

## R-034: 'echo' run as a command must be FLAGGED; 'echo' as a bareword inside
## a string or as another command's argument must be SPARED (the command-
## position anchoring that replaced the old '[[:space:]]echo' form).
expect_rule "R-034" "echo hi"                                   "present"
## echo run as a condition command (line-start keyword) must also be FLAGGED.
expect_rule "R-034" "if echo hi${sc} then"                      "present"
expect_rule "R-034" "printf ${sq}%s${nl}${sq} ${dq}a echo b${dq}" "absent"
expect_rule "R-034" "has echo"                                  "absent"

## R-070: ';;' must be on its own line. Both the jammed ('esac;;') and the
## spaced ('esac ;;') compact forms are FLAGGED; only a bare ';;' is spared.
expect_rule "R-070" "esac${sp}${dsemi}"                          "present"

## R-042: a DOUBLE-quoted blank-separator format is the same violation.
expect_rule "R-042" "printf ${dq}%s${nl}${dq} ${dq}${dq}"        "present"

## R-011: both the long toggle and the short 'set +e' must be FLAGGED.
expect_rule "R-011" "set +o errexit"                             "present"
expect_rule "R-011" "set +e"                                     "present"

## R-051: a double-quoted inline trap command is FLAGGED; clearing a trap
## with an empty string is SPARED.
expect_rule "R-051" "trap ${dq}${del} -f x${dq} EXIT"            "present"
expect_rule "R-051" "trap ${dq}${dq} EXIT"                       "absent"
## A trap in a '#' comment is documentation, not a live trap, so it is SPARED
## (the leading '^[^#]*' skips it), mirroring R-070's comment handling.
expect_rule "R-051" "#trap ${dq}${del} -f x${dq} EXIT"           "absent"
## The parameterized named-function form is SPARED in all three spellings of
## the handler: bare, '$name', and the R-020-mandated '${name}'. Missing the
## braced one made R-051 and R-020 contradict each other.
expect_rule "R-051" "trap ${dq}handler \${signal}${dq} ERR"      "absent"
expect_rule "R-051" "trap ${dq}\$handler \${signal}${dq} ERR"    "absent"
expect_rule "R-051" "trap ${dq}\${handler} \${signal}${dq} ERR"  "absent"
## Still FLAGGED with a braced-variable leading token: a LITERAL argument
## means real command logic, not a dispatch to a named handler.
expect_rule "R-051" "trap ${dq}\${cmd} -f x${dq} EXIT"           "present"

## R-130: ':' used as a COMMAND is FLAGGED -- bare, and the truncate idiom
## ('`: > f`', '`if ! : > f`'). The parameter-default idiom and every colon
## that is not in command position are SPARED.
expect_rule "R-130" "${colon}"                                    "present"
expect_rule "R-130" "${colon} > ${dq}\${report}${dq}"            "present"
expect_rule "R-130" "if ! ${colon} > ${dq}\${report}${dq}; then" "present"
expect_rule "R-130" "${colon} ${dq}\${var:=default}${dq}"        "absent"
expect_rule "R-130" "value=${dq}\${var:-fallback}${dq}"          "absent"
expect_rule "R-130" "PATH=${dq}/a::/b${dq}"                      "absent"
expect_rule "R-130" "url=${dq}https://example.com${dq}"          "absent"
expect_rule "R-130" "## ${colon} > file in a comment"            "absent"

## R-090: 'command -v' in code is FLAGGED; in a comment it is SPARED.
expect_rule "R-090" "if ! command${sp}-v foo"                    "present"
expect_rule "R-090" "## uses command${sp}-v not has"             "absent"
## ... and it does NOT fire in a POSIX '/bin/sh' script, where 'type -P' is
## undefined (SC3045) and sourcing has.sh is not an option: 'command -v' is the
## only portable spelling, so flagging it would demand code shellcheck rejects.
expect_rule "R-090" "if ! command${sp}-v foo"                    "absent"  '#!/bin/sh'

## R-103: a COMMAND-POSITION 'exec <command>' is FLAGGED. An 'exec' that is an
## argument to another command, an fd-redirection exec, and a usage-TEXT line
## describing an 'exec' SUBCOMMAND with bracketed options are all SPARED -- the
## last one is why the trailing class excludes '['.
expect_rule "R-103" "exec${sp}some-command --flag"               "present"
expect_rule "R-103" "exec${sp}${dq}\${impl}${dq} ${dq}\$@${dq}" "present"
expect_rule "R-103" "  exec  [--workdir DIR] [--raw] -- CMD"     "absent"
expect_rule "R-103" "exec${sp}9>${dq}\${lock}${dq}"              "absent"
expect_rule "R-103" "docker${sp}exec${sp}-it name sh"            "absent"

## R-102: an extensionless but slashed path operand is FLAGGED; a flag or a
## variable operand is SPARED. (Body assembled below via ${sp} so this
## comment carries no literal invocation.)
expect_rule "R-102" "bash${sp}ci/dry-run-start"                  "present"
expect_rule "R-102" "sh${sp}/usr/local/bin/foo"                  "present"
expect_rule "R-102" "bash${sp}--norc script"                     "absent"
expect_rule "R-102" "bash${sp}\${script}"                        "absent"
## A short flag ending in 'sh' and a .sh script run AS the command (with a
## path argument) are NOT interpreter prepends; both matched the old '\b'
## anchor ('\b' also fires after '-' and '.'), so pin them SPARED.
expect_rule "R-102" "du${sp}-sh${sp}/home/user/.cache"           "absent"
expect_rule "R-102" "run${sp}wrapper.sh${sp}/etc/config"         "absent"

## R-120: a separator-glued 'rm', and a real 'rm' next to a safe-rm on one
## line, are both FLAGGED (the invert no longer spares the whole line).
expect_rule "R-120" "true${sc}${del} -rf x"                      "present"
expect_rule "R-120" "safe-${del} -- a${sc}${sp}${del} -rf b"     "present"

## R-170: a hardcoded temp path must be FLAGGED, including the inline
## '${TMPDIR:-/tmp}' fallback idiom the rule exists to retire.
expect_rule "R-170" "work=${dq}${tmpp}/covwork${dq}"             "present"
expect_rule "R-170" "d=\$(mktemp -- ${dq}${tmpp}/x.XXXXXX${dq})" "present"
expect_rule "R-170" "d=${dq}\${TMPDIR:-${tmpp}}/x${dq}"          "present"
expect_rule "R-170" "cp -- foo ${tmpp}"                          "present"
## ... and the temp-dir variable INITIALISATIONS must be SPARED: they are the
## one place the literal belongs. Both the canonical guarded form and the
## bare/exported/bwrap spellings.
expect_rule "R-170" "[ -v TMP ] || TMP=${tmpp}"                  "absent"
expect_rule "R-170" "TMPDIR=${tmpp}"                             "absent"
expect_rule "R-170" "export TEMP=${tmpp}"                        "absent"
expect_rule "R-170" "readonly TEMPDIR=${tmpp}"                   "absent"
expect_rule "R-170" "bw+=(--setenv TMPDIR ${tmpp})"              "absent"
## Neither a different path that merely ENDS in '/tmp', nor a longer name
## that merely STARTS with '/tmp', is the hardcode.
expect_rule "R-170" "d=${dq}debian${tmpp}/usr${dq}"              "absent"
expect_rule "R-170" "d=${dq}/var${tmpp}/persist${dq}"            "absent"
expect_rule "R-170" "d=${dq}${tmpp}fs/thing${dq}"                "absent"
expect_rule "R-170" "d=${dq}\${TMP}/mine${dq}"                   "absent"
## A '/tmp' rooted in an expansion or in HOME is a subdirectory named tmp,
## not the absolute system path, so it must be SPARED.
expect_rule "R-170" "d=${dq}\${build_dir}/tmp/x${dq}"            "absent"
expect_rule "R-170" "d=${dq}\$(pwd)/tmp${dq}"                    "absent"
expect_rule "R-170" "d=~/tmp"                                    "absent"
## The initialisation is spared QUOTED as well as bare -- both quote styles,
## and the bwrap form.
expect_rule "R-170" "TMP=${dq}${tmpp}${dq}"                      "absent"
expect_rule "R-170" "export TMPDIR=${sq}${tmpp}${sq}"            "absent"
expect_rule "R-170" "readonly TEMP=${dq}${tmpp}${dq}"            "absent"
expect_rule "R-170" "bw+=(--setenv TMPDIR ${dq}${tmpp}${dq})"    "absent"
## ... but a temp-dir var assigned a SUBPATH of /tmp is still a hardcode:
## only the bare '<VAR>=/tmp' initialisation is spared.
expect_rule "R-170" "TMPDIR=${tmpp}/wrong"                       "present"
## A script-wide waiver disables the rule for the whole file.
expect_rule "R-170" "## style-ok: no-tmp-hardcode${nlreal}w=${dq}${tmpp}/x${dq}" "absent"

## R-010: six COPIES of one directive must NOT satisfy the block (DISTINCT
## directives are counted); the six distinct directives pass.
sixsame=$'set -o errexit\nset -o errexit\nset -o errexit\nset -o errexit\nset -o errexit\nset -o errexit'
sixdistinct=$'set -o errexit\nset -o nounset\nset -o pipefail\nset -o errtrace\nshopt -s inherit_errexit\nshopt -s shift_verbose'
expect_rule "R-010" "${sixsame}"                                 "present"
expect_rule "R-010" "${sixdistinct}"                             "absent"

## R-010 source-able exemption (present==0 AND a was_executed/was_sourced
## GUARD CALL) must fire ONLY for a real command-position call, not for an
## assignment or a string/param mention -- else a strict-mode-less script
## self-exempts. The tag is the FULL fail label so it distinguishes a real
## FAIL from the 'R-010 skipped' note (both contain 'R-010'). Present =>
## R-010 enforced (not exempted); absent => exemption applied.
guard_fail='R-010 strict-mode block'
## Assignment 'was_executed=1' is an ordinary flag var, NOT a guard: enforce.
expect_rule "${guard_fail}" "was_executed=1"                     "present"
## A string mention of the token is NOT a guard call: enforce.
expect_rule "${guard_fail}" "printf ${sq}%s${nl}${sq} ${dq}was_sourced${dq}" "present"
## A real command-position guard call still exempts.
expect_rule "${guard_fail}" "was_sourced && main"               "absent"

## R-080: a 'shellcheck source=' path must be relative, anchored with ./ or
## ../ (start with '.'). An absolute path OR a bare name (no ./) is FLAGGED.
expect_rule "R-080" "# shellcheck source=get_colors.sh"          "present"
expect_rule "R-080" "# shellcheck source=/usr/lib/foo.sh"        "present"
expect_rule "R-080" "# shellcheck source=./get_colors.sh"        "absent"
expect_rule "R-080" "# shellcheck source=../../foo.sh"           "absent"

## trailing-whitespace: a space OR tab immediately before end-of-line must be
## FLAGGED (the always-on native floor, independent of pre-commit-hooks); a
## clean line must be SPARED. Separators assembled from ${sp}/${tab} so no
## literal trailing whitespace lives in this tracked file.
expect_rule "trailing-whitespace" "true${sp}"  "present"
expect_rule "trailing-whitespace" "true${tab}" "present"
expect_rule "trailing-whitespace" "true"       "absent"
## CRLF: a blank BEFORE the carriage return is still trailing whitespace and
## must be FLAGGED (the CR sits between the blank and end-of-line); a clean
## CRLF line (bare CR, no preceding blank) must be SPARED.
expect_rule "trailing-whitespace" "true${sp}${cr}" "present"
expect_rule "trailing-whitespace" "true${cr}"      "absent"

## is_shell_file must detect a CRLF-terminated shebang. Regression for a '\r'
## left on the first line by 'read', which defeated the end-anchored
## interpreter globs and silently dropped the file from the ENTIRE shell tier
## (bash -n, shellcheck, every R-check). Use an EXTENSIONLESS file so
## detection relies on the shebang, not the name; give it a CRLF shebang and
## an R-120 'rm -rf' violation. With the fix the shell tier runs and flags
## R-120; without it R-120 never fires.
crlf_repo="$(mktemp --directory --tmpdir="${tmp_root}" crlf.XXXXXX)"
git -C "${crlf_repo}" init --quiet
git -C "${crlf_repo}" config user.email 'ci-test@example.com'
git -C "${crlf_repo}" config user.name 'ci-test'
git -C "${crlf_repo}" commit --quiet --no-verify --allow-empty --message base
crlf_base="$(git -C "${crlf_repo}" rev-parse HEAD)"
## CRLF shebang line; the violation line is plain LF so only the shebang
## exercises the CRLF path. 'deploy' has no extension on purpose.
printf '#!/bin/bash\r\ntrue%s%s -rf x\n' "${sc}" "${del}" > "${crlf_repo}/deploy"
git -C "${crlf_repo}" add deploy
git -C "${crlf_repo}" commit --quiet --no-verify --message crlf
crlf_out="$( cd -- "${crlf_repo}" && "${GATE}" "${crlf_base}" 2>&1 || true )"
if printf '%s\n' "${crlf_out}" | grep --quiet --fixed-strings -- "R-120"; then
   printf 'PASS: is_shell_file detects a CRLF shebang (shell tier ran, R-120 flagged)\n'
else
   printf 'FAIL: CRLF-shebang file was NOT shell-checked (R-120 missing)\n' >&2
   failures=$((failures + 1))
fi

## double-quote-string-fixer vs black: the two normalise Python string quotes
## in OPPOSITE directions, so running the fixer on a black-formatted repo makes
## the gate demand a change that repo's own CI rejects. Assert the fixer is
## SKIPPED when pyproject.toml declares '[tool.black]', and still RUNS when it
## does not -- a guard that never fires is the same bug in reverse.
dq_probe() {
   local declare_black repo base out
   declare_black="$1"
   repo="$(mktemp --directory --tmpdir="${tmp_root}" dq.XXXXXX)"
   git -C "${repo}" init --quiet
   git -C "${repo}" config user.email 'ci-test@example.com'
   git -C "${repo}" config user.name 'ci-test'
   git -C "${repo}" commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   ## A double-quoted string is exactly what the fixer rewrites.
   printf 'x = "fix me"\n' > "${repo}/probe.py"
   if [ "${declare_black}" = 'true' ]; then
      printf '[tool.black]\nline-length = 79\n' > "${repo}/pyproject.toml"
   fi
   git -C "${repo}" add --all
   git -C "${repo}" commit --quiet --no-verify --message probe
   out="$( cd -- "${repo}" && "${GATE}" "${base}" 2>&1 || true )"
   printf '%s' "${out}"
}

if printf '%s' "$(dq_probe true)" | grep --quiet --fixed-strings -- 'double-quote-string-fixer skipped'; then
   printf 'PASS: double-quote-string-fixer skipped on a black repo\n'
else
   printf 'FAIL: double-quote-string-fixer NOT skipped on a black repo\n' >&2
   failures=$((failures + 1))
fi

if printf '%s' "$(dq_probe false)" | grep --quiet --fixed-strings -- 'FAIL double-quote-string-fixer'; then
   printf 'PASS: double-quote-string-fixer still runs without black\n'
else
   printf 'FAIL: double-quote-string-fixer did not run on a non-black repo\n' >&2
   failures=$((failures + 1))
fi

## check-added-large-files must not choke on a path that exists at HEAD but is
## absent from the WORKING TREE (an uncommitted deletion, e.g. gating a staged
## 'git revert --no-commit'). Such a path is a changed file and is absent from
## the base ref, so it reaches the added-file list -- but there is nothing on
## disk to stat, and the hook died with FileNotFoundError, failing a changeset
## that is otherwise fine. A committed deletion does NOT reproduce it: the file
## then leaves the base..HEAD diff entirely.
addel_repo="$(mktemp --directory --tmpdir="${tmp_root}" addel.XXXXXX)"
git -C "${addel_repo}" init --quiet
git -C "${addel_repo}" config user.email 'ci-test@example.com'
git -C "${addel_repo}" config user.name 'ci-test'
printf '%s\n' 'seed' > "${addel_repo}/seed.txt"
git -C "${addel_repo}" add seed.txt
git -C "${addel_repo}" commit --quiet --no-verify --message base
addel_base="$(git -C "${addel_repo}" rev-parse HEAD)"
printf '%s\n' 'transient' > "${addel_repo}/transient.txt"
git -C "${addel_repo}" add transient.txt
git -C "${addel_repo}" commit --quiet --no-verify --message add
## delete it WITHOUT committing: present at HEAD, gone from the working tree
safe-rm --force -- "${addel_repo}/transient.txt"
addel_out="$( cd -- "${addel_repo}" && "${GATE}" "${addel_base}" 2>&1 || true )"
if printf '%s\n' "${addel_out}" | grep --quiet --fixed-strings -- 'FileNotFoundError'; then
   printf 'FAIL: uncommitted deletion crashed check-added-large-files\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: uncommitted deletion does not crash the large-files hook\n'
fi

## R-180: a python file must carry a shebang (and, via the pre-commit hooks,
## be executable). A file with NEITHER a shebang nor '+x' slips past both
## check-shebang-scripts-are-executable and check-executables-have-shebangs,
## which is the gap R-180 closes. An EMPTY '__init__.py' is exempt.
py_repo="$(mktemp --directory --tmpdir="${tmp_root}" py.XXXXXX)"
git -C "${py_repo}" init --quiet
git -C "${py_repo}" config user.email 'ci-test@example.com'
git -C "${py_repo}" config user.name 'ci-test'
git -C "${py_repo}" commit --quiet --no-verify --allow-empty --message base
py_base="$(git -C "${py_repo}" rev-parse HEAD)"
printf 'x = 1\n' > "${py_repo}/noshebang.py"
printf '#!/usr/bin/python3 -Bsu\ny = 2\n' > "${py_repo}/withshebang.py"
true > "${py_repo}/__init__.py"
chmod 0755 -- "${py_repo}/withshebang.py"
git -C "${py_repo}" add --all
git -C "${py_repo}" commit --quiet --no-verify --message py
py_out="$( cd -- "${py_repo}" && "${GATE}" "${py_base}" 2>&1 || true )"
if printf '%s\n' "${py_out}" | grep --quiet --fixed-strings -- 'R-180'; then
   printf 'PASS: R-180 flags a python file with no shebang\n'
else
   printf 'FAIL: R-180 did not flag a shebang-less python file\n' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${py_out}" | grep --quiet --fixed-strings -- 'withshebang.py'; then
   printf 'FAIL: R-180 flagged a compliant python file\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: R-180 spares a shebang+executable python file\n'
fi
if printf '%s\n' "${py_out}" | grep --quiet --fixed-strings -- '__init__.py'; then
   printf 'FAIL: R-180 flagged an EMPTY package marker\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: R-180 exempts an empty __init__.py\n'
fi

## R-190: a substantial interpreter program does not belong in a shell
## heredoc. Same defect as R-100 for workflow YAML -- ruff and pyrefly only see
## real '*.py' files, coverage.py cannot measure a heredoc, and no unit test can
## import a function that has no file. Short glue is fine; the threshold matches
## R-100's "more than ~5 lines".
inline_repo="$(mktemp --directory --tmpdir="${tmp_root}" inline.XXXXXX)"
git -C "${inline_repo}" init --quiet
git -C "${inline_repo}" config user.email 'ci-test@example.com'
git -C "${inline_repo}" config user.name 'ci-test'
git -C "${inline_repo}" commit --quiet --no-verify --allow-empty --message base
inline_base="$(git -C "${inline_repo}" rev-parse HEAD)"

printf '%s\n' \
   '#!/bin/bash' \
   'python3 - "$1" <<'"'"'PY'"'"'' \
   'a = 1' \
   'b = 2' \
   'c = 3' \
   'd = 4' \
   'e = 5' \
   'print(a, b, c, d, e)' \
   'PY' > "${inline_repo}/longinline.sh"
printf '%s\n' \
   '#!/bin/bash' \
   'python3 - <<'"'"'PY'"'"'' \
   'print("hi")' \
   'PY' > "${inline_repo}/shortglue.sh"
## A heredoc that feeds a NON-interpreter must never be flagged, however long.
printf '%s\n' \
   '#!/bin/bash' \
   'cat > /dev/null <<'"'"'EOF'"'"'' \
   'one' \
   'two' \
   'three' \
   'four' \
   'five' \
   'six' \
   'seven' \
   'EOF' > "${inline_repo}/plaindoc.sh"
printf '%s\n' \
   '#!/bin/bash' \
   '## style-ok: allow-inline-interpreter' \
   'python3 - <<'"'"'PY'"'"'' \
   'a = 1' \
   'b = 2' \
   'c = 3' \
   'd = 4' \
   'e = 5' \
   'f = 6' \
   'print(a, b, c, d, e, f)' \
   'PY' > "${inline_repo}/waived.sh"
## A DOCUMENTATION heredoc whose body demonstrates an inline program is not
## itself one. Flagging it blocks a valid push, which is worse than a miss.
printf '%s\n' \
   '#!/bin/bash' \
   'cat > /dev/null <<'"'"'DOC'"'"'' \
   'python3 - <<'"'"'PY'"'"'' \
   'a = 1' \
   'b = 2' \
   'c = 3' \
   'd = 4' \
   'e = 5' \
   'f = 6' \
   'PY' \
   'DOC' > "${inline_repo}/docexample.sh"
## A commented opener must not open a phantom body: on the way through it would
## swallow a REAL inline program later in the same file.
printf '%s\n' \
   '#!/bin/bash' \
   '## e.g. python3 - <<'"'"'PY'"'"'' \
   '## a = 1' \
   'true' \
   'python3 - <<'"'"'REAL'"'"'' \
   'x = 1' \
   'y = 2' \
   'z = 3' \
   'w = 4' \
   'v = 5' \
   'u = 6' \
   'REAL' > "${inline_repo}/masked.sh"
## Bash allows whitespace after the operator, so this is a real violation.
printf '%s\n' \
   '#!/bin/bash' \
   'python3 - << '"'"'PY'"'"'' \
   'a = 1' \
   'b = 2' \
   'c = 3' \
   'd = 4' \
   'e = 5' \
   'f = 6' \
   'PY' > "${inline_repo}/spaced.sh"
chmod 0755 -- "${inline_repo}"/*.sh
git -C "${inline_repo}" add --all
git -C "${inline_repo}" commit --quiet --no-verify --message inline
inline_out="$( cd -- "${inline_repo}" && "${GATE}" "${inline_base}" 2>&1 || true )"
## Scope every assertion to R-190 FAILURES. The fixtures deliberately lack a
## strict preamble and a copyright header, so other rules name them too.
## Match the FAILURE text, not the bare rule id: the gate also emits an
## 'R-190 skipped: ... waiver in <file>' note, which names the very file the
## waiver spared and would read as a violation.
inline_hits="$( printf '%s\n' "${inline_out}" \
   | grep --fixed-strings -- 'R-190 inline interpreter program' || true )"
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'longinline.sh'; then
   printf 'PASS: R-190 flags a long inline interpreter program\n'
else
   printf 'FAIL: R-190 did not flag a long inline interpreter program\n' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'shortglue.sh'; then
   printf 'FAIL: R-190 flagged short glue\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: R-190 spares a short inline one-liner\n'
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'plaindoc.sh'; then
   printf 'FAIL: R-190 flagged a non-interpreter heredoc\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: R-190 ignores a heredoc feeding a non-interpreter\n'
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'docexample.sh'; then
   printf 'FAIL: R-190 flagged an interpreter example inside a doc heredoc\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: R-190 ignores an interpreter example inside a doc heredoc\n'
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'masked.sh'; then
   printf 'PASS: R-190 still sees a violation after a commented opener\n'
else
   printf 'FAIL: a commented opener masked a real inline program\n' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'spaced.sh'; then
   printf 'PASS: R-190 catches whitespace after the heredoc operator\n'
else
   printf 'FAIL: R-190 missed "<< DELIM" with whitespace\n' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'waived.sh'; then
   printf 'FAIL: R-190 ignored its style-ok waiver\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: R-190 honours the allow-inline-interpreter waiver\n'
fi

## check-shebang-scripts-are-executable gains a per-file waiver. A SOURCED fragment
## carries a shebang for shellcheck dialect detection yet must stay non-executable:
## run standalone it fails on helpers only its sourcing context defines. Without the
## waiver the only way to green is chmod +x, which is a lie.
shebang_repo="$(mktemp --directory --tmpdir="${tmp_root}" shebang.XXXXXX)"
git -C "${shebang_repo}" init --quiet
git -C "${shebang_repo}" config user.email 'ci-test@example.com'
git -C "${shebang_repo}" config user.name 'ci-test'
git -C "${shebang_repo}" commit --quiet --no-verify --allow-empty --message base
shebang_base="$(git -C "${shebang_repo}" rev-parse HEAD)"
printf '#!/bin/bash\nbar=1\n' > "${shebang_repo}/plain.conf"
printf '#!/bin/bash\n## style-ok: sourced-fragment -- fixture\nfoo=1\n' \
   > "${shebang_repo}/waived.conf"
chmod 0644 -- "${shebang_repo}/plain.conf" "${shebang_repo}/waived.conf"
git -C "${shebang_repo}" add --all
git -C "${shebang_repo}" commit --quiet --no-verify --message shebang
shebang_out="$( cd -- "${shebang_repo}" && "${GATE}" "${shebang_base}" 2>&1 || true )"
## Anchor on the hook's own verdict line, not the filename: the gate's SKIP note
## names the waived file too, so a bare filename match would confirm itself.
if printf '%s\n' "${shebang_out}" \
   | grep --quiet --fixed-strings -- 'plain.conf: has a shebang but is not marked executable'; then
   printf 'PASS: shebang check still fires without the waiver\n'
else
   printf 'FAIL: shebang check missed an unwaived non-executable shebang file\n' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${shebang_out}" \
   | grep --quiet --fixed-strings -- 'waived.conf: has a shebang but is not marked executable'; then
   printf 'FAIL: shebang check ignored its sourced-fragment waiver\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: shebang check honours the sourced-fragment waiver\n'
fi

## A submodule gitlink is a DIRECTORY in the work tree. The waiver scan must not
## grep it: grep exits "Is a directory" and the noise lands in the gate output.
gitlink_repo="$(mktemp --directory --tmpdir="${tmp_root}" gitlink.XXXXXX)"
gitlink_inner="$(mktemp --directory --tmpdir="${tmp_root}" inner.XXXXXX)"
git -C "${gitlink_inner}" init --quiet
git -C "${gitlink_inner}" config user.email 'ci-test@example.com'
git -C "${gitlink_inner}" config user.name 'ci-test'
git -C "${gitlink_inner}" commit --quiet --no-verify --allow-empty --message inner
git -C "${gitlink_repo}" init --quiet
git -C "${gitlink_repo}" config user.email 'ci-test@example.com'
git -C "${gitlink_repo}" config user.name 'ci-test'
git -C "${gitlink_repo}" commit --quiet --no-verify --allow-empty --message base
gitlink_base="$(git -C "${gitlink_repo}" rev-parse HEAD)"
git -C "${gitlink_repo}" -c protocol.file.allow=always \
   submodule add --quiet -- "${gitlink_inner}" sub >/dev/null 2>&1
git -C "${gitlink_repo}" add --all
git -C "${gitlink_repo}" commit --quiet --no-verify --message gitlink
gitlink_out="$( cd -- "${gitlink_repo}" && "${GATE}" "${gitlink_base}" 2>&1 || true )"
if printf '%s\n' "${gitlink_out}" | grep --quiet --fixed-strings -- 'Is a directory'; then
   printf 'FAIL: gate grepped a submodule gitlink as if it were a file\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: gate does not grep a submodule gitlink\n'
fi
## forbid-new-submodules diffs '--staged' unless the range env vars are set, so
## in push mode it inspected an empty diff and passed unconditionally.
if printf '%s\n' "${gitlink_out}" \
   | grep --quiet --fixed-strings -- 'new submodule introduced'; then
   printf 'PASS: forbid-new-submodules sees the push-mode diff range\n'
else
   printf 'FAIL: forbid-new-submodules missed a newly added submodule\n' >&2
   failures=$((failures + 1))
fi

## R-001 gains a per-file waiver. A suite testing a SANITIZER has to contain
## the non-ASCII bytes it asserts are stripped, so the fixture is not a slip.
## The waiver must be opt-in per file, and absent it the rule must still fire.
ascii_repo="$(mktemp --directory --tmpdir="${tmp_root}" ascii.XXXXXX)"
git -C "${ascii_repo}" init --quiet
git -C "${ascii_repo}" config user.email 'ci-test@example.com'
git -C "${ascii_repo}" config user.name 'ci-test'
git -C "${ascii_repo}" commit --quiet --no-verify --allow-empty --message base
ascii_base="$(git -C "${ascii_repo}" rev-parse HEAD)"
## a non-ASCII byte (U+00D6) assembled so THIS file stays pure ASCII
non_ascii="$(printf '\303\226')"
printf '#!/usr/bin/python3 -Bsu\nx = "%s"\n' "${non_ascii}" > "${ascii_repo}/plain.py"
printf '#!/usr/bin/python3 -Bsu\n## style-ok: allow-non-ascii -- fixture\ny = "%s"\n' "${non_ascii}" > "${ascii_repo}/waived.py"
chmod 0755 -- "${ascii_repo}/plain.py" "${ascii_repo}/waived.py"
git -C "${ascii_repo}" add --all
git -C "${ascii_repo}" commit --quiet --no-verify --message ascii
ascii_out="$( cd -- "${ascii_repo}" && "${GATE}" "${ascii_base}" 2>&1 || true )"
if printf '%s\n' "${ascii_out}" | grep --quiet --fixed-strings -- "'plain.py' contains non-ASCII"; then
   printf 'PASS: R-001 still flags non-ASCII without the waiver\n'
else
   printf 'FAIL: R-001 did not flag non-ASCII -- the waiver is too broad\n' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${ascii_out}" | grep --quiet --fixed-strings -- "'waived.py' contains non-ASCII"; then
   printf 'FAIL: R-001 waiver did not take effect\n' >&2
   failures=$((failures + 1))
else
   printf 'PASS: R-001 waiver exempts the marked file\n'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "test_pre_push_static_style_rules: ${failures} assertion(s) FAILED." >&2
   exit 1
fi
printf '%s\n' "test_pre_push_static_style_rules: OK -- R-070, R-074, R-030/R-031, R-042, R-034, R-011, R-051, R-090, R-102, R-103, R-120, R-170, R-180, R-010, trailing-whitespace, CRLF-shebang and double-quote-fixer-vs-black enforced as expected."
