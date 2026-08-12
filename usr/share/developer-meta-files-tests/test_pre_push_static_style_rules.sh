#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for the pre-push-static single-grep style checks: assert that
## R-070 (';;' trailing a statement), R-074 (';'-chained break/continue/return),
## R-030/R-031 (a newline printf missing its explicit "" data argument),
## R-034 (echo run as a command), R-011 (set +e),
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

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/).
## That path is correct in both layouts -- installed it resolves to
## /usr/bin/pre-push-static, from a checkout to the checkout's own copy -- so it
## must be tried FIRST. Preferring the installed CLI instead silently tests the
## PACKAGED gate while a developer edits the in-tree one: every new rule then
## reads as "does not fire" and every 'absent' assertion passes vacuously.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
## PRE_PUSH_STATIC_BIN override aims the suite at an alternate gate copy (e.g. the
## pre-fix version for a canary run); otherwise the in-tree copy, then the packaged.
GATE="${PRE_PUSH_STATIC_BIN:-${gate_test_dir}/../../bin/pre-push-static}"
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
   printf '%s\n' "${shebang}" "${body}" > "${repo}/sample.sh"
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
      printf '%s\n' \
         "FAIL: gate produced no final verdict for body '${body}'" >&2
      failures=$((failures + 1))
      return 0
   fi
   if printf '%s\n' "${out}" | grep --quiet --fixed-strings -- "${tag}"; then
      got="present"
   else
      got="absent"
   fi
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' \
         "PASS: ${tag} ${want} for body '${body}' (${shebang})"
   else
      printf '%s\n' \
         "FAIL: ${tag} expected ${want} but was ${got} for body '${body}'" >&2
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
## Fragments for the R-153 comment-scrape assertions, assembled so the '^##'
## anchor and the '$0' / '${BASH_SOURCE}' self-reference never co-occur as a
## literal on any line of THIS tracked file (which the gate would, correctly,
## flag as a comment-scrape). Combined only inside the assertion bodies, which
## gate_output writes verbatim to the fixture.
caret='^'
hash='#'
dollar='$'
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
## R-026 fragments: the array-all subscript '[@]' and the '+' alternate
## operator, assembled so the flagged sequence '${name[@]+' never appears
## literally in THIS tracked file (which the gate greps too, and would
## correctly trip over).
atall='[@]'
altop='+'
## R-062 end-of-options separator, assembled so the literal 'git
## check-ref-format --' (which the gate correctly flags) never appears in
## THIS tracked file.
dd='--'

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

## R-062 negative half: a '--' passed to a tool that rejects it (denylist:
## 'git check-ref-format') must be FLAGGED. A denylisted tool WITHOUT '--',
## a '--' with a tool that accepts it ('git rev-parse'), a non-standalone
## '--flag', and a command-token that is only a suffix ('mygit') must be SPARED.
expect_rule "R-062" "git check-ref-format ${dd} refs/heads/x" "present"
expect_rule "R-062" "out=\$(git check-ref-format ${dd} \"\${ref}\")" "present"
expect_rule "R-062" "git check-ref-format refs/heads/x"       "absent"
expect_rule "R-062" "git rev-parse ${dd} HEAD"                "absent"
expect_rule "R-062" "git check-ref-format ${dd}branch x"      "absent"
expect_rule "R-062" "mygit check-ref-format ${dd} x"          "absent"
## stcat takes EVERY argument as a path, so it reads the separator itself as a
## filename. This is the shape that broke read_integer_file and with it four of
## tb-updater's e2e scenarios.
expect_rule "R-062" "value=\$(stcat ${dd} \"\${target_file}\")"  "present"
expect_rule "R-062" "value=\$(stcat \"\${target_file}\")"        "absent"
## The scan must not cross a command boundary. Here the '--' belongs to grep,
## which accepts one; only a ';'-separated denylisted tool precedes it. Letting
## the intermediate tokens span ';', '|' or '&' turns every legitimate '--'
## later on the line into a false positive.
expect_rule "R-062" "git check-ref-format branch; grep ${dd} \"foo\" bar" "absent"
expect_rule "R-062" "git check-ref-format branch | grep ${dd} foo"        "absent"
expect_rule "R-062" "git check-ref-format branch && grep ${dd} foo"       "absent"
## ...while a '--' in a LATER argument position of the denylisted tool itself,
## with no separator between, is still the real violation.
expect_rule "R-062" "git check-ref-format \"\${ref}\" ${dd} x"            "present"

## R-070: ';;' trailing a statement must be FLAGGED; ';;' on its own line spared.
expect_rule "R-070" "esac${dsemi}"           "present"
expect_rule "R-070" "${dsemi}"               "absent"

## R-030/R-031: a newline emitted without an explicit '' data argument must be
## FLAGGED -- both 'printf \n' (newline in the format) and a bare 'printf %s\n'
## (data arg omitted). The compliant 'printf %s\n' "" and a normal data printf
## must be SPARED -- 'printf %s\n' "" is the correct newline spelling and is a
## legitimate blank-line output, not a violation.
expect_rule "R-030/R-031" "printf ${sq}${nl}${sq}"              "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq}"            "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} ${dq}${dq}" "absent"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} hello"      "absent"
## A trailing comment does not supply a data argument, so a commented bare
## form is still a violation; the compliant form stays spared even commented.
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} # blank"        "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} ${dq}${dq} # ok" "absent"

## R-030: a printf inside a single-quoted program handed to ANOTHER interpreter
## is not shell printf. awk's takes a comma-separated argument list and
## interpolates nothing from the shell, so neither of R-030's failure modes is
## reachable -- and rewriting the format to '%s' would break the awk program.
##
## The quote OPENS on a later line than the 'awk' word (line continuation), so
## this is only correct if the gate tracks quote state ACROSS lines; the
## single-line check reads each body line as shell and flagged both printfs.
awk_program="awk -v a=\"\${x}\" \\${nl}   ${sq}BEGIN {${nl}      if (a <= 0) { printf \"0.00\"; exit }${nl}      printf \"%.2f\", a / 2;${nl}    }${sq}"
expect_rule "R-030 printf format" "${awk_program}" "absent"
## CANARY: the state must RESET at the closing quote, or every violation after
## an awk program in the same file is silently spared -- a fail-OPEN, and the
## direction that matters. A real shell violation following the program above
## must still be flagged.
expect_rule "R-030 printf format" "${awk_program}${nl}printf \"bad \${x}\\n\"" "present"

## R-030 format string, numeric-PROBE carve-out. A '%d' printf whose own command
## discards BOTH stdout and stderr emits nothing, so it is a validator rather than
## output -- helper-scripts' is_integer(), the guard R-141 mandates before an
## untrusted value reaches an arithmetic context. Its FAILURE is the check, so it
## must be SPARED; rewriting such a format to '%s' turns the guard into a no-op.
## The negatives below are what stops the carve-out becoming a blanket '%d' amnesty.
r030fmt="R-030 printf format string"
discard=">/dev/null 2>&1"
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${1}${dq} ${discard} || exit 1" "absent"
## Same format, no discard at all: still output, still FLAGGED.
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${1}${dq}"                      "present"
## stdout-only discard still lets stderr out, so it does NOT qualify.
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${1}${dq} >/dev/null"           "present"
## '2>&1 >/dev/null' sends stderr to the ORIGINAL stdout -- that command still
## emits, so the ordering must not be treated as a both-streams discard.
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${1}${dq} 2>&1 >/dev/null"      "present"
## A DOUBLE-quoted format interpolates, so it never qualifies however redirected:
## the carve-out's premise is a format literal nothing can be injected into.
expect_rule "${r030fmt}" "printf ${dq}%d \${x}${dq} ${dq}\${1}${dq} ${discard}"     "present"
## Scoping: the discard belongs to the SECOND printf, so the first is judged on
## its own and stays FLAGGED. Guards against exempting a whole line by proximity.
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${a}${dq} ${sc} printf ${sq}%d${sq} ${dq}\${b}${dq} ${discard}" "present"
## '&&' is a command separator too, so the tail after it must not leak backwards.
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${a}${dq} && printf ${sq}%d${sq} ${dq}\${b}${dq} ${discard}" "present"
## The discard must belong to the printf COMMAND, not merely appear somewhere
## in its text. A redirect inside an argument's command substitution silences
## the SUBSTITUTED command; the printf itself still writes to stdout, so the
## carve-out's premise ("nothing is emitted") does not hold and the line stays
## FLAGGED.
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\$(probe ${discard})${dq}"       "present"
## An allowed format stays spared with and without the discard.
expect_rule "${r030fmt}" "printf ${sq}%s${nl}${sq} ${dq}\${1}${dq}"                 "absent"
expect_rule "${r030fmt}" "printf ${sq}%s${nl}${sq} ${dq}\${1}${dq} ${discard}"      "absent"

## A '#' INSIDE the format does not make the line a comment. The comment skip
## globbed '[[:space:]]*#*' -- one whitespace char, then anything, then a '#'
## -- so an INDENTED line carrying a '#' ANYWHERE was waived. The indent is
## load-bearing in these fixtures: without it the old glob could not match
## either, and the case would pass against the very code it must catch.
hash='#'
indent='   '
banner="${hash}${hash}${hash}"
expect_rule "${r030fmt}" "${indent}printf ${sq}${nl}${banner} %s ${banner}${nl}${sq} ${dq}\${x}${dq}" "present"
## Same violation, indented, '#' only in a trailing comment -- also waived by
## the old glob.
expect_rule "${r030fmt}" "${indent}printf ${sq}%d${sq} ${dq}\${1}${dq} ${hash} count" "present"
## A real comment -- '#' is the first non-blank character -- is still prose and
## must stay SPARED, indented too. This is what stops the fix from turning
## every rule-describing comment into a finding.
expect_rule "${r030fmt}" "${indent}${hash} printf ${sq}%d${sq} ${dq}\${1}${dq}"    "absent"
expect_rule "${r030fmt}" "${hash} printf ${sq}%d${sq} ${dq}\${1}${dq}"             "absent"

## 'printf %s\n' "" is the correct newline spelling (R-030/R-031 REQUIRE it) and
## a legitimate blank-line output, so no rule may flag it. Pin that nothing
## tagged R-042 fires on this form: a blank-line-separator check would contradict
## R-030/R-031 and must not exist.
expect_rule "R-042" "printf ${sq}%s${nl}${sq} ${dq}${dq}"       "absent"

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

## The DOUBLE-quoted newline form is equally correct and equally unflagged.
expect_rule "R-042" "printf ${dq}%s${nl}${dq} ${dq}${dq}"        "absent"

## R-011: both the long toggle and the short 'set +e' must be FLAGGED.
expect_rule "R-011" "set +o errexit"                             "present"
expect_rule "R-011" "set +e"                                     "present"

## R-013: shell options in long '-o' name, one per line. Short-flag enables of
## errexit/nounset (set -e, set -eu, set -euo pipefail) and >1 option on one
## 'set' line (set -o a -o b) are FLAGGED; a lone 'set -o <name>', 'set --'
## positional-param forms, and a bare 'set -x'/'set -f' (no e/u) are SPARED.
r013='R-013 set options long-form one-per-line'
expect_rule "${r013}" "set -eu"                                  "present"
expect_rule "${r013}" "set -e"                                   "present"
expect_rule "${r013}" "set -euo pipefail"                        "present"
expect_rule "${r013}" "set -o errexit -o nounset"               "present"
expect_rule "${r013}" "set -o errexit"                           "absent"
expect_rule "${r013}" "set -o nounset"                           "absent"
expect_rule "${r013}" "set -- ${dq}\$@${dq}"                     "absent"
## End-of-options makes the rest POSITIONAL, so these enable nothing: SPARED
## (the token skip stops at a bare '--'). Regression for the false positive
## where '--' was scanned through to a following '-e'/'-eu'.
expect_rule "${r013}" "set -- -e"                                "absent"
expect_rule "${r013}" "set -- ${dq}\$@${dq} -eu"                 "absent"
## A trailing '#' comment that mentions 'set -e' is documentation: SPARED (the
## skip stops at the '#' token).
expect_rule "${r013}" "set -o errexit # equivalent to set -e"    "absent"
expect_rule "${r013}" "set -x"                                   "absent"
## Bypass forms (both reviewers caught): e/u in a LATER token, uppercase flags
## in the bundle, and a long-then-short mix -- all FLAGGED.
expect_rule "${r013}" "set -x -e"                                "present"
expect_rule "${r013}" "set -Eeuo pipefail"                       "present"
expect_rule "${r013}" "set -o errexit -u"                        "present"
## 'set -E' (errtrace, no e/u) stays SPARED, like 'set -x'.
expect_rule "${r013}" "set -E"                                   "absent"
## A '## set -eu' comment is documentation, not code: SPARED.
expect_rule "${r013}" "## set -eu"                               "absent"
## Script-wide waiver disables it.
expect_rule "${r013}" "## style-ok: allow-short-set${nlreal}set -eu" "absent"

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

## R-070/R-074 blind spot: a '#' begins a shell comment only at the START OF A
## WORD. A '${#var}' length expansion earlier on the line is CODE, and must not
## make the violation after it invisible. A real '#' comment still spares.
expect_rule "R-070" '   0) out="${set:0:${#set}}" ;;'                    "present"
expect_rule "R-070" '   1) out="${plain}" ;;'                            "present"
expect_rule "R-070" "   argc=\${#args[@]}${sp}${sp}## a note about ;;"    "absent"
expect_rule "R-074" "if [ \"\${#a[@]}\" -eq 0 ]${sc} continue"           "present"

## R-021: a local declared WITH its assignment must be flagged; a bare
## declaration list, and a typed declaration whose attribute must be set at
## declaration time, must be spared. Assembled so the flagged sequence does
## not appear literally in THIS tracked file, which the gate also greps.
lcl='lo''cal'
expect_rule "R-021" "   ${lcl} name=\"\${1}\""        "present"
expect_rule "R-021" "   ${lcl} out=\"\$(cmd)\""       "present"
## The assignment need not be the FIRST operand: this form combines
## declaration and assignment on the second name and masks the substitution's
## exit status just the same.
expect_rule "R-021" "   ${lcl} first second=\"\$(cmd)\"" "present"
expect_rule "R-021" "   ${lcl} name other value"      "absent"
expect_rule "R-021" "   ${lcl} -a arr=()"             "absent"
expect_rule "R-021" "   ${lcl} -i count=0"            "absent"
## 'declare' is not function-local by default, so it is not this rule's.
expect_rule "R-021" "   declare name=1"               "absent"

## R-026: the obsolete pre-4.4 empty-array guard '${arr[@]+"${arr[@]}"}' (a
## nounset workaround unneeded since bash 4.4) must be FLAGGED. The legitimate
## length '${#arr[@]}', a plain '${arr[@]}', and the conditional-substitution
## forms '${arr[@]:-fallback}' / '${arr[@]:+word}' must all be SPARED -- none
## is the '+alternate-directly-on-[@]' guard. Bodies are assembled from
## ${atall}/${altop} so the flagged literal never lives in this tracked file.
guard="\${arr${atall}${altop}\"\${arr${atall}}\"}"
expect_rule "R-026" "x=${guard}"                       "present"
expect_rule "R-026" "for x in ${guard}${sc} do"        "present"
expect_rule "R-026" "n=\${#arr${atall}}"               "absent"
expect_rule "R-026" "p=\"\${arr${atall}}\""            "absent"
expect_rule "R-026" "f=\${arr${atall}:-fallback}"      "absent"
expect_rule "R-026" "c=\${arr${atall}:${altop}word}"   "absent"

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

## R-153: scraping the script's OWN comments for help/usage is FLAGGED. The
## '^##'/'^#' anchor plus a '$0' or '${BASH_SOURCE}' self-reference on a
## non-comment line is the comment-scrape signature. A plain 'dirname
## "${BASH_SOURCE[0]}"' or 'head "$0"' (no anchor) and a comment that merely
## names the pattern are SPARED. Anchor + self-ref assembled from fragments so
## this tracked file does not itself embed the flagged co-occurrence.
anchor="${caret}${hash}${hash}"
self0="${dollar}0"
selfbs="${dollar}{BASH_SOURCE[0]}"
expect_rule "R-153" "help=${dq}${dollar}(grep ${sq}${anchor}${sq} -- ${dq}${self0}${dq})${dq}" "present"
expect_rule "R-153" "sed -n ${sq}s/${anchor} //p${sq} -- ${dq}${selfbs}${dq}"                  "present"
expect_rule "R-153" "here=${dq}${dollar}(dirname -- ${dq}${selfbs}${dq})${dq}"                  "absent"
expect_rule "R-153" "head --lines 5 -- ${dq}${self0}${dq}"                                      "absent"
expect_rule "R-153" "grep ${sq}${caret}pattern${sq} -- somefile.txt"                            "absent"

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
## ...but 'git rm' -- a tracked, reversible delete -- is SPARED, INCLUDING with
## git global options between 'git' and 'rm' ('git -C <dir> rm' is the common
## test/CI form). A real 'rm' after a non-'rm' git subcommand is still FLAGGED.
expect_rule "R-120" "git${sp}${del} -f a"                        "absent"
expect_rule "R-120" "git${sp}-C${sp}x${sp}${del} -f a"           "absent"
expect_rule "R-120" "git${sp}-c${sp}k=v${sp}${del} b"            "absent"
expect_rule "R-120" "git${sp}-C${sp}x${sp}log${sp}&&${sp}${del} -rf z" "present"

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

## R-010 shopt sub-check: a source-able guarded script whose guarded block
## ENABLES errexit must carry the shopt half of the strict block too
## ('shopt -s inherit_errexit' + 'shopt -s shift_verbose'). The column-0
## count is 0 (block indented inside the guard), so this shape is exempt
## from the all-6 top-level rule -- but forgetting the shopt lines is the
## exact gap this catches. Fail tag 'R-010 shopt block' is distinct from
## 'R-010 strict-mode block', so it does not collide with the guard tests.
shopt_fail='R-010 shopt block'
guarded_no_shopt=$'if was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o nounset\n   set -o pipefail\n   set -o errtrace\nfi'
guarded_only_inherit=$'if was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o nounset\n   shopt -s inherit_errexit\nfi'
guarded_full_shopt=$'if was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o nounset\n   set -o pipefail\n   set -o errtrace\n   shopt -s inherit_errexit\n   shopt -s shift_verbose\nfi'
## errexit enabled, both shopt lines missing => FLAGGED.
expect_rule "${shopt_fail}" "${guarded_no_shopt}"               "present"
## errexit enabled, only shift_verbose missing (the make-helper-one.bsh
## case: inherit_errexit present) => still FLAGGED.
expect_rule "${shopt_fail}" "${guarded_only_inherit}"           "present"
## errexit enabled, both shopt lines present => SPARED.
expect_rule "${shopt_fail}" "${guarded_full_shopt}"             "absent"
## A guarded script that enables NO strict-mode (just calls main) has
## nothing for inherit_errexit to complete => SPARED.
expect_rule "${shopt_fail}" $'if was_executed "${BASH_SOURCE[0]}"; then\n   main "$@"\nfi' "absent"
## The 'no-strict' waiver exempts a guarded errexit block from the shopt
## sub-check too (onion-time-pre-script's deliberate minimal-strict shape).
expect_rule "${shopt_fail}" $'## style-ok: no-strict\nif was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o pipefail\nfi' "absent"

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
printf '%s\n' "#!/bin/bash${cr}" "true${sc}${del} -rf x" > "${crlf_repo}/deploy"
git -C "${crlf_repo}" add deploy
git -C "${crlf_repo}" commit --quiet --no-verify --message crlf
crlf_out="$( cd -- "${crlf_repo}" && "${GATE}" "${crlf_base}" 2>&1 || true )"
if printf '%s\n' "${crlf_out}" | grep --quiet --fixed-strings -- "R-120"; then
   printf '%s\n' 'PASS: is_shell_file detects a CRLF shebang (shell tier ran, R-120 flagged)'
else
   printf '%s\n' 'FAIL: CRLF-shebang file was NOT shell-checked (R-120 missing)' >&2
   failures=$((failures + 1))
fi

## double-quote-string-fixer is DISABLED in the gate (pre-commit/pre-commit-hooks#889: it
## rewrites Python strings to SINGLE quotes, fighting black's DOUBLE-quote normalisation in an
## unresolvable revert loop). A double-quoted Python string must therefore be left ALONE: the
## gate must neither run the fixer nor otherwise reference it.
dq_repo="$(mktemp --directory --tmpdir="${tmp_root}" dq.XXXXXX)"
git -C "${dq_repo}" init --quiet
git -C "${dq_repo}" config user.email 'ci-test@example.com'
git -C "${dq_repo}" config user.name 'ci-test'
git -C "${dq_repo}" commit --quiet --no-verify --allow-empty --message base
dq_base="$(git -C "${dq_repo}" rev-parse HEAD)"
printf '%s\n' 'x = "double quoted"' > "${dq_repo}/probe.py"
git -C "${dq_repo}" add --all
git -C "${dq_repo}" commit --quiet --no-verify --message probe
dq_out="$( cd -- "${dq_repo}" && "${GATE}" "${dq_base}" 2>&1 || true )"
if printf '%s' "${dq_out}" | grep --quiet --fixed-strings -- 'double-quote-string-fixer'; then
   printf '%s\n' 'FAIL: the gate still references double-quote-string-fixer (should be disabled)' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: double-quote-string-fixer is disabled -- double quotes are left alone'
fi

## A Python file inside an installed package directory is imported, never run.
## Debian ships those 0644, so the shebang-plus-executable rules must not fire
## on them -- and must still fire on an ordinary script.
module_probe() {
   local rel repo base out
   rel="$1"
   repo="$(mktemp --directory --tmpdir="${tmp_root}" mod.XXXXXX)"
   git -C "${repo}" init --quiet
   git -C "${repo}" config user.email 'ci-test@example.com'
   git -C "${repo}" config user.name 'ci-test'
   git -C "${repo}" commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   mkdir --parents -- "${repo}/$(dirname -- "${rel}")"
   ## A shebang with no +x: what an imported module in a Debian package looks
   ## like, and what an ordinary script must not look like.
   printf '%s\n' '#!/usr/bin/python3 -su' 'x = 1' > "${repo}/${rel}"
   chmod 0644 -- "${repo}/${rel}"
   git -C "${repo}" add --all
   git -C "${repo}" commit --quiet --no-verify --message probe
   out="$( cd -- "${repo}" && "${GATE}" "${base}" 2>&1 || true )"
   printf '%s' "${out}"
}

if printf '%s' "$(module_probe 'usr/lib/python3/dist-packages/probe/mod.py')" \
   | grep --quiet --fixed-strings -- 'is an imported package module'; then
   printf '%s\n' 'PASS: an imported package module is exempt from the shebang/+x rules'
else
   printf '%s\n' 'FAIL: an imported package module was held to the shebang/+x rules' >&2
   failures=$((failures + 1))
fi

if printf '%s' "$(module_probe 'usr/bin/probe-tool.py')" \
   | grep --quiet --fixed-strings -- 'check-shebang-scripts-are-executable'; then
   printf '%s\n' 'PASS: an ordinary script with a shebang still needs +x'
else
   printf '%s\n' 'FAIL: the shebang/+x rule stopped firing for ordinary scripts' >&2
   failures=$((failures + 1))
fi

## A directory merely NAMED dist-packages is not a Python library path. An
## unanchored exemption would let any script opt out of the rule by sitting in
## one.
if printf '%s' "$(module_probe 'usr/bin/dist-packages/probe-tool.py')" \
   | grep --quiet --fixed-strings -- 'check-shebang-scripts-are-executable'; then
   printf '%s\n' 'PASS: a directory merely named dist-packages is not exempt'
else
   printf '%s\n' 'FAIL: a script escaped the shebang/+x rule via a dist-packages directory name' >&2
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
   printf '%s\n' 'FAIL: uncommitted deletion crashed check-added-large-files' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: uncommitted deletion does not crash the large-files hook'
fi

## check-added-large-files, staged mode, no upstream: a large file already
## tracked at HEAD that a staged change merely TOUCHES must not be flagged as
## newly added. In staged mode the base is HEAD (the index is diffed against
## it), so the "already tracked" exclusion must resolve against HEAD -- not the
## push-mode default '@{u}', which is unresolvable on a branch with no upstream
## and made the exclusion silently fail, so a pre-existing large file failed the
## gate on every changeset that so much as appended to it. A genuinely NEW large
## staged file must still be flagged (the fix must not disable the check).
bigstaged_repo="$(mktemp --directory --tmpdir="${tmp_root}" bigstaged.XXXXXX)"
git -C "${bigstaged_repo}" init --quiet
git -C "${bigstaged_repo}" config user.email 'ci-test@example.com'
git -C "${bigstaged_repo}" config user.name 'ci-test'
## >500 KB: the check-added-large-files default maxkb threshold.
head --bytes=600000 /dev/zero | tr '\0' 'x' > "${bigstaged_repo}/big.txt"
git -C "${bigstaged_repo}" add big.txt
git -C "${bigstaged_repo}" commit --quiet --no-verify --message base
## touch it and stage the change: present at HEAD, modified in the index.
printf '%s\n' 'appended' >> "${bigstaged_repo}/big.txt"
git -C "${bigstaged_repo}" add big.txt
bigstaged_out="$( cd -- "${bigstaged_repo}" && "${GATE}" --staged 2>&1 || true )"
if printf '%s\n' "${bigstaged_out}" | grep --quiet --fixed-strings -- 'FAIL check-added-large-files'; then
   printf '%s\n' 'FAIL: a pre-existing large file was flagged as newly added in staged mode (no upstream)' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: a pre-existing large file is exempt from check-added-large-files in staged mode'
fi

bignew_repo="$(mktemp --directory --tmpdir="${tmp_root}" bignew.XXXXXX)"
git -C "${bignew_repo}" init --quiet
git -C "${bignew_repo}" config user.email 'ci-test@example.com'
git -C "${bignew_repo}" config user.name 'ci-test'
git -C "${bignew_repo}" commit --quiet --no-verify --allow-empty --message base
head --bytes=600000 /dev/zero | tr '\0' 'y' > "${bignew_repo}/bignew.txt"
git -C "${bignew_repo}" add bignew.txt
bignew_out="$( cd -- "${bignew_repo}" && "${GATE}" --staged 2>&1 || true )"
if printf '%s\n' "${bignew_out}" | grep --quiet --fixed-strings -- 'FAIL check-added-large-files'; then
   printf '%s\n' 'PASS: a genuinely new large staged file is still flagged'
else
   printf '%s\n' 'FAIL: the staged-mode base fix disabled check-added-large-files for new large files' >&2
   failures=$((failures + 1))
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
printf '%s\n' 'x = 1' > "${py_repo}/noshebang.py"
printf '%s\n' '#!/usr/bin/python3 -Bsu' 'y = 2' > "${py_repo}/withshebang.py"
true > "${py_repo}/__init__.py"
chmod 0755 -- "${py_repo}/withshebang.py"
git -C "${py_repo}" add --all
git -C "${py_repo}" commit --quiet --no-verify --message py
py_out="$( cd -- "${py_repo}" && "${GATE}" "${py_base}" 2>&1 || true )"
if printf '%s\n' "${py_out}" | grep --quiet --fixed-strings -- 'R-180'; then
   printf '%s\n' 'PASS: R-180 flags a python file with no shebang'
else
   printf '%s\n' 'FAIL: R-180 did not flag a shebang-less python file' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${py_out}" | grep --quiet --fixed-strings -- 'withshebang.py'; then
   printf '%s\n' 'FAIL: R-180 flagged a compliant python file' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-180 spares a shebang+executable python file'
fi
if printf '%s\n' "${py_out}" | grep --quiet --fixed-strings -- '__init__.py'; then
   printf '%s\n' 'FAIL: R-180 flagged an EMPTY package marker' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-180 exempts an empty __init__.py'
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
   printf '%s\n' 'PASS: R-190 flags a long inline interpreter program'
else
   printf '%s\n' 'FAIL: R-190 did not flag a long inline interpreter program' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'shortglue.sh'; then
   printf '%s\n' 'FAIL: R-190 flagged short glue' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 spares a short inline one-liner'
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'plaindoc.sh'; then
   printf '%s\n' 'FAIL: R-190 flagged a non-interpreter heredoc' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 ignores a heredoc feeding a non-interpreter'
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'docexample.sh'; then
   printf '%s\n' 'FAIL: R-190 flagged an interpreter example inside a doc heredoc' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 ignores an interpreter example inside a doc heredoc'
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'masked.sh'; then
   printf '%s\n' 'PASS: R-190 still sees a violation after a commented opener'
else
   printf '%s\n' 'FAIL: a commented opener masked a real inline program' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'spaced.sh'; then
   printf '%s\n' 'PASS: R-190 catches whitespace after the heredoc operator'
else
   printf '%s\n' 'FAIL: R-190 missed "<< DELIM" with whitespace' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${inline_hits}" | grep --quiet --fixed-strings -- 'waived.sh'; then
   printf '%s\n' 'FAIL: R-190 ignored its style-ok waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 honours the allow-inline-interpreter waiver'
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
printf '%s\n' '#!/bin/bash' 'bar=1' > "${shebang_repo}/plain.conf"
printf '%s\n' \
   '#!/bin/bash' \
   '## style-ok: sourced-fragment -- fixture' \
   'foo=1' \
   > "${shebang_repo}/waived.conf"
chmod 0644 -- "${shebang_repo}/plain.conf" "${shebang_repo}/waived.conf"
git -C "${shebang_repo}" add --all
git -C "${shebang_repo}" commit --quiet --no-verify --message shebang
shebang_out="$( cd -- "${shebang_repo}" && "${GATE}" "${shebang_base}" 2>&1 || true )"
## Anchor on the hook's own verdict line, not the filename: the gate's SKIP note
## names the waived file too, so a bare filename match would confirm itself.
if printf '%s\n' "${shebang_out}" \
   | grep --quiet --fixed-strings -- 'plain.conf: has a shebang but is not marked executable'; then
   printf '%s\n' 'PASS: shebang check still fires without the waiver'
else
   printf '%s\n' 'FAIL: shebang check missed an unwaived non-executable shebang file' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${shebang_out}" \
   | grep --quiet --fixed-strings -- 'waived.conf: has a shebang but is not marked executable'; then
   printf '%s\n' 'FAIL: shebang check ignored its sourced-fragment waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: shebang check honours the sourced-fragment waiver'
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
   printf '%s\n' 'FAIL: gate grepped a submodule gitlink as if it were a file' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: gate does not grep a submodule gitlink'
fi
## forbid-new-submodules diffs '--staged' unless the range env vars are set, so
## in push mode it inspected an empty diff and passed unconditionally.
if printf '%s\n' "${gitlink_out}" \
   | grep --quiet --fixed-strings -- 'new submodule introduced'; then
   printf '%s\n' 'PASS: forbid-new-submodules sees the push-mode diff range'
else
   printf '%s\n' 'FAIL: forbid-new-submodules missed a newly added submodule' >&2
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
printf '%s\n' \
   '#!/usr/bin/python3 -Bsu' \
   "x = ${dq}${non_ascii}${dq}" \
   > "${ascii_repo}/plain.py"
printf '%s\n' \
   '#!/usr/bin/python3 -Bsu' \
   '## style-ok: allow-non-ascii -- fixture' \
   "y = ${dq}${non_ascii}${dq}" \
   > "${ascii_repo}/waived.py"
chmod 0755 -- "${ascii_repo}/plain.py" "${ascii_repo}/waived.py"
git -C "${ascii_repo}" add --all
git -C "${ascii_repo}" commit --quiet --no-verify --message ascii
ascii_out="$( cd -- "${ascii_repo}" && "${GATE}" "${ascii_base}" 2>&1 || true )"
if printf '%s\n' "${ascii_out}" | grep --quiet --fixed-strings -- "'plain.py' contains non-ASCII"; then
   printf '%s\n' 'PASS: R-001 still flags non-ASCII without the waiver'
else
   printf '%s\n' 'FAIL: R-001 did not flag non-ASCII -- the waiver is too broad' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${ascii_out}" | grep --quiet --fixed-strings -- "'waived.py' contains non-ASCII"; then
   printf '%s\n' 'FAIL: R-001 waiver did not take effect' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-001 waiver exempts the marked file'
fi

## An UNTRACKED shell file must be named in the output. 'git diff' cannot see
## one, so it contributes no changed file and every check skips it -- while the
## gate still prints "all static checks passed". Read as "my new script passed",
## that is a false green: the gate never opened the file.
untracked_repo="$(mktemp --directory --tmpdir="${tmp_root}" untracked.XXXXXX)"
git -C "${untracked_repo}" init --quiet
git -C "${untracked_repo}" config user.email 'ci-test@example.com'
git -C "${untracked_repo}" config user.name 'ci-test'
git -C "${untracked_repo}" commit --quiet --no-verify --allow-empty --message base
untracked_base="$(git -C "${untracked_repo}" rev-parse HEAD)"
## Never added: that is the whole point of the case.
printf '%s\n' '#!/bin/bash' 'true' > "${untracked_repo}/brand-new-tool"
untracked_out="$( cd -- "${untracked_repo}" && "${GATE}" "${untracked_base}" 2>&1 || true )"
if printf '%s\n' "${untracked_out}" | grep --quiet --fixed-strings 'brand-new-tool'; then
   printf '%s\n' 'PASS: an untracked shell file is named as NOT checked'
else
   printf '%s\n' \
      "FAIL: an untracked shell file was silently unchecked; output: ${untracked_out}" >&2
   failures=$((failures + 1))
fi

## A tracked, committed file must NOT be reported as untracked, or the notice
## would fire on every run and stop meaning anything.
if printf '%s\n' "${untracked_out}" | grep --quiet --fixed-strings 'sample.sh'; then
   printf '%s\n' 'FAIL: a tracked file was reported as untracked' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: the untracked notice does not fire for tracked files'
fi

## R-191: a systemd unit must not embed a multi-statement shell script in an
## 'Exec*=' directive. A multi-statement 'bash -c' (';', '&&', pipe, keyword, or
## a line continuation) is FLAGGED; a single-command wrapper and a plain
## non-shell Exec are SPARED; the file-wide waiver exempts the unit.
unit_repo="$(mktemp --directory --tmpdir="${tmp_root}" unit.XXXXXX)"
git -C "${unit_repo}" init --quiet
git -C "${unit_repo}" config user.email 'ci-test@example.com'
git -C "${unit_repo}" config user.name 'ci-test'
git -C "${unit_repo}" commit --quiet --no-verify --allow-empty --message base
unit_base="$(git -C "${unit_repo}" rev-parse HEAD)"
## '&&' and the ';' come from run-time text (${sc}) so no multi-statement
## 'bash -c' literal lives in THIS tracked file for R-191 to trip on -- and the
## leading quote before 'ExecStart' keeps the membership grep from reading these
## fixture-authoring lines as a unit in the first place.
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -c 'a && b'" \
   > "${unit_repo}/bad-amp.service"
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -c 'a${sc} b'" \
   > "${unit_repo}/bad-semi.service"
## A multi-line Exec (backslash continuation) is itself the multi-statement
## signal even without a separator on any single physical line. The trailing
## '\' is assembled from an octal escape so no literal backslash-before-quote
## lives in THIS tracked file (which shellcheck would flag SC1003).
bslash="$(printf '\134')"
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -c ${bslash}" \
   "   'true'" \
   > "${unit_repo}/bad-continued.service"
## Option clusters ('-lc', '-ec') and a command attached to the flag with no
## space ('-c'a...'') all still invoke a shell with -c and must be flagged. The
## '&&' is a literal here (fine); the leading quote before 'ExecStart' keeps
## R-191's own membership grep from reading these fixture lines as a unit.
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -lc 'a && b'" \
   > "${unit_repo}/bad-lc.service"
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -ec 'a && b'" \
   > "${unit_repo}/bad-ec.service"
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -c'a && b'" \
   > "${unit_repo}/bad-attached.service"
## A standalone '&' background separator is multi-statement too. 'worker &
## runner' carries no control keyword and no ';'/'&&'/pipe, so only the
## '&'-background check -- not the keyword or separator checks -- flags this
## unit. (Both commands are placeholders; a real 'echo' here would trip R-034.)
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -c 'worker & runner'" \
   > "${unit_repo}/bad-bg.service"
## A single-command wrapper and a plain non-shell Exec are glue, not a program.
printf '%s\n' \
   '[Service]' \
   "ExecStartPre=/bin/bash -c 'touch /run/x'" \
   'ExecStart=/usr/bin/foo --bar' \
   > "${unit_repo}/good.service"
## A '>&2' redirection is NOT backgrounding: the '&' is not space-flanked, so
## R-191 must spare this single-command wrapper (guards the '&'-background check
## against firing on '>&'/'2>&1').
printf '%s\n' \
   '[Service]' \
   "ExecStart=/bin/bash -c 'foo >&2'" \
   > "${unit_repo}/good-redir.service"
printf '%s\n' \
   '[Service]' \
   '# style-ok: allow-embedded-script' \
   "ExecStart=/bin/bash -c 'a && b'" \
   > "${unit_repo}/waived.service"
git -C "${unit_repo}" add --all
git -C "${unit_repo}" commit --quiet --no-verify --message unit
unit_out="$( cd -- "${unit_repo}" && "${GATE}" "${unit_base}" 2>&1 || true )"
## Scope to the R-191 FAILURE text: the gate also emits an 'R-191 skipped: ...
## waiver in <file>' note that names the waived file, which a bare rule-id match
## would misread as a violation.
unit_hits="$( printf '%s\n' "${unit_out}" \
   | grep --fixed-strings -- 'R-191 systemd unit embeds' || true )"
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'bad-amp.service'; then
   printf '%s\n' 'PASS: R-191 flags a "&&"-chained embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a "&&"-chained embedded script' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'bad-semi.service'; then
   printf '%s\n' 'PASS: R-191 flags a ";"-separated embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a ";"-separated embedded script' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'bad-continued.service'; then
   printf '%s\n' 'PASS: R-191 flags a line-continued embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a line-continued embedded script' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'bad-lc.service'; then
   printf '%s\n' 'PASS: R-191 flags a "-lc" option-cluster embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a "-lc" option-cluster embedded script' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'bad-ec.service'; then
   printf '%s\n' 'PASS: R-191 flags a "-ec" option-cluster embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a "-ec" option-cluster embedded script' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'bad-attached.service'; then
   printf '%s\n' 'PASS: R-191 flags a command attached to -c with no space'
else
   printf '%s\n' 'FAIL: R-191 did not flag a command attached to -c with no space' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'bad-bg.service'; then
   printf '%s\n' 'PASS: R-191 flags a standalone "&" background separator'
else
   printf '%s\n' 'FAIL: R-191 did not flag a standalone "&" background separator' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'good-redir.service'; then
   printf '%s\n' 'FAIL: R-191 flagged a ">&2" redirection as backgrounding' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-191 spares a ">&2" redirection (not a "&" background)'
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'good.service'; then
   printf '%s\n' 'FAIL: R-191 flagged a single-command wrapper / plain Exec' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-191 spares a single-command wrapper and a plain Exec'
fi
if printf '%s\n' "${unit_hits}" | grep --quiet --fixed-strings -- 'waived.service'; then
   printf '%s\n' 'FAIL: R-191 ignored its allow-embedded-script waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-191 honours the allow-embedded-script waiver'
fi

## R-100: a workflow 'run: |' block over 5 shell lines is FLAGGED; a single-line
## 'run: ./ci/x.sh' and a short block are SPARED; the file-wide waiver exempts
## the workflow. The fixtures live under '.github/workflows/' because R-100
## scopes to that path.
wf_repo="$(mktemp --directory --tmpdir="${tmp_root}" workflow.XXXXXX)"
git -C "${wf_repo}" init --quiet
git -C "${wf_repo}" config user.email 'ci-test@example.com'
git -C "${wf_repo}" config user.name 'ci-test'
git -C "${wf_repo}" commit --quiet --no-verify --allow-empty --message base
wf_base="$(git -C "${wf_repo}" rev-parse HEAD)"
mkdir -p -- "${wf_repo}/.github/workflows"
printf '%s\n' \
   'jobs:' \
   '  build:' \
   '    steps:' \
   '      - run: |' \
   '          step_one' \
   '          step_two' \
   '          step_three' \
   '          step_four' \
   '          step_five' \
   '          step_six' \
   > "${wf_repo}/.github/workflows/bad.yml"
## A quoted mapping key ('"run": |') is parsed identically by GitHub to the
## unquoted spelling and must be flagged the same when its block is long.
printf '%s\n' \
   'jobs:' \
   '  build:' \
   '    steps:' \
   '      - "run": |' \
   '          step_one' \
   '          step_two' \
   '          step_three' \
   '          step_four' \
   '          step_five' \
   '          step_six' \
   > "${wf_repo}/.github/workflows/quoted-run.yml"
## 'run : |' (whitespace before the colon) -- YAML parses the key as 'run', so
## GitHub runs it as an inline shell; a long block must be flagged the same.
printf '%s\n' \
   'jobs:' \
   '  build:' \
   '    steps:' \
   '      - run : |' \
   '          step_one' \
   '          step_two' \
   '          step_three' \
   '          step_four' \
   '          step_five' \
   '          step_six' \
   > "${wf_repo}/.github/workflows/spaced-run.yml"
printf '%s\n' \
   'jobs:' \
   '  build:' \
   '    steps:' \
   '      - run: ./ci/x.sh' \
   '      - run: |' \
   '          step_one' \
   '          step_two' \
   '          step_three' \
   > "${wf_repo}/.github/workflows/good.yml"
printf '%s\n' \
   '# style-ok: allow-inline-shell' \
   'jobs:' \
   '  build:' \
   '    steps:' \
   '      - run: |' \
   '          step_one' \
   '          step_two' \
   '          step_three' \
   '          step_four' \
   '          step_five' \
   '          step_six' \
   > "${wf_repo}/.github/workflows/waived.yml"
git -C "${wf_repo}" add --all
git -C "${wf_repo}" commit --quiet --no-verify --message workflow
wf_out="$( cd -- "${wf_repo}" && "${GATE}" "${wf_base}" 2>&1 || true )"
## Scope to the R-100 FAILURE text, past the 'R-100 skipped: ... waiver' note.
wf_hits="$( printf '%s\n' "${wf_out}" \
   | grep --fixed-strings -- 'R-100 workflow embeds' || true )"
if printf '%s\n' "${wf_hits}" | grep --quiet --fixed-strings -- 'bad.yml'; then
   printf '%s\n' 'PASS: R-100 flags a long inline run block'
else
   printf '%s\n' 'FAIL: R-100 did not flag a long inline run block' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${wf_hits}" | grep --quiet --fixed-strings -- 'quoted-run.yml'; then
   printf '%s\n' 'PASS: R-100 flags a long inline block behind a quoted "run:" key'
else
   printf '%s\n' 'FAIL: R-100 did not flag a quoted "run:" inline block' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${wf_hits}" | grep --quiet --fixed-strings -- 'spaced-run.yml'; then
   printf '%s\n' 'PASS: R-100 flags a long inline block behind a whitespace-before-colon run key'
else
   printf '%s\n' 'FAIL: R-100 did not flag a "run :" (space before colon) inline block' >&2
   failures=$((failures + 1))
fi
if printf '%s\n' "${wf_hits}" | grep --quiet --fixed-strings -- 'good.yml'; then
   printf '%s\n' 'FAIL: R-100 flagged a single-line run and a short block' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-100 spares a single-line run and a short block'
fi
if printf '%s\n' "${wf_hits}" | grep --quiet --fixed-strings -- 'waived.yml'; then
   printf '%s\n' 'FAIL: R-100 ignored its allow-inline-shell waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-100 honours the allow-inline-shell waiver'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "test_pre_push_static_style_rules: ${failures} assertion(s) FAILED." >&2
   exit 1
fi
printf '%s\n' "test_pre_push_static_style_rules: OK -- R-070, R-074, R-026, R-030 format string, R-030/R-031, R-034, R-011, R-051, R-090, R-102, R-103, R-120, R-170, R-180, R-190, R-191, R-100, R-010, trailing-whitespace, CRLF-shebang, untracked-shell-file reporting, double-quote-string-fixer-disabled and imported-package-module exemption enforced as expected."
