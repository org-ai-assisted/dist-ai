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
export LC_ALL=C

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
GATE="${PRE_PUSH_STATIC_BIN:-${gate_test_dir}/../../bin/dist-ai-style}"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
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
      "${GATE}" --check --range "${base}"
   ) 2>&1 || true
}

## py_gate_output <line>...  -- write the lines to sample.py, gate --check the
## commit, echo the output. For the Python waiver tests (tokenize-aware comments).
py_gate_output() {
   local repo base
   repo="$(mktemp --directory --tmpdir="${tmp_root}" py.XXXXXX)"
   git -C "${repo}" init --quiet
   git -C "${repo}" config user.email 'ci-test@example.com'
   git -C "${repo}" config user.name 'ci-test'
   git -C "${repo}" commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   printf '%s\n' "$@" > "${repo}/sample.py"
   git -C "${repo}" add sample.py
   git -C "${repo}" commit --quiet --no-verify --message sample
   (
      cd -- "${repo}" || exit 1
      "${GATE}" --check --range "${base}"
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
   ## Liveness guard: require the gate's TERMINAL verdict line. An early exit
   ## (a crash before the rule, an env error) prints no verdict, so an 'absent'
   ## assertion could otherwise pass spuriously on a real regression.
   if ! grep --quiet --extended-regexp \
      'all static checks passed|[0-9]+ check\(s\) failed' <<< "${out}"; then
      printf '%s\n' \
         "FAIL: gate produced no final verdict for body '${body}'" >&2
      failures=$((failures + 1))
      return 0
   fi
   if grep --quiet --fixed-strings -- "${tag}" <<< "${out}"; then
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

## R-070: a case ';;' at END-OF-LINE glued to the arm's last command is FLAGGED;
## ';;' on its own line is SPARED, and so is the FULLY-INLINE arm form (real code
## -- 'esac' or the next pattern -- AFTER the ';;' on the same physical line),
## which the style guide exempts. '${dsemi}' assembles ';;' so no literal lives
## in this tracked file; '${nlreal}' is a real newline for the multi-line forms.
## EOL-glued (multi-line arm, ';;' ends the line):
expect_rule "R-070" "case x in${nlreal}a) true${dsemi}${nlreal}esac"           "present"
## ';;' on its OWN line -- spared:
expect_rule "R-070" "case x in${nlreal}a) true${nlreal}${dsemi}${nlreal}esac"  "absent"
## FULLY-INLINE arm ('esac' after ';;' on the same line) -- exempt, spared:
expect_rule "R-070" "case x in a) true${dsemi} esac"                           "absent"
## Regression (dev339): the compact match-or-default guard the style guide shows
## must NOT be flagged -- 'esac' closes the case on the same line.
expect_rule "R-070" "case ${dq}\${p}${dq} in '' | *[!0-9]* | 0* ) p=15 ${dsemi} esac" "absent"

## Universal per-rule id override: '## style-ok: <R-id>' suppresses THAT rule for
## the file, wired once in Rule.applies() so it reaches even a rule (R-070 here)
## that carries no dedicated waiver_tag.
expect_rule "R-070" "## style-ok: R-070${nlreal}case x in${nlreal}a) true${dsemi}${nlreal}esac" "absent"
## Specificity: a DIFFERENT rule's id must not suppress R-070 (no cross-leakage).
expect_rule "R-070" "## style-ok: R-034${nlreal}case x in${nlreal}a) true${dsemi}${nlreal}esac" "present"
## Boundary: a longer id that merely PREFIX-contains R-070 must not suppress it.
expect_rule "R-070" "## style-ok: R-0700${nlreal}case x in${nlreal}a) true${dsemi}${nlreal}esac" "present"

## AST-aware waivers: a '## style-ok:' line inside a HEREDOC body is DATA, not a
## real comment, so it must NOT waive -- otherwise a fixture heredoc silently
## disables the gate for the whole file (a false-green). Both the per-rule id
## override and the named waiver_tag path honor this.
expect_rule "R-070" "cat <<'EOF'${nlreal}## style-ok: R-070${nlreal}EOF${nlreal}case x in${nlreal}a) true${dsemi}${nlreal}esac" "present"
expect_rule "R-034" "cat <<'EOF'${nlreal}## style-ok: allow-echo${nlreal}EOF${nlreal}echo hi" "present"
## The REAL comment forms still waive (AST change must not break genuine waivers).
expect_rule "R-034" "## style-ok: allow-echo${nlreal}echo hi" "absent"
## A TRAILING inline comment is not a line-leading waiver: the grammar wants the
## waiver on its OWN line, so 'cmd ## style-ok: X' must NOT suppress -- both the
## named-tag path and the id-override path.
expect_rule "R-034" "echo hi ## style-ok: allow-echo" "present"
expect_rule "R-034" "echo hi ## style-ok: R-034"       "present"

## Python is tokenize-aware too: a '## style-ok:' line inside a triple-quoted
## STRING is data, not a comment, so it must not waive; a genuine '#' comment
## still does. A non-ASCII byte (built at runtime so THIS file stays ASCII) trips
## R-001, the rule the spoofed waiver tries to silence.
emdash="$(printf '\342\200\224')"
py_spoof_out="$(py_gate_output '#!/usr/bin/python3' 'x = """' '## style-ok: allow-non-ascii' '"""' "y = \"${emdash}\"")"
if grep --quiet --fixed-strings -- 'R-001' <<< "${py_spoof_out}"; then
   printf '%s\n' "PASS: R-001 not waived by a '## style-ok:' inside a Python string"
else
   printf '%s\n' "FAIL: R-001 wrongly waived by a '## style-ok:' inside a Python string" >&2
   failures=$((failures + 1))
fi
py_real_out="$(py_gate_output '#!/usr/bin/python3' '## style-ok: allow-non-ascii' "y = \"${emdash}\"")"
## Liveness guard: an absence assertion must first confirm the gate RAN to its
## verdict -- a crash leaves R-001 absent too, which would falsely PASS.
if ! grep --quiet --extended-regexp \
      'all static checks passed|[0-9]+ check\(s\) failed' <<< "${py_real_out}"; then
   printf '%s\n' "FAIL: gate produced no verdict for the Python real-comment fixture" >&2
   failures=$((failures + 1))
elif grep --quiet --fixed-strings -- 'R-001' <<< "${py_real_out}"; then
   printf '%s\n' "FAIL: R-001 not waived by a genuine Python '#' comment" >&2
   failures=$((failures + 1))
else
   printf '%s\n' "PASS: R-001 waived by a genuine Python '#' comment"
fi

## R-030/R-031: a newline emitted without an explicit '' data argument must be
## FLAGGED -- both 'printf \n' (newline in the format) and a bare 'printf %s\n'
## (data arg omitted). The compliant 'printf %s\n' "" and a normal data printf
## must be SPARED -- 'printf %s\n' "" is the correct newline spelling and is a
## legitimate blank-line output, not a violation.
expect_rule "R-030/R-031" "printf ${sq}${nl}${sq}"              "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq}"            "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} ${dq}${dq}" "absent"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} hello"      "absent"
## '--' is an OPTION, not a data argument -- 'printf -- \n' still needs the explicit
## "" (the old 'len(args) != 2' counted '--' as the data arg and spared it). A
## '-v NAME' target writes to a variable (emits nothing) and is spared.
expect_rule "R-030/R-031" "printf -- ${sq}${nl}${sq}"          "present"
expect_rule "R-030/R-031" "printf -v v ${sq}${nl}${sq}"        "absent"
## A trailing comment does not supply a data argument, so a commented bare
## form is still a violation; the compliant form stays spared even commented.
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} # blank"        "present"
expect_rule "R-030/R-031" "printf ${sq}%s${nl}${sq} ${dq}${dq} # ok" "absent"
## The 'printf-format' waiver now covers R-031 too (the bare newline form), not
## only R-030's format-injection form -- a printf missing its explicit '' arg is
## SPARED when the file carries the waiver.
expect_rule "R-030/R-031" "## style-ok: printf-format${nlreal}printf ${sq}%s${nl}${sq}" "absent"
## The finding is DISPLAYED as the composite 'R-030/R-031'; that exact tag must
## work as a per-rule override (override_ids), so a user copying it from the
## finding does not hit a silent no-op.
expect_rule "R-030/R-031" "## style-ok: R-030/R-031${nlreal}printf ${sq}${nl}${sq}" "absent"

## R-030: a printf inside a single-quoted program handed to ANOTHER interpreter
## (awk here, whose printf takes a comma-separated list and interpolates nothing
## from the shell) is NOT a shell printf. The AST sees it as text inside a
## single-quoted Word argument to 'awk', never a command, so it is not extracted
## -- the cross-line quote walker the former gate needed is gone.
awk_program="awk -v a=\"\${x}\" \\${nl}   ${sq}BEGIN {${nl}      if (a <= 0) { printf \"0.00\"; exit }${nl}      printf \"%.2f\", a / 2;${nl}    }${sq}"
expect_rule "R-030 printf format" "${awk_program}" "absent"
## CANARY: a REAL shell printf on the line AFTER the awk program must still fire
## -- the awk program's inner printfs are data, but the next line is a live call.
expect_rule "R-030 printf format" "${awk_program}${nlreal}printf \"bad \${x}\\n\"" "present"

## R-030 flags a format ONLY when it CAN interpolate data -- a DOUBLE-quoted or
## UNQUOTED format containing a '$' or backtick reads '$var' / command
## substitution straight INTO the format. A SINGLE-quoted format, OR any format
## with no expansion metachar (a fixed literal '%d'/'%02x'/'%(%Y)T'), interpolates
## nothing and is SPARED whatever verbs it spells -- the data goes in the data
## argument. printf's own options ('-v NAME', '--') are skipped so the FORMAT is
## judged, not the option.
r030fmt="R-030 printf format string"
bt='`'
## Single-quoted verbs -- literal, SPARED (a redirect makes no difference):
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${1}${dq}"                 "absent"
expect_rule "${r030fmt}" "printf ${sq}%8d${sq} ${dq}\${1}${dq}"                "absent"
expect_rule "${r030fmt}" "printf ${sq}%-12s${sq} ${dq}\${a}${dq}"              "absent"
expect_rule "${r030fmt}" "printf ${sq}%d${sq} ${dq}\${1}${dq} >/dev/null 2>&1 || exit 1" "absent"
## No-expansion literal, DOUBLE-quoted or UNQUOTED -- cannot interpolate, SPARED
## (these fixed-verb false positives are exactly what this rule used to raise):
expect_rule "${r030fmt}" "printf %d ${dq}\${1}${dq}"                           "absent"
expect_rule "${r030fmt}" "printf ${dq}%02x${dq} ${dq}\${n}${dq}"               "absent"
expect_rule "${r030fmt}" "printf -v hex ${dq}%02x${dq} ${dq}\${n}${dq}"        "absent"
expect_rule "${r030fmt}" "printf -v pad ${dq}%05d${dq} ${dq}\${n}${dq}"        "absent"
expect_rule "${r030fmt}" "printf ${dq}%(%Y)T${dq} -1"                          "absent"
## A '$' or backtick in a double/unquoted format DOES interpolate -- FLAGGED:
expect_rule "${r030fmt}" "printf ${dq}%d \${x}${dq} ${dq}\${1}${dq}"           "present"
expect_rule "${r030fmt}" "printf ${dq}%02x \${y}${dq} ${dq}\${n}${dq}"         "present"
expect_rule "${r030fmt}" "printf ${dq}v ${bt}id${bt}${dq}"                     "present"
## CANARY: a CONCATENATED single-quoted format 'x'$name'y' interpolates $name INTO
## the format (a real %n injection). Its outer chars are both "'", but a bash
## single-quoted string cannot CONTAIN a "'", so this is 'x' . $name . 'y' -- NOT a
## literal -- and must be FLAGGED. FAILS pre-fix (the outer-quote heuristic stamped
## the whole word single_quoted and spared it).
expect_rule "${r030fmt}" "printf ${sq}x${sq}\$name${sq}y${sq} 1 2"             "present"
## CANARY: 'x''$name' is TWO ADJACENT single-quoted segments ('x' . '$name'), so
## $name stays LITERAL (single quotes suppress it) -- SPARED. A naive "inner has a
## quote" heuristic would wrongly flag it; the quote-SEGMENT scan does not.
expect_rule "${r030fmt}" "printf ${sq}x${sq}${sq}\$name${sq} 1 2"             "absent"
## a PURE single-quoted '\$name' is a LITERAL dollar (no interpolation) -- SPARED.
expect_rule "${r030fmt}" "printf ${sq}\$name${sq}"                            "absent"
## 'printf -v NAME' with NO format string has nothing to judge -- SPARED.
expect_rule "${r030fmt}" "printf -v onlyname"                                 "absent"
## '-v NAME' / '--' options skipped, so the FORMAT is what is judged:
expect_rule "${r030fmt}" "printf -v out ${sq}%s${sq} ${dq}\${1}${dq}"          "absent"
expect_rule "${r030fmt}" "printf -v out ${dq}bad \${x}${dq} ${dq}\${1}${dq}"   "present"
expect_rule "${r030fmt}" "printf -- ${dq}bad \${x}${dq}"                       "present"
## a NON-bare '-v' spelling (attached '-vNAME', quoted '"-v"') is STILL the option,
## so the real FORMAT after it is judged -- else a $(...) format smuggles past R-030.
## FAILS pre-fix: the exact word=="-v" match read the spelled -v AS the format.
expect_rule "${r030fmt}" "printf -vfoo ${dq}\$(id)${dq}"                       "present"
expect_rule "${r030fmt}" "printf ${dq}-v${dq} foo ${dq}\$(id)${dq}"            "present"
## An allowlisted verb is safe in any quoting.
expect_rule "${r030fmt}" "printf ${sq}%s${nl}${sq} ${dq}\${1}${dq}"            "absent"

## A printf spelled INSIDE another printf's double-quoted DATA argument is a
## payload string, not a command -- e.g. a canary feeding a deliberately malformed
## 'printf %s\n a b c' to a checker. The outer printf is compliant; the nested one
## must NOT be extracted and flagged. The format loop tracks quote depth so only a
## depth-zero printf is judged. FAILS on the pre-fix gate, which flagged the nested
## format.
expect_rule "${r030fmt}" "printf ${sq}%s${nl}${sq} ${dq}note printf ${sq}bad %s here${sq} a b c${dq}" "absent"
## CANARY: quote depth resets per line, so a REAL violation on the NEXT line still
## fires -- a nested-printf line must not fail the rule OPEN for what follows.
expect_rule "${r030fmt}" "printf ${sq}%s${nl}${sq} ${dq}has printf ${sq}x %s${sq}${dq}${nlreal}printf ${dq}real \${bad}${dq}" "present"
## A printf spelled in a trailing '#' comment is documentation, not a call: spared.
expect_rule "${r030fmt}" "printf ${sq}%s${nl}${sq} ${dq}\${v}${dq} ${hash} printf ${sq}%d${sq} ${dq}\${x}${dq}" "absent"
## CANARY: an unquoted backslash escapes ONE character (a literal quote), it does not
## open a string -- so a real violation after '\"' must still be flagged. FAILS on a
## walker that treats '\"' as a string opener (fail-OPEN).
expect_rule "${r030fmt}" "echo \\${dq} ${sc} printf ${dq}bad \${x}${nl}${dq}" "present"
## A '#' inside a substring-removal expansion '${v#/p}' is not a comment, so a real printf
## violation later on the same line is still flagged (not masked by a false comment-truncation).
expect_rule "${r030fmt}" "x=${dollar}{v${hash}/p} ${sc} printf ${dq}bad \${z}${dq}" "present"

## A '#' INSIDE the format is not a comment: a DOUBLE-quoted format with a '#'
## banner still interpolates and is FLAGGED (the AST parses the whole quoted
## word, indent and all -- no comment-glob to mislead it).
hash='#'
indent='   '
banner="${hash}${hash}${hash}"
expect_rule "${r030fmt}" "${indent}printf ${dq}${nl}${banner} \${x} ${banner}${nl}${dq} ${dq}\${1}${dq}" "present"
## A double-quoted violation with a '#' only in a TRAILING comment is still flagged;
## the comment is not part of the format.
expect_rule "${r030fmt}" "${indent}printf ${dq}%d \${x}${dq} ${dq}\${1}${dq} ${hash} count" "present"
## A real comment -- '#' is the first non-blank character -- is prose, not a
## printf CALL, so it is SPARED, indented too (the AST never parses it as a
## command).
expect_rule "${r030fmt}" "${indent}${hash} printf ${dq}%d \${x}${dq} ${dq}\${1}${dq}"    "absent"
expect_rule "${r030fmt}" "${hash} printf ${dq}%d \${x}${dq} ${dq}\${1}${dq}"             "absent"

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
expect_rule "R-034" "if echo hi${sc} then true${sc} fi"         "present"
expect_rule "R-034" "printf ${sq}%s${nl}${sq} ${dq}a echo b${dq}" "absent"
expect_rule "R-034" "has echo"                                  "absent"
## The per-rule id override coexists with a rule's own named waiver: '## style-ok:
## R-034' suppresses echo just as 'allow-echo' does.
expect_rule "R-034" "## style-ok: R-034${nlreal}echo hi"        "absent"

## R-070: a ';;' at END-OF-LINE glued to the arm command, jammed ('true;;') or
## spaced ('true ;;'), is FLAGGED (here the spaced form, ';;' ending the line).
expect_rule "R-070" "case x in${nlreal}a) true${sp}${dsemi}${nlreal}esac"  "present"

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
expect_rule "R-130" "if ! ${colon} > ${dq}\${report}${dq}${sc} then true${sc} fi" "present"
expect_rule "R-130" "${colon} ${dq}\${var:=default}${dq}"        "absent"
expect_rule "R-130" "value=${dq}\${var:-fallback}${dq}"          "absent"
expect_rule "R-130" "PATH=${dq}/a::/b${dq}"                      "absent"
expect_rule "R-130" "url=${dq}https://example.com${dq}"          "absent"
expect_rule "R-130" "## ${colon} > file in a comment"            "absent"

## R-070/R-074 vs '${#var}': the '#' inside a length expansion is CODE, not a
## comment start, so the AST parses it as a parameter expansion and the
## violation after it is still flagged; a REAL '#' comment still spares.
expect_rule "R-070" "case x in${nlreal}0) out=${dq}\${set:0:\${#set}}${dq} ${dsemi}${nlreal}esac" "present"
expect_rule "R-070" "case x in${nlreal}1) out=${dq}\${plain}${dq} ${dsemi}${nlreal}esac"          "present"
expect_rule "R-070" "argc=\${#args[@]}${sp}${sp}## a note about ;;"               "absent"
expect_rule "R-074" "[ ${dq}\${#a[@]}${dq} -eq 0 ]${sc} continue"                "present"

## R-021 / R-022 (local declaration position; local combined with command
## substitution) are GUIDANCE only -- not mechanically gate-enforced (the
## engine implements no such rule; the bash-style-guide tags them
## 'auto-detected: no'). No gate assertion here; a future AST rule would add one.

## R-026: the obsolete pre-4.4 empty-array guard '${arr[@]+"${arr[@]}"}' (a
## nounset workaround unneeded since bash 4.4) must be FLAGGED. The legitimate
## length '${#arr[@]}', a plain '${arr[@]}', and the conditional-substitution
## forms '${arr[@]:-fallback}' / '${arr[@]:+word}' must all be SPARED -- none
## is the '+alternate-directly-on-[@]' guard. Bodies are assembled from
## ${atall}/${altop} so the flagged literal never lives in this tracked file.
guard="\${arr${atall}${altop}\"\${arr${atall}}\"}"
expect_rule "R-026" "x=${guard}"                       "present"
## A COMPLETE loop so the AST parses (the engine rule needs a valid tree; the
## '${arr[@]+' guard is flagged wherever the parameter expansion sits).
expect_rule "R-026" "for x in ${guard}${sc} do :${sc} done" "present"
expect_rule "R-026" "n=\${#arr${atall}}"               "absent"
expect_rule "R-026" "p=\"\${arr${atall}}\""            "absent"
expect_rule "R-026" "f=\${arr${atall}:-fallback}"      "absent"
expect_rule "R-026" "c=\${arr${atall}:${altop}word}"   "absent"

## R-090: 'command -v' in code is FLAGGED; in a comment it is SPARED.
expect_rule "R-090" "if ! command${sp}-v foo${sc} then true${sc} fi" "present"
expect_rule "R-090" "## uses command${sp}-v not has"             "absent"
## ... and it does NOT fire in a POSIX '/bin/sh' script, where 'type -P' is
## undefined (SC3045) and sourcing has.sh is not an option: 'command -v' is the
## only portable spelling, so flagging it would demand code shellcheck rejects.
expect_rule "R-090" "if ! command${sp}-v foo${sc} then true${sc} fi" "absent"  '#!/bin/sh'

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
## A '-n' (syntax-check, noexec) cluster never RUNS the script -> SPARED; a '-x'
## (execution + trace) cluster still runs it -> FLAGGED. Guards the noexec spare.
expect_rule "R-102" "bash${sp}-n${sp}foo.bash"                   "absent"
expect_rule "R-102" "bash${sp}-x${sp}foo.bash"                   "present"
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

## R-172: a 'mkdir' creating a temp dir must set the mode ATOMICALLY with
## '--mode='. The command word and the '$TMPDIR' operand are assembled at run
## time so neither the literal 'mkdir ... $TMPDIR' nor a bare '$TMP' ever
## appears in THIS tracked file (which the gate greps and would, correctly,
## flag as an R-172 violation).
mkd='mkdir'
tv="${dollar}TMPDIR"
tvbrace="${dollar}{TMP}"
tvalias="${dollar}TMP"
## The missing-mode form -- the exact regression: perms dropped, or split into
## a following 'chmod' (a TOCTOU window). Both FLAG the mkdir line.
expect_rule "R-172" "${mkd}${sp}--parents${sp}--${sp}${dq}${tv}${dq}"                                  "present"
expect_rule "R-172" "${mkd}${sp}--parents${sp}--${sp}${dq}${tv}${dq}${nlreal}chmod${sp}700${sp}--${sp}${dq}${tv}${dq}" "present"
## The '$TMP' alias operand (e.g. 'TMP=\"\$TMPDIR\"; mkdir ... \"\$TMP\"').
expect_rule "R-172" "${mkd}${sp}--parents${sp}--${sp}${dq}${tvalias}${dq}"                             "present"
## The short '-m' is atomic but must be the long '--mode=' -- standalone,
## attached, and bundled ('-pm700') spellings all FLAG.
expect_rule "R-172" "${mkd}${sp}-m${sp}700${sp}--${sp}${dq}${tv}${dq}"                                 "present"
expect_rule "R-172" "${mkd}${sp}-m700${sp}--${sp}${dq}${tv}${dq}"                                      "present"
expect_rule "R-172" "${mkd}${sp}-pm700${sp}--${sp}${dq}${tv}${dq}"                                     "present"
## The compliant atomic long form is SPARED -- both '--mode=700' and
## '--mode 700', and the '${TMP}' brace operand.
expect_rule "R-172" "${mkd}${sp}--parents${sp}--mode=700${sp}--${sp}${dq}${tv}${dq}"                   "absent"
expect_rule "R-172" "${mkd}${sp}--mode${sp}700${sp}--${sp}${dq}${tv}${dq}"                             "absent"
expect_rule "R-172" "${mkd}${sp}--mode=700${sp}--${sp}${dq}${tvbrace}${dq}"                            "absent"
## A mkdir NOT creating a temp dir is none of R-172's business, and a name that
## merely STARTS with a temp prefix ('$TMPFILE') is not the temp DIR family.
expect_rule "R-172" "${mkd}${sp}--parents${sp}--${sp}${dq}${dollar}dir${dq}"                           "absent"
expect_rule "R-172" "${mkd}${sp}--parents${sp}--${sp}${dq}${dollar}TMPFILE${dq}"                       "absent"
## A script-wide waiver disables the rule for the whole file.
expect_rule "R-172" "## style-ok: allow-mkdir-no-mode${nlreal}${mkd}${sp}--parents${sp}--${sp}${dq}${tv}${dq}" "absent"
## The mode is judged on the mkdir COMMAND, not the whole line: a '--mode' in a
## trailing comment or a SECOND command on the line must NOT mask a mode the
## mkdir itself lacks (the whole-line-grep bypass).
expect_rule "R-172" "${mkd}${sp}--${sp}${dq}${tv}${dq}${sc}${sp}foo${sp}--mode=700"                  "present"
expect_rule "R-172" "${mkd}${sp}--parents${sp}--${sp}${dq}${tv}${dq}${sp}${sp}${hash}${sp}--mode=700" "present"
expect_rule "R-172" "foo${sp}--mode=700${sc}${sp}${mkd}${sp}--parents${sp}--${sp}${dq}${tv}${dq}"     "present"
## ... but a COMPLIANT mkdir followed by another command on the line is SPARED:
## the '&& cd' must not read as ambiguous and false-positive.
expect_rule "R-172" "${mkd}${sp}--parents${sp}--mode=700${sp}--${sp}${dq}${tv}${dq}${sp}&&${sp}cd${sp}--${sp}${dq}${tv}${dq}" "absent"
## A backtick command substitution is COMMAND position -> a temp mkdir there is
## still checked. And a name that merely STARTS with a temp prefix followed by a
## word char ('$TMPDIR_SUFFIX') is a DIFFERENT variable, not the temp dir.
btick='`'
expect_rule "R-172" "foo=${btick}${mkd}${sp}--parents${sp}--${sp}${dq}${tv}${dq}${btick}"    "present"
expect_rule "R-172" "${mkd}${sp}--parents${sp}--${sp}${dq}${dollar}TMPDIR_SUFFIX${dq}"        "absent"

## R-010: seven COPIES of one directive must NOT satisfy the block (DISTINCT
## directives are counted); the seven distinct directives pass.
sevensame=$'set -o errexit\nset -o errexit\nset -o errexit\nset -o errexit\nset -o errexit\nset -o errexit\nset -o errexit'
sevendistinct=$'set -o errexit\nset -o nounset\nset -o pipefail\nset -o errtrace\nshopt -s inherit_errexit\nshopt -s shift_verbose\nexport LC_ALL=C'
expect_rule "R-010" "${sevensame}"                               "present"
expect_rule "R-010" "${sevendistinct}"                           "absent"
## The six set/shopt lines WITHOUT 'export LC_ALL=C' are 6/7 -- flagged. This
## is the LC_ALL regression: the old gate (six required) passed this body, the
## new gate (seven required) must flag it.
sixmissing_lcall=$'set -o errexit\nset -o nounset\nset -o pipefail\nset -o errtrace\nshopt -s inherit_errexit\nshopt -s shift_verbose'
expect_rule "R-010" "${sixmissing_lcall}"                        "present"
## 'export LC_ALL=C' is whole-line exact: a 'C.UTF-8' global does NOT satisfy
## the requirement (a multibyte need is a per-command override, not the block
## default), so six lines + 'export LC_ALL=C.UTF-8' is still 6/7 -- flagged.
sixplus_utf8=$'set -o errexit\nset -o nounset\nset -o pipefail\nset -o errtrace\nshopt -s inherit_errexit\nshopt -s shift_verbose\nexport LC_ALL=C.UTF-8'
expect_rule "R-010" "${sixplus_utf8}"                            "present"

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
## from the all-7 top-level rule -- but forgetting the shopt lines (or the
## guarded 'export LC_ALL=C') is the exact gap this catches. Fail tag
## 'R-010 shopt block' is distinct from 'R-010 strict-mode block', so it
## does not collide with the guard tests.
shopt_fail='R-010 shopt block'
guarded_no_shopt=$'if was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o nounset\n   set -o pipefail\n   set -o errtrace\nfi'
guarded_only_inherit=$'if was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o nounset\n   shopt -s inherit_errexit\nfi'
## Both shopt lines present but 'export LC_ALL=C' still missing: the guarded
## LC_ALL regression -- the old gate spared this, the new gate must flag it.
guarded_no_lcall=$'if was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o nounset\n   set -o pipefail\n   set -o errtrace\n   shopt -s inherit_errexit\n   shopt -s shift_verbose\nfi'
guarded_full_shopt=$'if was_executed "${BASH_SOURCE[0]}"; then\n   set -o errexit\n   set -o nounset\n   set -o pipefail\n   set -o errtrace\n   shopt -s inherit_errexit\n   shopt -s shift_verbose\n   export LC_ALL=C\nfi'
## errexit enabled, both shopt lines missing => FLAGGED.
expect_rule "${shopt_fail}" "${guarded_no_shopt}"               "present"
## errexit enabled, only shift_verbose missing (the make-helper-one.bsh
## case: inherit_errexit present) => still FLAGGED.
expect_rule "${shopt_fail}" "${guarded_only_inherit}"           "present"
## errexit enabled, shopt half present but guarded 'export LC_ALL=C' missing
## => FLAGGED.
expect_rule "${shopt_fail}" "${guarded_no_lcall}"              "present"
## errexit enabled, both shopt lines AND guarded 'export LC_ALL=C' present
## => SPARED.
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

## R-081: 'shellcheck source=/dev/null' silences SC1091 without following the
## real file -- FLAGGED (and, being absolute, R-080 flags it too). A relative
## source= is not this rule.
expect_rule "R-081" "# shellcheck source=/dev/null"              "present"
expect_rule "R-081" "# shellcheck source=./helper.sh"            "absent"

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
crlf_out="$( cd -- "${crlf_repo}" && "${GATE}" --check --range "${crlf_base}" 2>&1 || true )"
if grep --quiet --fixed-strings -- "R-120" <<< "${crlf_out}"; then
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
dq_out="$( cd -- "${dq_repo}" && "${GATE}" --check --range "${dq_base}" 2>&1 || true )"
if grep --quiet --fixed-strings -- 'double-quote-string-fixer' <<< "${dq_out}"; then
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
   out="$( cd -- "${repo}" && "${GATE}" --check --range "${base}" 2>&1 || true )"
   printf '%s' "${out}"
}

if grep --quiet --fixed-strings -- 'is an imported package module' <<< "$(module_probe 'usr/lib/python3/dist-packages/probe/mod.py')"; then
   printf '%s\n' 'PASS: an imported package module is exempt from the shebang/+x rules'
else
   printf '%s\n' 'FAIL: an imported package module was held to the shebang/+x rules' >&2
   failures=$((failures + 1))
fi

if grep --quiet --fixed-strings -- 'check-shebang-scripts-are-executable' <<< "$(module_probe 'usr/bin/probe-tool.py')"; then
   printf '%s\n' 'PASS: an ordinary script with a shebang still needs +x'
else
   printf '%s\n' 'FAIL: the shebang/+x rule stopped firing for ordinary scripts' >&2
   failures=$((failures + 1))
fi

## A directory merely NAMED dist-packages is not a Python library path. An
## unanchored exemption would let any script opt out of the rule by sitting in
## one.
if grep --quiet --fixed-strings -- 'check-shebang-scripts-are-executable' <<< "$(module_probe 'usr/bin/dist-packages/probe-tool.py')"; then
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
addel_out="$( cd -- "${addel_repo}" && "${GATE}" --check --range "${addel_base}" 2>&1 || true )"
## Assert the real success predicate -- the gate ran to its clean verdict -- not
## merely the absence of one exception name: a DIFFERENT crash (any other
## exception, or no verdict at all) would slip past a FileNotFoundError-only
## grep but is caught here.
if grep --quiet --fixed-strings -- 'all static checks passed' <<< "${addel_out}"; then
   printf '%s\n' 'PASS: uncommitted deletion runs the large-files hook to a clean verdict'
else
   printf '%s\n' \
      "FAIL: uncommitted deletion did not reach a clean gate verdict; output: ${addel_out}" >&2
   failures=$((failures + 1))
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
bigstaged_out="$( cd -- "${bigstaged_repo}" && "${GATE}" --check --staged 2>&1 || true )"
if grep --quiet --fixed-strings -- 'FAIL check-added-large-files' <<< "${bigstaged_out}"; then
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
bignew_out="$( cd -- "${bignew_repo}" && "${GATE}" --check --staged 2>&1 || true )"
if grep --quiet --fixed-strings -- 'FAIL check-added-large-files' <<< "${bignew_out}"; then
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
py_out="$( cd -- "${py_repo}" && "${GATE}" --check --range "${py_base}" 2>&1 || true )"
if grep --quiet --fixed-strings -- 'R-180' <<< "${py_out}"; then
   printf '%s\n' 'PASS: R-180 flags a python file with no shebang'
else
   printf '%s\n' 'FAIL: R-180 did not flag a shebang-less python file' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'withshebang.py' <<< "${py_out}"; then
   printf '%s\n' 'FAIL: R-180 flagged a compliant python file' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-180 spares a shebang+executable python file'
fi
if grep --quiet --fixed-strings -- '__init__.py' <<< "${py_out}"; then
   printf '%s\n' 'FAIL: R-180 flagged an EMPTY package marker' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-180 exempts an empty __init__.py'
fi

## R-190: a substantial interpreter program does not belong in a shell
## heredoc. Same defect as R-100 for workflow YAML -- ruff and pyrefly only see
## real '*.py' files, coverage.py cannot measure a heredoc, and no unit test can
## import a function that has no file. Short glue is fine; a substantial program
## (like R-100's inline-shell block) must live in its own file.
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
## A '#'-bearing heredoc delimiter must not swallow a REAL inline interpreter that
## follows it: `<<EOF#x` has delimiter EOF#x, and mis-recording it as EOF (breaking
## the delimiter word at '#') never matches the EOF#x terminator, so the body would
## run on and mask the python heredoc below.
printf '%s\n' \
   '#!/bin/bash' \
   'cat > /dev/null <<EOF#x' \
   'one' \
   'two' \
   'EOF#x' \
   'python3 - <<'"'"'PY'"'"'' \
   'a = 1' \
   'b = 2' \
   'c = 3' \
   'd = 4' \
   'e = 5' \
   'f = 6' \
   'print(a, b, c, d, e, f)' \
   'PY' > "${inline_repo}/hashdelim.sh"
chmod 0755 -- "${inline_repo}"/*.sh
git -C "${inline_repo}" add --all
git -C "${inline_repo}" commit --quiet --no-verify --message inline
inline_out="$( cd -- "${inline_repo}" && "${GATE}" --check --range "${inline_base}" 2>&1 || true )"
## Scope every assertion to R-190 FAILURES. The fixtures deliberately lack a
## strict preamble and a copyright header, so other rules name them too.
## Match the FAILURE text, not the bare rule id: the gate also emits an
## 'R-190 skipped: ... waiver in <file>' note, which names the very file the
## waiver spared and would read as a violation.
inline_hits="$( printf '%s\n' "${inline_out}" \
   | grep --fixed-strings -- 'R-190 inline interpreter program' || true )"
if grep --quiet --fixed-strings -- 'longinline.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'PASS: R-190 flags a long inline interpreter program'
else
   printf '%s\n' 'FAIL: R-190 did not flag a long inline interpreter program' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'shortglue.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'FAIL: R-190 flagged short glue' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 spares a short inline one-liner'
fi
if grep --quiet --fixed-strings -- 'plaindoc.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'FAIL: R-190 flagged a non-interpreter heredoc' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 ignores a heredoc feeding a non-interpreter'
fi
if grep --quiet --fixed-strings -- 'docexample.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'FAIL: R-190 flagged an interpreter example inside a doc heredoc' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 ignores an interpreter example inside a doc heredoc'
fi
if grep --quiet --fixed-strings -- 'masked.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'PASS: R-190 still sees a violation after a commented opener'
else
   printf '%s\n' 'FAIL: a commented opener masked a real inline program' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'spaced.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'PASS: R-190 catches whitespace after the heredoc operator'
else
   printf '%s\n' 'FAIL: R-190 missed "<< DELIM" with whitespace' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'hashdelim.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'PASS: a "#"-bearing heredoc delimiter does not mask a later inline program'
else
   printf '%s\n' 'FAIL: "<<EOF#x" delimiter swallowed a real inline interpreter' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'waived.sh' <<< "${inline_hits}"; then
   printf '%s\n' 'FAIL: R-190 ignored its style-ok waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-190 honours the allow-inline-interpreter waiver'
fi

## R-193: an in-repo script is called DIRECTLY via its shebang + exec bit, not
## through an interpreter prefix that re-names it (which also drops shebang flags).
## Only a LITERAL '<interpreter> -- <path>.py' is flagged. Fragments keep the flagged
## sequence from appearing literally in THIS tracked file.
py='foo.py'
## The FAIL message is the tag, not the bare rule id: the waiver-skip NOTE also
## carries 'R-193', so a bare-id match would read the skip as a violation.
r193='R-193 call the +x script'
## The interpreter-prefixed call is FLAGGED.
expect_rule "${r193}" "python3 ${dd} ${dq}\${dir}/${py}${dq} arg" "present"
## The direct call (shebang honoured) is SPARED.
expect_rule "${r193}" "${dq}\${dir}/${py}${dq} arg"              "absent"
## A generic dispatcher ('interpreter -- "$@"') names no literal script -- glue, not
## a call; SPARED.
expect_rule "${r193}" "python3 ${dd} ${dq}\$@${dq}"              "absent"
## A COMMENT that merely spells the pattern must not self-trip.
expect_rule "${r193}" "${hash}${hash} example python3 ${dd} bar.py" "absent"
## The per-file waiver (a script deliberately NOT +x, or an external path) is honoured.
expect_rule "${r193}" "${hash}${hash} style-ok: allow-python-dashdash${nlreal}python3 ${dd} ${dq}\${dir}/${py}${dq}" "absent"
## The 'python' token is word-bounded: a command that merely ENDS in 'python' is spared.
expect_rule "${r193}" "run_python ${dd} ${dq}\${dir}/${py}${dq}"  "absent"
## The '.py' must end at a path boundary: 'x.py.txt' (not a .py file) is spared.
expect_rule "${r193}" "python3 ${dd} script.py.txt"              "absent"
## A 'python3 -- x.py' spelled INSIDE a quoted string is data, not a call: spared.
expect_rule "${r193}" "echo ${sq}python3 ${dd} ${py}${sq}"       "absent"
## A trailing inline comment that merely spells the call is documentation: spared.
expect_rule "${r193}" "run something ${hash} python3 ${dd} ${py}" "absent"
## A '/' after '.py' is a path continuation, not a boundary: 'foo.py/bar' is spared.
expect_rule "${r193}" "python3 ${dd} ${py}/bar"                  "absent"
## A '#' inside a word (substring-removal '${var#pre}') is NOT a comment, so a real call
## LATER on the same line is still scanned and flagged.
expect_rule "${r193}" "run ${dollar}{var${hash}pre} && python3 ${dd} real.py" "present"
## A benign quoted occurrence before a real call on the same line does not mask the call.
expect_rule "${r193}" "echo ${dq}python3 ${dd} ${py}${dq} ${sc} python3 ${dd} real.py" "present"

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
shebang_out="$( cd -- "${shebang_repo}" && "${GATE}" --check --range "${shebang_base}" 2>&1 || true )"
## Anchor on the hook's own verdict line, not the filename: the gate's SKIP note
## names the waived file too, so a bare filename match would confirm itself.
if grep --quiet --fixed-strings -- 'plain.conf: has a shebang but is not marked executable' <<< "${shebang_out}"; then
   printf '%s\n' 'PASS: shebang check still fires without the waiver'
else
   printf '%s\n' 'FAIL: shebang check missed an unwaived non-executable shebang file' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'waived.conf: has a shebang but is not marked executable' <<< "${shebang_out}"; then
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
gitlink_out="$( cd -- "${gitlink_repo}" && "${GATE}" --check --range "${gitlink_base}" 2>&1 || true )"
if grep --quiet --fixed-strings -- 'Is a directory' <<< "${gitlink_out}"; then
   printf '%s\n' 'FAIL: gate grepped a submodule gitlink as if it were a file' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: gate does not grep a submodule gitlink'
fi
## forbid-new-submodules diffs '--staged' unless the range env vars are set, so
## in push mode it inspected an empty diff and passed unconditionally.
if grep --quiet --fixed-strings -- 'new submodule introduced' <<< "${gitlink_out}"; then
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
ascii_out="$( cd -- "${ascii_repo}" && "${GATE}" --check --range "${ascii_base}" 2>&1 || true )"
if grep --quiet --fixed-strings -- "R-001 non-ASCII character(s): 'plain.py:" <<< "${ascii_out}"; then
   printf '%s\n' 'PASS: R-001 still flags non-ASCII without the waiver'
else
   printf '%s\n' 'FAIL: R-001 did not flag non-ASCII -- the waiver is too broad' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- "R-001 non-ASCII character(s): 'waived.py:" <<< "${ascii_out}"; then
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
## A genuinely TRACKED shell file, committed at base. The tracked-vs-untracked
## assertion below tests against a name that actually exists in this fixture, so
## a regression that listed tracked files as untracked would flip it -- the old
## 'sample.sh' probe was vacuous (no such file could ever appear).
printf '%s\n' '#!/bin/bash' 'true' > "${untracked_repo}/tracked-tool.sh"
git -C "${untracked_repo}" add tracked-tool.sh
git -C "${untracked_repo}" commit --quiet --no-verify --message base
untracked_base="$(git -C "${untracked_repo}" rev-parse HEAD)"
## Never added: that is the whole point of the case.
printf '%s\n' '#!/bin/bash' 'true' > "${untracked_repo}/brand-new-tool"
untracked_out="$( cd -- "${untracked_repo}" && "${GATE}" --check --range "${untracked_base}" 2>&1 || true )"
if grep --quiet --fixed-strings 'brand-new-tool' <<< "${untracked_out}"; then
   printf '%s\n' 'PASS: an untracked shell file is named as NOT checked'
else
   printf '%s\n' \
      "FAIL: an untracked shell file was silently unchecked; output: ${untracked_out}" >&2
   failures=$((failures + 1))
fi

## The tracked, committed shell file must NOT be reported as untracked, or the
## notice would fire on every run and stop meaning anything.
if grep --quiet --fixed-strings 'tracked-tool.sh' <<< "${untracked_out}"; then
   printf '%s\n' 'FAIL: a tracked file was reported as untracked' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: the untracked notice does not fire for tracked files'
fi

## An untracked EXTENSIONLESS shell file whose NAME carries a non-UTF-8 byte: the
## shebang open() must see the REAL path, so decoding the name lossily
## (errors='replace') corrupts it, the open fails, and the advisory silently
## drops -- the exact gap it exists to close. The 0xFF byte comes from a run-time
## octal escape, so no non-UTF-8 byte lives in THIS tracked file.
nonutf_name="$(printf 'untr8-\377-marker')"
printf '%s\n' '#!/bin/bash' 'true' > "${untracked_repo}/${nonutf_name}"
nonutf_out="$( cd -- "${untracked_repo}" && "${GATE}" --check --range "${untracked_base}" 2>&1 || true )"
if grep --quiet --fixed-strings 'untr8-' <<< "${nonutf_out}"; then
   printf '%s\n' 'PASS: an untracked shell file with a non-UTF-8 name is still named'
else
   printf '%s\n' 'FAIL: a non-UTF-8-named untracked shell file was silently unchecked' >&2
   failures=$((failures + 1))
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
## A markdown doc is documentation, never a systemd unit: a rule doc (the bash
## style guide itself) carries an example 'Exec*=' multi-statement line that
## R-191 must NOT flag. The leading quote before 'ExecStart' keeps R-191's own
## membership grep from reading THIS authoring line as a unit.
printf '%s\n' \
   '# Example unit (documentation)' \
   '' \
   "    ExecStart=/bin/bash -c 'a && b'" \
   > "${unit_repo}/doc.md"
git -C "${unit_repo}" add --all
git -C "${unit_repo}" commit --quiet --no-verify --message unit
unit_out="$( cd -- "${unit_repo}" && "${GATE}" --check --range "${unit_base}" 2>&1 || true )"
## Scope to the R-191 FAILURE text: the gate also emits an 'R-191 skipped: ...
## waiver in <file>' note that names the waived file, which a bare rule-id match
## would misread as a violation.
unit_hits="$( printf '%s\n' "${unit_out}" \
   | grep --fixed-strings -- 'R-191 systemd unit embeds' || true )"
if grep --quiet --fixed-strings -- 'bad-amp.service' <<< "${unit_hits}"; then
   printf '%s\n' 'PASS: R-191 flags a "&&"-chained embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a "&&"-chained embedded script' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-semi.service' <<< "${unit_hits}"; then
   printf '%s\n' 'PASS: R-191 flags a ";"-separated embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a ";"-separated embedded script' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-continued.service' <<< "${unit_hits}"; then
   printf '%s\n' 'PASS: R-191 flags a line-continued embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a line-continued embedded script' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-lc.service' <<< "${unit_hits}"; then
   printf '%s\n' 'PASS: R-191 flags a "-lc" option-cluster embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a "-lc" option-cluster embedded script' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-ec.service' <<< "${unit_hits}"; then
   printf '%s\n' 'PASS: R-191 flags a "-ec" option-cluster embedded script'
else
   printf '%s\n' 'FAIL: R-191 did not flag a "-ec" option-cluster embedded script' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-attached.service' <<< "${unit_hits}"; then
   printf '%s\n' 'PASS: R-191 flags a command attached to -c with no space'
else
   printf '%s\n' 'FAIL: R-191 did not flag a command attached to -c with no space' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-bg.service' <<< "${unit_hits}"; then
   printf '%s\n' 'PASS: R-191 flags a standalone "&" background separator'
else
   printf '%s\n' 'FAIL: R-191 did not flag a standalone "&" background separator' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'good-redir.service' <<< "${unit_hits}"; then
   printf '%s\n' 'FAIL: R-191 flagged a ">&2" redirection as backgrounding' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-191 spares a ">&2" redirection (not a "&" background)'
fi
if grep --quiet --fixed-strings -- 'good.service' <<< "${unit_hits}"; then
   printf '%s\n' 'FAIL: R-191 flagged a single-command wrapper / plain Exec' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-191 spares a single-command wrapper and a plain Exec'
fi
if grep --quiet --fixed-strings -- 'waived.service' <<< "${unit_hits}"; then
   printf '%s\n' 'FAIL: R-191 ignored its allow-embedded-script waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-191 honours the allow-embedded-script waiver'
fi
if grep --quiet --fixed-strings -- 'doc.md' <<< "${unit_hits}"; then
   printf '%s\n' 'FAIL: R-191 flagged an example Exec= line in a markdown doc' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-191 spares a markdown doc carrying an example Exec= line'
fi

## R-194: an apt config hook must not embed a multi-statement shell command in
## its quoted value. A ';'-separated or piped value is FLAGGED; a '|| true' /
## single-command value and a non-hook path setting are SPARED; the file-wide
## waiver exempts the file. Fixtures live under 'apt.conf.d/' because R-194
## scopes to that path. The multi-statement ';' comes from run-time text (${sc})
## so no literal lives in THIS tracked file.
apt_repo="$(mktemp --directory --tmpdir="${tmp_root}" apt.XXXXXX)"
git -C "${apt_repo}" init --quiet
git -C "${apt_repo}" config user.email 'ci-test@example.com'
git -C "${apt_repo}" config user.name 'ci-test'
git -C "${apt_repo}" commit --quiet --no-verify --allow-empty --message base
apt_base="$(git -C "${apt_repo}" rev-parse HEAD)"
mkdir -p -- "${apt_repo}/etc/apt/apt.conf.d"
printf '%s\n' \
   "DPkg::Post-Invoke {\"/usr/bin/a${sc} /usr/bin/b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/10bad-semi"
printf '%s\n' \
   'DPkg::Post-Invoke {"/usr/bin/a | /usr/bin/b"};' \
   > "${apt_repo}/etc/apt/apt.conf.d/11bad-pipe"
## Bare (brace-less) quoted value: the embedded ';' sits at brace depth 0, so a
## depth-only region scan would end the directive AT that ';' and never see the
## closing quote -- hiding the multi-statement value. The quoted-region scan must
## treat the ';' as literal data. apt accepts this exact form.
printf '%s\n' \
   "DPkg::Pre-Invoke \"/usr/bin/a${sc} /usr/bin/b\"${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/12bad-semi-bareval"
## No SPACE between the keyword and its value: apt runs 'Pre-Invoke{"..."}' and
## 'Pre-Invoke"..."' identically to the spaced form, but the keyword regex used to
## CONSUME that first '{'/'"' as its trailing boundary, so the value scan began one
## char late and truncated at the first embedded ';'. The brace form hides a whole
## second command; the quote form hides the multi-statement inside one value.
printf '%s\n' \
   "DPkg::Pre-Invoke{\"true\"${sc} \"/usr/bin/a${sc} /usr/bin/b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/13bad-nospace-brace"
## apt '::' list-append and an UNQUOTED value are both real hook forms apt runs;
## parsing via apt_pkg catches them where a quoted-only scanner did not.
printf '%s\n' \
   "DPkg::Pre-Install-Pkgs:: \"echo a${sc} echo b\"${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/23bad-list-append"
printf '%s\n' \
   "DPkg::Pre-Invoke {echo|rm${sc}}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/24bad-unquoted"
## Post-Invoke-Success is an executed hook too ('-' is part of the name).
printf '%s\n' \
   "APT::Update::Post-Invoke-Success {\"echo a${sc} echo b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/25bad-invoke-success"
## An '#include' in an UNTRUSTED apt.conf must be NEUTERED (apt_pkg would follow
## it against the host: /dev/zero pegs a CPU, a fifo hangs, a dir reads host
## config). The real hook below must still be flagged, and the gate must not hang.
printf '%s\n' \
   "#include \"/dev/zero\"" \
   "DPkg::Pre-Invoke {\"echo a${sc} echo b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/26bad-include-neutered"
## The neuter must be COMMENT-blind too: a '//' comment holding an unmatched '\"'
## precedes a '#include \"/dev/zero\"'. A quote-AWARE neuter would let the comment
## quote flip its in-quote state and leave this '#include' LIVE -> apt follows
## /dev/zero and the gate HANGS. The unconditional neuter has no such hole; the
## real hook below must still be flagged (and the timeout above proves no hang).
printf '%s\n' \
   "// note with an unmatched \" quote" \
   "#include \"/dev/zero\"" \
   "DPkg::Pre-Invoke {\"echo x${sc} echo y\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/27bad-include-after-comment"
## A trailing INLINE '//' comment (apt honours it from any column, not just a
## whole-line comment) carrying a '}' desyncs the brace-depth scan: the ';' after
## the benign entry is then read as the directive terminator, hiding the later
## multi-statement entry. Stripping inline comments first must keep R-194 seeing it.
printf '%s\n' \
   'APT::Update::Pre-Invoke {' \
   "\"echo one\"${sc} // stray brace } in a comment" \
   "\"benign\"${sc}" \
   "\"echo two${sc} echo three\"${sc}" \
   "}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/15bad-inline-comment"
## apt.conf option names are case-INSENSITIVE, so a lower/mixed-case hook runs
## its multi-statement value just the same; a case-sensitive match missed it.
printf '%s\n' \
   "dpkg::pre-invoke {\"echo one${sc} echo two\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/16bad-lowercase"
## apt CONCATENATES adjacent double-quoted spans (C-string style) into one value,
## so a multi-statement command split across two touching "..." spans is one sh -c
## command; checking each span independently missed it.
printf '%s\n' \
   "DPkg::Pre-Invoke {\"echo a${sc}\"\"echo b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/17bad-concat"
## '#clear'/'#include' are apt DIRECTIVES, not comments -- apt keeps parsing the
## rest of the line, so a hook after a '#clear' must still be seen.
printf '%s\n' \
   "DPkg::Pre-Invoke {\"true\"}${sc} #clear APT::Foo${sc} DPkg::Post-Invoke {\"echo a${sc} echo b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/19bad-hash-directive"
## '|| true' error-suppression and a single command are glue, not a program.
printf '%s\n' \
   'DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true"};' \
   > "${apt_repo}/etc/apt/apt.conf.d/20good-ortrue"
## A non-hook setting whose quoted value is a path must never be scanned.
printf '%s\n' \
   'Dir::Cache "/var/cache/apt";' \
   > "${apt_repo}/etc/apt/apt.conf.d/30good-setting"
## A '#' comment (line-leading OR inline) is NOT installed by apt, so a hook it
## comments out must be SPARED -- '#' is a comment except a '#include'/'#clear'
## directive. Guards against the fail-closed over-blocking a commented-out hook.
printf '%s\n' \
   "# DPkg::Pre-Invoke {\"echo a${sc} echo b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/31good-hash-comment"
printf '%s\n' \
   "DPkg::Post-Invoke {\"/usr/bin/a\"}${sc} # inline note" \
   > "${apt_repo}/etc/apt/apt.conf.d/32good-inline-hash"
printf '%s\n' \
   '// style-ok: allow-embedded-script' \
   "DPkg::Post-Invoke {\"a${sc} b\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/40waived"
## A '|' that is DATA inside a quoted grep pattern, plus '|| true' glue, is a
## single command -- the defang must keep R-194 from over-blocking it.
printf '%s\n' \
   "DPkg::Post-Invoke {\"grep -E 'foo|bar' /etc/x || true\"}${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/50good-quoted-pipe"
## A non-hook setting whose quoted VALUE merely mentions a hook keyword (and a
## ';') must not be read as a hook -- the directive detect defangs the line first,
## so the keyword inside the value does not count.
printf '%s\n' \
   "Acquire::http::User-Agent \"mentions Post-Invoke and a${sc} b\"${sc}" \
   > "${apt_repo}/etc/apt/apt.conf.d/60good-keyword-in-value"
git -C "${apt_repo}" add --all
git -C "${apt_repo}" commit --quiet --no-verify --message apt
## '--kill-after' + a bound: if the '#include' XXE neuter ever regresses, a fixture
## with '#include "/dev/zero"' would HANG the gate -- fail the test, do not hang it.
apt_out="$( cd -- "${apt_repo}" && timeout --kill-after=5s 60s "${GATE}" --check --range "${apt_base}" 2>&1 || true )"
## Scope to the R-194 FAILURE text: the 'R-194 skipped: ... waiver' note names
## the waived file, which a bare rule-id match would misread as a violation.
apt_hits="$( printf '%s\n' "${apt_out}" \
   | grep --fixed-strings -- 'R-194 apt hook embeds' || true )"
## Liveness: the gate run above (line ~1640, `|| true`) could crash or be
## timeout-killed, leaving apt_out empty -- which would make every ABSENCE ('good'
## fixture) assertion below PASS spuriously. Require the gate's final verdict first.
if ! grep --quiet --extended-regexp \
   'all static checks passed|[0-9]+ check\(s\) failed' <<< "${apt_out}"; then
   printf '%s\n' 'FAIL: R-194 apt gate run produced no final verdict (crashed or killed)' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '10bad-semi' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a ";"-separated apt hook command'
else
   printf '%s\n' 'FAIL: R-194 did not flag a ";"-separated apt hook command' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '11bad-pipe' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a piped apt hook command'
else
   printf '%s\n' 'FAIL: R-194 did not flag a piped apt hook command' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '12bad-semi-bareval' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a ";"-separated bare-quoted (brace-less) apt hook command'
else
   printf '%s\n' 'FAIL: R-194 did not flag a ";"-separated bare-quoted apt hook command' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '13bad-nospace-brace' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a no-space brace apt hook (keyword glued to value)'
else
   printf '%s\n' 'FAIL: R-194 did not flag a no-space brace apt hook' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '23bad-list-append' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a "::" list-append multi-statement hook'
else
   printf '%s\n' 'FAIL: R-194 did not flag a "::" list-append hook' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '24bad-unquoted' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags an UNQUOTED apt hook value (a pipe)'
else
   printf '%s\n' 'FAIL: R-194 did not flag an unquoted apt hook value' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '25bad-invoke-success' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a Post-Invoke-Success multi-statement hook'
else
   printf '%s\n' 'FAIL: R-194 did not flag a Post-Invoke-Success hook' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '26bad-include-neutered' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags the hook and neuters a malicious "#include"'
else
   printf '%s\n' 'FAIL: R-194 missed a hook beside a neutered "#include"' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '27bad-include-after-comment' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 neuters a "#include" after a comment holding an unmatched quote (no hang)'
else
   printf '%s\n' 'FAIL: R-194 missed the hook, or the gate hung, on a "#include" after a comment' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '15bad-inline-comment' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a hook hidden behind an inline-comment brace desync'
else
   printf '%s\n' 'FAIL: R-194 did not flag a hook behind an inline-comment brace desync' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '16bad-lowercase' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a non-canonical-case (lowercase) apt hook'
else
   printf '%s\n' 'FAIL: R-194 did not flag a lowercase apt hook' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '17bad-concat' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a value split across adjacent concatenated spans'
else
   printf '%s\n' 'FAIL: R-194 did not flag an adjacent-concatenated split value' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '19bad-hash-directive' <<< "${apt_hits}"; then
   printf '%s\n' 'PASS: R-194 flags a hook after a "#clear" apt directive'
else
   printf '%s\n' 'FAIL: R-194 did not flag a hook after a "#clear" directive' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- '20good-ortrue' <<< "${apt_hits}"; then
   printf '%s\n' 'FAIL: R-194 flagged a "|| true" glue apt hook' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-194 spares a "|| true" glue apt hook'
fi
if grep --quiet --fixed-strings -- '30good-setting' <<< "${apt_hits}"; then
   printf '%s\n' 'FAIL: R-194 scanned a non-hook apt setting value' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-194 spares a non-hook apt setting'
fi
if grep --quiet --fixed-strings -- '31good-hash-comment' <<< "${apt_hits}"; then
   printf '%s\n' 'FAIL: R-194 flagged a "#"-commented-out apt hook' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-194 spares a "#"-commented-out apt hook'
fi
if grep --quiet --fixed-strings -- '32good-inline-hash' <<< "${apt_hits}"; then
   printf '%s\n' 'FAIL: R-194 flagged a hook with a trailing "#" inline comment' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-194 spares a hook with a trailing "#" inline comment'
fi
if grep --quiet --fixed-strings -- '40waived' <<< "${apt_hits}"; then
   printf '%s\n' 'FAIL: R-194 ignored its allow-embedded-script waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-194 honours the allow-embedded-script waiver'
fi
if grep --quiet --fixed-strings -- '50good-quoted-pipe' <<< "${apt_hits}"; then
   printf '%s\n' 'FAIL: R-194 over-blocked a "|" inside a quoted grep pattern' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-194 defangs a "|" inside a quoted value'
fi
if grep --quiet --fixed-strings -- '60good-keyword-in-value' <<< "${apt_hits}"; then
   printf '%s\n' 'FAIL: R-194 read a non-hook setting as a hook (keyword inside a value)' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-194 defangs the line before matching the hook directive'
fi

## R-195: a cron entry must not embed a multi-statement command. A ';'-separated
## or piped command is FLAGGED; the stock-Debian 'cd / && run-parts' and 'test
## -x X || ( ... )' glue, an env assignment, and a single command are SPARED; the
## file-wide waiver exempts the file. Fixtures live under 'cron.d/' because R-195
## scopes to that path.
cron_repo="$(mktemp --directory --tmpdir="${tmp_root}" cron.XXXXXX)"
git -C "${cron_repo}" init --quiet
git -C "${cron_repo}" config user.email 'ci-test@example.com'
git -C "${cron_repo}" config user.name 'ci-test'
git -C "${cron_repo}" commit --quiet --no-verify --allow-empty --message base
cron_base="$(git -C "${cron_repo}" rev-parse HEAD)"
mkdir -p -- "${cron_repo}/etc/cron.d"
printf '%s\n' \
   "*/5 * * * * root /usr/bin/a${sc} /usr/bin/b" \
   > "${cron_repo}/etc/cron.d/bad-semi"
printf '%s\n' \
   '0 3 * * * root /usr/bin/a | /usr/bin/b' \
   > "${cron_repo}/etc/cron.d/bad-pipe"
## The stock '/etc/crontab' idiom: cron has no native cwd / conditional-run
## directive, so '&&' and '|| ( ... )' glue must be tolerated.
printf '%s\n' \
   '17 * * * * root cd / && run-parts --report /etc/cron.hourly' \
   > "${cron_repo}/etc/cron.d/good-amp"
printf '%s\n' \
   '25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts /etc/cron.daily )' \
   > "${cron_repo}/etc/cron.d/good-ortest"
## Env assignments, a comment, and a single-command entry are not programs.
printf '%s\n' \
   'MAILTO=""' \
   'PATH=/usr/local/bin:/usr/bin:/bin' \
   '# scheduled cleanup' \
   '@daily root /usr/local/bin/clean' \
   > "${cron_repo}/etc/cron.d/good-env"
## Single commands whose ';' / '|' is DATA, not a separator: an escaped 'find
## -exec ... \;' terminator and a '|' inside a quoted awk pattern. The defang
## must keep R-195 from over-blocking these ordinary idioms.
## '${tmpp}' (=/tmp) and '${del}' (=rm) are assembled at run time so the literal
## '/tmp' / 'rm' the gate flags (R-170 / R-120) never appears in THIS file.
printf '%s\n' \
   "0 3 * * * root find ${tmpp} -type f -mtime +7 -exec ${del} -- {} \\;" \
   > "${cron_repo}/etc/cron.d/good-find-exec"
printf '%s\n' \
   "0 4 * * * root awk '/foo|bar/{print}' /var/log/x" \
   > "${cron_repo}/etc/cron.d/good-awk-pipe"
## A cron command's first UNESCAPED '%' ends the command -- the rest is stdin, so
## a ';' after it is message DATA, not a shell separator.
printf '%s\n' \
   "0 5 * * * root mail user%body${sc} more text" \
   > "${cron_repo}/etc/cron.d/good-percent"
## A whitespace-introduced '#' begins a shell comment in the command; a ';' inside
## that comment is not executable.
printf '%s\n' \
   "0 6 * * * root /usr/bin/job # note${sc} monitored elsewhere" \
   > "${cron_repo}/etc/cron.d/good-hash"
git -C "${cron_repo}" add --all
git -C "${cron_repo}" commit --quiet --no-verify --message cron
cron_out="$( cd -- "${cron_repo}" && "${GATE}" --check --range "${cron_base}" 2>&1 || true )"
cron_hits="$( printf '%s\n' "${cron_out}" \
   | grep --fixed-strings -- 'R-195 cron entry embeds' || true )"
## Liveness: the gate run above (`|| true`) could crash or be timeout-killed, leaving
## cron_out empty and every ABSENCE ('good' fixture) assertion below a spurious PASS.
if ! grep --quiet --extended-regexp \
   'all static checks passed|[0-9]+ check\(s\) failed' <<< "${cron_out}"; then
   printf '%s\n' 'FAIL: R-195 cron gate run produced no final verdict (crashed or killed)' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-semi' <<< "${cron_hits}"; then
   printf '%s\n' 'PASS: R-195 flags a ";"-separated cron command'
else
   printf '%s\n' 'FAIL: R-195 did not flag a ";"-separated cron command' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad-pipe' <<< "${cron_hits}"; then
   printf '%s\n' 'PASS: R-195 flags a piped cron command'
else
   printf '%s\n' 'FAIL: R-195 did not flag a piped cron command' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'good-amp' <<< "${cron_hits}"; then
   printf '%s\n' 'FAIL: R-195 flagged the stock "cd / && run-parts" glue' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-195 spares the stock "cd / && run-parts" glue'
fi
if grep --quiet --fixed-strings -- 'good-ortest' <<< "${cron_hits}"; then
   printf '%s\n' 'FAIL: R-195 flagged the stock "test || ( ... )" glue' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-195 spares the stock "test || ( ... )" glue'
fi
if grep --quiet --fixed-strings -- 'good-find-exec' <<< "${cron_hits}"; then
   printf '%s\n' 'FAIL: R-195 over-blocked an escaped "find -exec ... \;" terminator' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-195 defangs an escaped "\;" find terminator'
fi
if grep --quiet --fixed-strings -- 'good-awk-pipe' <<< "${cron_hits}"; then
   printf '%s\n' 'FAIL: R-195 over-blocked a "|" inside a quoted awk pattern' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-195 defangs a "|" inside a quoted pattern'
fi
if grep --quiet --fixed-strings -- 'good-percent' <<< "${cron_hits}"; then
   printf '%s\n' 'FAIL: R-195 over-blocked a ";" after a cron "%" (stdin body)' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-195 scans only the command before a cron "%"'
fi
if grep --quiet --fixed-strings -- 'good-hash' <<< "${cron_hits}"; then
   printf '%s\n' 'FAIL: R-195 over-blocked a ";" inside a "#" shell comment' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-195 strips a trailing "#" comment before the test'
fi
if grep --quiet --fixed-strings -- 'good-env' <<< "${cron_hits}"; then
   printf '%s\n' 'FAIL: R-195 flagged an env assignment / single-command entry' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-195 spares env assignments and a single-command entry'
fi

## R-100: a workflow 'run: |' block of more than 5 shell STATEMENTS is FLAGGED
## (the six 'step_*' commands below); a single-line 'run: ./ci/x.sh' and a
## short (<=5-statement) block are SPARED; the file-wide waiver exempts the
## workflow. The fixtures live under '.github/workflows/' because R-100 scopes
## to that path.
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
wf_out="$( cd -- "${wf_repo}" && "${GATE}" --check --range "${wf_base}" 2>&1 || true )"
## Scope to the R-100 FAILURE text, past the 'R-100 skipped: ... waiver' note.
wf_hits="$( printf '%s\n' "${wf_out}" \
   | grep --fixed-strings -- 'R-100 workflow embeds' || true )"
## Liveness: a crashed/killed gate leaves wf_out empty -> the ABSENCE assertions below
## PASS spuriously. Require the terminal verdict before trusting them.
if ! grep --quiet --extended-regexp \
   'all static checks passed|[0-9]+ check\(s\) failed' <<< "${wf_out}"; then
   printf '%s\n' 'FAIL: R-100 workflow gate run produced no final verdict (crashed or killed)' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'bad.yml' <<< "${wf_hits}"; then
   printf '%s\n' 'PASS: R-100 flags a long inline run block'
else
   printf '%s\n' 'FAIL: R-100 did not flag a long inline run block' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'quoted-run.yml' <<< "${wf_hits}"; then
   printf '%s\n' 'PASS: R-100 flags a long inline block behind a quoted "run:" key'
else
   printf '%s\n' 'FAIL: R-100 did not flag a quoted "run:" inline block' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'spaced-run.yml' <<< "${wf_hits}"; then
   printf '%s\n' 'PASS: R-100 flags a long inline block behind a whitespace-before-colon run key'
else
   printf '%s\n' 'FAIL: R-100 did not flag a "run :" (space before colon) inline block' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- 'good.yml' <<< "${wf_hits}"; then
   printf '%s\n' 'FAIL: R-100 flagged a single-line run and a short block' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-100 spares a single-line run and a short block'
fi
if grep --quiet --fixed-strings -- 'waived.yml' <<< "${wf_hits}"; then
   printf '%s\n' 'FAIL: R-100 ignored its allow-inline-shell waiver' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-100 honours the allow-inline-shell waiver'
fi

## ---- R-001 file-based allowlist (.gitattributes binary) ----
## A file DECLARED binary in .gitattributes is data, not text: R-001 (ASCII) and the
## pre-commit-hooks text fixers skip it, exactly as they skip a PNG. It is the clean
## opt-out for a raw byte-stream payload / fixture that cannot carry a '## style-ok'
## comment (the output-lies terminal-attack demo rides on it). The CANARY is the
## un-attributed case: the SAME bytes must still be flagged, so the allowlist is a real
## exemption, not the rule quietly not firing.
gate_output_data() {  ## $1=.gitattributes line (empty for none) -> gate output over base..HEAD
   local attr repo base
   attr="$1"
   repo="$(mktemp --directory --tmpdir="${tmp_root}" repo.XXXXXX)"
   git -C "${repo}" init --quiet
   git -C "${repo}" config user.email 'ci-test@example.com'
   git -C "${repo}" config user.name 'ci-test'
   git -C "${repo}" commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   ## A raw byte stream's shape: a non-ASCII byte (0xC3 0xA9), a CR, and no final
   ## newline -- each an independent R-001 / line-ending / end-of-file violation. Built
   ## with '%b' octal escapes, so no literal non-ASCII lives in THIS tracked file.
   printf '%b' 'blob header\rcaf\0303\0251 body no-newline' > "${repo}/blob.dat"
   if [ -n "${attr}" ]; then
      printf '%s\n' "${attr}" > "${repo}/.gitattributes"
      git -C "${repo}" add .gitattributes
   fi
   git -C "${repo}" add blob.dat
   git -C "${repo}" commit --quiet --no-verify --message blob
   (
      cd -- "${repo}" || exit 1
      "${GATE}" --check --range "${base}"
   ) 2>&1 || true
}

data_unattributed="$(gate_output_data '')"
if grep --quiet --fixed-strings -- 'R-001 non-ASCII' <<< "${data_unattributed}"; then
   printf '%s\n' 'PASS: R-001 flags a non-ASCII data file with no .gitattributes entry (canary)'
else
   printf '%s\n' 'FAIL: R-001 did not flag a non-ASCII data file without the binary attribute' >&2
   failures=$((failures + 1))
fi

data_allowlisted="$(gate_output_data 'blob.dat binary')"
if grep --quiet --fixed-strings -- 'R-001 non-ASCII' <<< "${data_allowlisted}"; then
   printf '%s\n' 'FAIL: R-001 flagged a .gitattributes binary data file (allowlist not honoured)' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-001 spares a .gitattributes binary data file'
fi
## The allowlist must clear the WHOLE text-content tier (ASCII + line endings + EOF via
## is_text_file), so the allowlisted commit reaches a clean verdict, not just a
## missing R-001 line.
if grep --quiet --fixed-strings -- 'all static checks passed' <<< "${data_allowlisted}"; then
   printf '%s\n' 'PASS: a .gitattributes binary data file passes the whole static gate'
else
   printf '%s\n' 'FAIL: a .gitattributes binary data file did not reach a clean gate verdict' >&2
   failures=$((failures + 1))
fi

## ---- commit-message R-001 (check_message_ascii, push mode) ----
## The pending commit message is the one text blob that is NOT a tree file. The
## gate resolves the base..HEAD message (or, staged, the --message-file) and
## hands it to the SAME engine rule via --message-file, so message and tree share
## one non-ASCII definition. A non-ASCII message must FAIL referencing the
## '(commit message)' pseudo-path; a clean ASCII message must pass.
gate_output_msg() {  ## $1=commit subject -> gate output over base..HEAD
   local subject repo base
   subject="$1"
   repo="$(mktemp --directory --tmpdir="${tmp_root}" msg.XXXXXX)"
   git -C "${repo}" init --quiet
   git -C "${repo}" config user.email 'ci-test@example.com'
   git -C "${repo}" config user.name 'ci-test'
   git -C "${repo}" commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   printf '%s\n' '#!/bin/bash' 'true' > "${repo}/ok.sh"
   git -C "${repo}" add ok.sh
   git -C "${repo}" commit --quiet --no-verify --message "${subject}"
   (
      cd -- "${repo}" || exit 1
      "${GATE}" --check --range "${base}"
   ) 2>&1 || true
}
## A U+00E9 (0xC3 0xA9) in the subject, assembled so THIS tracked file stays ASCII.
msg_bad_out="$(gate_output_msg "fix caf$(printf '%b' '\303\251') bug")"
if grep --quiet --fixed-strings -- "R-001 non-ASCII character(s): '(commit message)" <<< "${msg_bad_out}"; then
   printf '%s\n' 'PASS: R-001 flags a non-ASCII commit message (push mode)'
else
   printf '%s\n' 'FAIL: R-001 did not flag a non-ASCII commit message' >&2
   failures=$((failures + 1))
fi
msg_ok_out="$(gate_output_msg 'fix a plain ascii bug')"
## Liveness: this is an ABSENCE assertion (a clean message must NOT be flagged), so a
## crashed/killed gate with empty msg_ok_out would PASS it spuriously.
if ! grep --quiet --extended-regexp \
   'all static checks passed|[0-9]+ check\(s\) failed' <<< "${msg_ok_out}"; then
   printf '%s\n' 'FAIL: R-001 commit-message gate run produced no final verdict (crashed or killed)' >&2
   failures=$((failures + 1))
fi
if grep --quiet --fixed-strings -- "'(commit message)" <<< "${msg_ok_out}"; then
   printf '%s\n' 'FAIL: R-001 wrongly flagged a clean ASCII commit message' >&2
   failures=$((failures + 1))
else
   printf '%s\n' 'PASS: R-001 spares a clean ASCII commit message (push mode)'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "test_pre_push_static_style_rules: ${failures} assertion(s) FAILED." >&2
   exit 1
fi
printf '%s\n' "test_pre_push_static_style_rules: OK -- R-070, R-070 per-rule id override, R-074, R-026, R-030 format string, R-030/R-031, R-030/R-031 printf-format waiver, R-030/R-031 composite id override, AST-aware waiver (heredoc-body / trailing-inline / Python-string not honored), R-034, R-034 per-rule id override, R-011, R-051, R-090, R-102, R-103, R-120, R-170, R-180, R-190, R-191, R-194, R-195, R-100, R-010, R-001 .gitattributes-binary allowlist, R-001 commit-message, trailing-whitespace, CRLF-shebang, untracked-shell-file reporting, double-quote-string-fixer-disabled and imported-package-module exemption enforced as expected."
