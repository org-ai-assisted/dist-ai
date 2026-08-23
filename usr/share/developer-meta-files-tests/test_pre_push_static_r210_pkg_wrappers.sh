#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for the package-management rules, both sides of each:
##  R-210 apt-get         -> apt-get-noninteractive (gate FLAGS + fixer REWRITES)
##  R-211 state-changing dpkg -> dpkg-noninteractive (gate FLAGS; query/dpkg-*
##                            spared; fixer does NOT touch dpkg)
##  R-212 --allow-downgrades forbidden (gate FLAGS; fixer does NOT touch)
##  R-213 make_use_lintian=false forbidden (gate FLAGS; fixer does NOT touch)
##
## Each rule carries a CONTROL (a command it MUST flag) so no ALLOW passes
## vacuously, the spared forms (the wrapper itself, a query dpkg, a dpkg-* tool,
## an in-string mention, a waived file), and the human-operator waiver.
##
## Fixture bodies are ASSEMBLED from fragments so no command-position apt-get /
## 'dpkg <action>' / '--allow-downgrades' / 'make_use_lintian=false' appears
## literally on a source line of THIS tracked file -- the gate scans it too. The
## waiver strings are wrapped inside a 'body_of "..."' argument so their '##'
## never anchors as a real waiver on this file. Assertions match the gate's FAIL
## line ('FAIL R-21x') so a waiver-SKIP note (which also names the rule) is not
## mistaken for a violation.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
if ! has git ; then
   printf '%s\n' "FATAL: git not on PATH" >&2
   exit 1
fi

## Resolve the tools RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/)
## so a developer editing the in-tree copies tests those, not the packaged ones.
tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${tool_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi
FIX="${tool_dir}/../../bin/pre-push-fix"
if [ ! -x "${FIX}" ]; then
   FIX='/usr/bin/pre-push-fix'
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

fail=0

## Fragments, so no command-position needle appears literally in this file.
ag='apt-get'
agn='apt-get-noninteractive'
dp='dpkg'
adg='--allow-downgrades'
mul='make_use_lintian'
sc=';'
dq='"'
hash='#'

fixture_prologue=(
   '#!/bin/bash'
   ''
   'set -o errexit'
   'set -o nounset'
   'set -o pipefail'
   'set -o errtrace'
   'shopt -s inherit_errexit'
   'shopt -s shift_verbose'
   'export LC_ALL=C'
   ''
)

body_of() {
   printf '%s\n' "${fixture_prologue[@]}" "$@"
}

## Builds a one-file repo around a script body; sets gate_output and gate_rc.
run_gate_on_body() {
   local name body repo base_sha
   name="$1"
   body="$2"
   repo="${test_dir}/gate-${name}"
   mkdir --parents -- "${repo}/usr/bin"
   printf '%s\n' "${body}" >"${repo}/usr/bin/subject"
   chmod 0755 -- "${repo}/usr/bin/subject"
   git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --allow-empty --message "base"
   base_sha="$(git -C "${repo}" rev-parse HEAD)"
   git -C "${repo}" -c core.hooksPath=/dev/null add --all
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --message "fixture"
   gate_rc=0
   gate_output="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || gate_rc=$?
}

## assert_flagged <rule> <name> <body> -- 'FAIL <rule>' must appear.
assert_flagged() {
   local rule="$1" name="$2" body="$3"
   run_gate_on_body "${name}" "${body}"
   if grep --fixed-strings -- "FAIL ${rule}" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "PASS: ${rule} flagged ${name}"
   else
      printf '%s\n' "FAIL: ${rule} did NOT flag ${name}"
      printf '%s\n' "${gate_output}" | tail -5
      fail=1
   fi
}

## assert_spared <rule> <name> <body> -- 'FAIL <rule>' must NOT appear and the
## whole fixture must be gate-green (a spared construct is a valid one).
assert_spared() {
   local rule="$1" name="$2" body="$3"
   run_gate_on_body "${name}" "${body}"
   if grep --fixed-strings -- "FAIL ${rule}" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "FAIL: ${rule} wrongly flagged ${name}"
      printf '%s\n' "${gate_output}" | grep --fixed-strings -- "FAIL ${rule}" | head -2
      fail=1
   elif [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: gate not green on spared fixture ${name} (rc=${gate_rc})"
      printf '%s\n' "${gate_output}" | tail -5
      fail=1
   else
      printf '%s\n' "PASS: ${rule} spared ${name}"
   fi
}

## --- R-210: apt-get -> apt-get-noninteractive ---
assert_flagged "R-210" "apt-sudo"     "$(body_of "sudo ${ag} install foo")"
assert_flagged "R-210" "apt-linestart" "$(body_of "${ag} update")"
assert_flagged "R-210" "apt-cmdsubst" "$(body_of "out=\$(${ag} update)")"
assert_flagged "R-210" "apt-after-sep" "$(body_of "true${sc} ${ag} install foo")"
assert_spared  "R-210" "apt-wrapper"  "$(body_of "sudo ${agn} install foo")"
assert_spared  "R-210" "apt-instring" "$(body_of "printf '%s' 'run (${ag} install x)'")"
assert_spared  "R-210" "apt-waiver" \
   "$(body_of "## style-ok: allow-apt-get" "sudo ${ag} install foo")"
## A subshell '(cmd)' IS a command position; an ARRAY element 'v=(cmd)' is DATA.
assert_flagged "R-210" "apt-subshell"  "$(body_of "(${ag} install foo)")"
assert_spared  "R-210" "apt-array" \
   "$(body_of "cmd=(${ag} install foo)" "printf '%s' ${dq}\${cmd[@]}${dq}")"
## PROSE: a control keyword ('until') mid-sentence must NOT be read as a command
## introducer -- the removed keyword-introducer pattern flagged this (a false
## POSITIVE that fails a valid push). allow-echo waives the echo so only the
## R-210 decision is under test. Documented RESIDUAL (safe direction, NOT tested
## as a hard assertion): a real keyword-introduced command ('if ${ag} ...; then')
## and a command after a CLOSED quote ('echo "x"${sc} ${ag} ...') are missed --
## catching them needs a bash parser the gate refuses to grow.
assert_spared  "R-210" "prose-keyword" \
   "$(body_of "## style-ok: allow-echo" "echo wait until ${ag} finishes")"

## --- R-211: state-changing dpkg -> dpkg-noninteractive ---
assert_flagged "R-211" "dpkg-i"          "$(body_of "sudo ${dp} -i ./x.deb")"
assert_flagged "R-211" "dpkg-install"    "$(body_of "sudo ${dp} --install -- ./x.deb")"
assert_flagged "R-211" "dpkg-configure"  "$(body_of "sudo ${dp} --configure -a")"
assert_flagged "R-211" "dpkg-purge"      "$(body_of "sudo ${dp} -P somepkg")"
assert_spared  "R-211" "dpkg-compare"    "$(body_of "${dp} --compare-versions a gt b")"
assert_spared  "R-211" "dpkg-listfiles"  "$(body_of "${dp} -L somepkg")"
assert_spared  "R-211" "dpkg-deb"        "$(body_of "${dp}-deb --field ./x.deb Version")"
assert_spared  "R-211" "dpkg-wrapper"    "$(body_of "sudo ${dp}-noninteractive --install --refuse-downgrade -- ./x.deb")"
assert_spared  "R-211" "dpkg-instring"   "$(body_of "printf '%s' 'try (${dp} -i x)'")"
assert_spared  "R-211" "dpkg-waiver" \
   "$(body_of "## style-ok: allow-dpkg" "sudo ${dp} -i ./x.deb")"
## A state-changing action named only in a trailing COMMENT is not executed.
assert_spared  "R-211" "dpkg-action-in-comment" \
   "$(body_of "${dp} --version ${hash} ${dp} --install ./x.deb")"
## Command-position residual (documented, NOT fixed): a space-separated sudo
## option value ('sudo -u root ${dp} ...') is a false negative. Running dpkg as a
## non-root user is nonsensical, so this form does not occur for these targets;
## growing the wrap into a sudo-option parser is the treadmill the style rules
## forbid. No assertion -- see the R-210 note.

## --- R-212: --allow-downgrades forbidden ---
assert_flagged "R-212" "downgrade"       "$(body_of "sudo ${agn} install ${adg} -- foo")"
assert_spared  "R-212" "no-downgrade"    "$(body_of "sudo ${agn} install --yes -- foo")"
assert_spared  "R-212" "downgrade-waiver" \
   "$(body_of "## style-ok: allow-downgrades" "sudo ${agn} install ${adg} -- foo")"
## The flag named inside a quoted string (prose) is not an invocation.
assert_spared  "R-212" "downgrade-in-string" \
   "$(body_of "printf '%s' 'never use ${adg} here'")"

## --- R-213: make_use_lintian=false forbidden ---
assert_flagged "R-213" "lintian-off"     "$(body_of "${mul}=false genmkfile deb-pkg")"
assert_spared  "R-213" "lintian-on"      "$(body_of "${mul}=true genmkfile deb-pkg")"
assert_spared  "R-213" "lintian-waiver" \
   "$(body_of "## style-ok: allow-lintian-disable" "${mul}=false genmkfile deb-pkg")"
## Inside a quoted string, or as the tail of a LONGER variable name, is not a
## disable (word-boundary anchored).
assert_spared  "R-213" "lintian-in-string" \
   "$(body_of "message='${mul}=false is forbidden'" "printf '%s' ${dq}\${message}${dq}")"
assert_spared  "R-213" "lintian-substring" \
   "$(body_of "disable_${mul}=false" "printf '%s' ${dq}\${disable_${mul}}${dq}")"

## --- fixer (pre-push-fix): R-210 rewrites; R-211/212/213 are gate-report-only ---
run_fix() {
   local name body file
   name="$1"
   body="$2"
   file="${test_dir}/fix-${name}.sh"
   printf '%s\n' '#!/bin/bash' "${body}" >"${file}"
   "${FIX}" "${file}" >/dev/null 2>&1 || true
   fix_result="$(cat -- "${file}")"
}

## A command-position apt-get is renamed to the wrapper.
run_fix "apt-rename" "sudo ${ag} install foo"
if grep --fixed-strings -- "sudo ${agn} install foo" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix renamed apt-get to the wrapper"
else
   printf '%s\n' "FAIL: pre-push-fix did not rename apt-get"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## Idempotent: a second pass changes nothing.
run_fix "apt-idem" "sudo ${ag} install foo"
first="${fix_result}"
"${FIX}" "${test_dir}/fix-apt-idem.sh" >/dev/null 2>&1 || true
if [ "${first}" = "$(cat -- "${test_dir}/fix-apt-idem.sh")" ]; then
   printf '%s\n' "PASS: pre-push-fix apt-get rename is idempotent"
else
   printf '%s\n' "FAIL: pre-push-fix apt-get rename is not idempotent"
   fail=1
fi

## SAFETY: the fixer must NOT rewrite an already-wrapped apt-get, an in-string
## mention, a waived file, a dpkg, an --allow-downgrades, or make_use_lintian.
assert_fix_unchanged() {
   local name body
   name="$1"
   body="$2"
   run_fix "${name}" "${body}"
   if [ "${fix_result}" = "$(printf '%s\n' '#!/bin/bash' "${body}")" ]; then
      printf '%s\n' "PASS: pre-push-fix left ${name} unchanged"
   else
      printf '%s\n' "FAIL: pre-push-fix modified ${name}"
      printf '%s\n' "${fix_result}"
      fail=1
   fi
}
assert_fix_unchanged "already-wrapped" "sudo ${agn} install foo"
assert_fix_unchanged "apt-in-string"   "printf '%s' 'run (${ag} install x)'"
assert_fix_unchanged "apt-waived" \
   "$(printf '%s\n' '## style-ok: allow-apt-get' "sudo ${ag} install foo")"
## dpkg is gate-report-only: the fixer never touches it (an action-aware
## decision, not a single-token rename).
assert_fix_unchanged "dpkg-untouched"  "sudo ${dp} -i ./x.deb"
## --allow-downgrades and make_use_lintian=false are deliberate removals a human
## must make; the fixer leaves them for the gate to report.
assert_fix_unchanged "downgrade-untouched" "sudo ${agn} install ${adg} -- foo"
assert_fix_unchanged "lintian-untouched"   "${mul}=false genmkfile deb-pkg"
## The fixer must NOT rename a function DEFINITION, an assignment, or an array
## element -- none of which the gate flags (whole-word 'apt-get' + trailing
## space/EOL); renaming them would mutate gate-clean code.
assert_fix_unchanged "apt-funcdef" "${ag}() { command ${ag} ${dq}\$@${dq}; }"
assert_fix_unchanged "apt-assign"  "${ag}=/usr/bin/${ag}"
assert_fix_unchanged "apt-array"   "cmd=( ${ag} install foo )"
## Residual, in lockstep with the gate: a command after a CLOSED quote is left
## alone (the gate does not flag it either). The fixer builds no quote-state
## parser, so the two never disagree.
assert_fix_unchanged "apt-after-closed-quote" "printf '%s' ok${sc} sudo ${ag} install foo"

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
