#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-style's shellcheck tier: a '# shellcheck source='
## directive into the helper-scripts SIBLING repo cannot be FOLLOWED on a dev host
## (no local helper-scripts checkout; the installed /usr/libexec/helper-scripts is a
## flat runtime layout, not the repo tree the directive names). CI checks the
## sibling out and follows it; reproducing that locally is not viable because
## shellcheck's '--external-sources' following of the deep helper-scripts graph is
## exponential and hangs the gate. So the gate DROPS the info-level SC1091 for that
## absent sibling and reaches the same verdict CI does.
##
## The tolerance is decided from the FILESYSTEM, so it is EXACT. Fixtures, the real
## shipped gate driven as a subprocess:
##   A -- compliant script sourcing the helper-scripts sibling, sibling ABSENT: the
##        gate must be GREEN (FAILS on the pre-fix gate: SC1091 -> red).
##   B -- a NON-helper-scripts path that does not exist: the gate must be RED (the
##        tolerance is not a blanket SC1091 suppression).
##   C -- the helper-scripts sibling is PRESENT but the named file is missing (the
##        CI layout, or a typo): the gate must be RED (the drop is NOT inert-by-
##        substring; a genuinely broken helper-scripts path stays fatal).
##   D -- a bogus path that merely CONTAINS 'helper-scripts/usr/libexec/helper-scripts/'
##        as a substring but resolves elsewhere: the gate must be RED (anchored, not
##        a substring match).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has shellcheck ; then
   printf '%s\n' "FATAL: shellcheck not on PATH (apt-get install shellcheck)" >&2
   printf '%s\n' "This test cannot validate the SC1091 tolerance without it." >&2
   exit 1
fi
if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/), so
## an in-tree edit is what gets tested, not the installed copy.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/dist-ai-style"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
fi

test_dir="$(mktemp --directory)"
cleanup() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup EXIT

fail=0

## Build an isolated case dir holding a git repo at <case>/repo with FILE (repo-
## relative path, arg 1) carrying BODY (arg 2). When arg 3 is 'sibling', also create
## a PRESENT-but-empty <case>/helper-scripts/usr/libexec/helper-scripts/ (the CI
## layout), so a source= into it fails as a missing FILE, not an absent sibling.
## Commit an empty base + the fixture, run the real gate from the repo root over
## base...HEAD, leaving output in gate_output / rc in gate_rc.
gate_output=""
gate_rc=0
run_fixture() {
   local file="$1" body="$2" sibling="${3:-}" case repo
   case="$(mktemp --directory --tmpdir="${test_dir}" case.XXXXXX)"
   repo="${case}/repo"
   mkdir --parents -- "${repo}/$(dirname -- "${file}")"
   printf '%s' "${body}" >"${repo}/${file}"
   chmod 0755 -- "${repo}/${file}"
   if [ "${sibling}" = "sibling" ]; then
      mkdir --parents -- "${case}/helper-scripts/usr/libexec/helper-scripts"
   fi
   git -c init.defaultBranch=master -c core.hooksPath=/dev/null \
      init --quiet -- "${repo}"
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --allow-empty --message "base"
   local base_sha
   base_sha="$(git -C "${repo}" rev-parse HEAD)"
   git -C "${repo}" -c core.hooksPath=/dev/null add --all
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --message "fixture"
   gate_rc=0
   gate_output="$( cd -- "${repo}" && "${GATE}" --check --range "${base_sha}" 2>&1 )" \
      || gate_rc=$?
}

## Assert the current gate_output/gate_rc is GREEN with no SC1091 (arg 1 = label).
assert_green_no_sc1091() {
   local label="$1"
   if grep --quiet --fixed-strings 'SC1091' <<< "${gate_output}"; then
      printf '%s\n' "FAIL: ${label}: SC1091 raised (not tolerated)"
      grep --max-count=2 --fixed-strings 'SC1091' <<< "${gate_output}"; fail=1
   elif [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: ${label}: gate red (rc=${gate_rc}) on an otherwise-clean fixture"
      printf '%s\n' "${gate_output}" | tail -5; fail=1
   else
      printf '%s\n' "PASS: ${label}"
   fi
   if grep --quiet --fixed-strings 'shellcheck not on PATH' <<< "${gate_output}"; then
      printf '%s\n' "FAIL: ${label}: gate SKIPPED its shellcheck tier -- nothing tested"; fail=1
   fi
}

## Assert the current gate_output/gate_rc is RED with SC1091 (arg 1 = label).
assert_red_sc1091() {
   local label="$1"
   if grep --quiet --fixed-strings 'SC1091' <<< "${gate_output}" && [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "PASS: ${label}"
   else
      printf '%s\n' "FAIL: ${label}: expected SC1091 + red, got rc=${gate_rc}"
      printf '%s\n' "${gate_output}" | tail -5; fail=1
   fi
}

## Compliant preamble every fixture shares, so the ONLY verdict-moving thing is the
## source directive under test.
preamble="$(cat <<'PRE'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

PRE
)"

## A -- helper-scripts sibling source, sibling ABSENT -> tolerated (green).
run_fixture "bin/caller" "${preamble}
# shellcheck source=../../helper-scripts/usr/libexec/helper-scripts/log_run_die.sh
source \"\${HELPER_SCRIPTS_PATH:-}\"/usr/libexec/helper-scripts/log_run_die.sh

printf '%s\\n' \"ok\"
"
assert_green_no_sc1091 "A: absent helper-scripts sibling is tolerated"

## B -- a non-helper-scripts missing source -> fatal (red).
run_fixture "bin/caller" "${preamble}
# shellcheck source=../lib/does-not-exist.sh
source \"\${0%/*}\"/../lib/does-not-exist.sh

printf '%s\\n' \"ok\"
"
assert_red_sc1091 "B: a non-helper-scripts missing source stays fatal"

## C -- helper-scripts sibling PRESENT but the named file missing (CI layout / a
## typo) -> fatal (red). Guards that the drop is NOT inert-by-substring.
run_fixture "bin/caller" "${preamble}
# shellcheck source=../../helper-scripts/usr/libexec/helper-scripts/typo_no_such_file.sh
source \"\${HELPER_SCRIPTS_PATH:-}\"/usr/libexec/helper-scripts/typo_no_such_file.sh

printf '%s\\n' \"ok\"
" sibling
assert_red_sc1091 "C: a missing file under a PRESENT sibling stays fatal (CI parity)"

## D -- a bogus path that only CONTAINS the sibling substring but resolves under
## repo/lib -> fatal (red). Guards the anchored (not substring) match.
run_fixture "bin/caller" "${preamble}
# shellcheck source=../lib/decoy-helper-scripts/usr/libexec/helper-scripts/x.sh
source \"\${0%/*}\"/../lib/decoy-helper-scripts/usr/libexec/helper-scripts/x.sh

printf '%s\\n' \"ok\"
"
assert_red_sc1091 "D: a substring-only bogus path stays fatal (anchored match)"

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
