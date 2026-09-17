#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-style's shellcheck tier: a '# shellcheck source='
## directive into the helper-scripts SIBLING repo cannot be FOLLOWED on a dev
## host (no local helper-scripts checkout; the installed /usr/libexec/helper-scripts
## is a flat runtime layout, not the repo tree the directive names). CI checks the
## sibling out and follows it; reproducing that locally is not viable because
## shellcheck's '--external-sources' following of the deep helper-scripts graph is
## exponential and hangs the gate. So the gate DROPS the info-level SC1091 for that
## absent sibling and reaches the same verdict CI does -- while keeping SC1091 for
## ANY OTHER missing source fatal (a genuinely broken helper-scripts path still
## fails in CI, where the sibling is present).
##
## Two fixtures, the real shipped gate driven as a subprocess:
##   A -- a compliant script sourcing helper-scripts via the sibling directive:
##        the gate must be GREEN (this FAILS on the pre-fix gate: SC1091 -> red).
##   B -- a script sourcing a NON-helper-scripts path that does not exist: the gate
##        must be RED (the tolerance is narrow, not a blanket SC1091 suppression).

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

## Build a fixture repo containing FILE (repo-relative path, arg 1) with BODY
## (arg 2), commit an empty base + the fixture, run the real gate from the repo
## root over base...HEAD, and leave the output in gate_output / rc in gate_rc.
gate_output=""
gate_rc=0
run_fixture() {
   local file="$1" body="$2" repo
   repo="$(mktemp --directory --tmpdir="${test_dir}" repo.XXXXXX)"
   mkdir --parents -- "${repo}/$(dirname -- "${file}")"
   printf '%s' "${body}" >"${repo}/${file}"
   chmod 0755 -- "${repo}/${file}"
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

## The compliant preamble every fixture script shares (strict mode + LC_ALL), so
## the ONLY thing that can move the verdict is the source directive under test.
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

## --- Fixture A: a helper-scripts sibling source that cannot resolve locally ----
## The directive names the repo-tree helper-scripts path; from bin/ it climbs to a
## sibling that does not exist in this fixture -> SC1091. The gate must tolerate it.
caller_a="${preamble}
# shellcheck source=../../helper-scripts/usr/libexec/helper-scripts/log_run_die.sh
source \"\${HELPER_SCRIPTS_PATH:-}\"/usr/libexec/helper-scripts/log_run_die.sh

printf '%s\\n' \"ok\"
"
run_fixture "bin/caller" "${caller_a}"

if grep --quiet --fixed-strings 'SC1091' <<< "${gate_output}"; then
   printf '%s\n' "FAIL: the absent helper-scripts source= raised SC1091 (not tolerated)"
   grep --max-count=2 --fixed-strings 'SC1091' <<< "${gate_output}"
   fail=1
else
   printf '%s\n' "PASS: SC1091 for the absent helper-scripts sibling is tolerated"
fi
if [ "${gate_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: the gate is red on a fixture whose only issue is the absent sibling (rc=${gate_rc})"
   printf '%s\n' "${gate_output}" | tail -5
   fail=1
else
   printf '%s\n' "PASS: the gate is green when the only finding is the absent helper-scripts sibling"
fi
if grep --quiet --fixed-strings 'shellcheck not on PATH' <<< "${gate_output}"; then
   printf '%s\n' "FAIL: the gate SKIPPED its shellcheck tier -- nothing was tested"
   fail=1
fi

## --- Fixture B: a NON-helper-scripts absent source must still fail -------------
## Proves the tolerance is scoped to the helper-scripts sibling, not a blanket
## SC1091 suppression: a plainly broken source path is still a hard failure.
caller_b="${preamble}
# shellcheck source=../lib/does-not-exist.sh
source \"\${0%/*}\"/../lib/does-not-exist.sh

printf '%s\\n' \"ok\"
"
run_fixture "bin/caller" "${caller_b}"

if grep --quiet --fixed-strings 'SC1091' <<< "${gate_output}" && [ "${gate_rc}" -ne 0 ]; then
   printf '%s\n' "PASS: a non-helper-scripts missing source still fails (SC1091, gate red)"
else
   printf '%s\n' "FAIL: a non-helper-scripts missing source was wrongly tolerated (rc=${gate_rc})"
   printf '%s\n' "${gate_output}" | tail -5
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
