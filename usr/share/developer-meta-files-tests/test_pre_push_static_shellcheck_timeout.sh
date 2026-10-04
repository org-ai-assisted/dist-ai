#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-style's shellcheck tier: a file whose
## '# shellcheck source=' graph makes '--external-sources' following EXPLODE
## (the following is exponential -- a deep/branching source= graph hangs the
## gate for minutes). Without a per-subprocess cap the hang reaches the OUTER
## hook timeout, which FAILS OPEN -- the required gate silently stops gating.
##
## The fix bounds each shellcheck run (SHELLCHECK_TIMEOUT, env-overridable via
## DIST_AI_SHELLCHECK_TIMEOUT) and, on expiry, re-runs ONCE without following --
## bounded, so it cannot explode -- dropping the forced SC1091 'not following'
## infos while keeping every other finding, and emitting a VISIBLE note. So a
## hanging file degrades loudly instead of vanishing into a fail-open pass.
##
## Fixture, the real shipped gate driven as a subprocess under a SHORT outer
## 'timeout' with a small inner cap:
##   - a self-contained diamond source= graph (each level source=s the next
##     TWICE; no helper-scripts dependency) + a caller that sources its root.
##   OLD gate (no inner cap): shellcheck follows the graph unbounded -> the outer
##     'timeout' kills it -> rc 124 -> FAIL (0 fail = 0 coverage).
##   NEW gate: the inner cap fires fast -> no-following fallback -> the gate
##     returns promptly (rc != 124), GREEN (the graph is otherwise clean), with
##     the degrade note present.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has shellcheck ; then
   printf '%s\n' "FATAL: shellcheck not on PATH (apt-get install shellcheck)" >&2
   printf '%s\n' "This test cannot validate the follow-timeout fallback without it." >&2
   exit 1
fi
if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
if ! has timeout ; then
   printf '%s\n' "FATAL: timeout (coreutils) not on PATH" >&2
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

## Depth of the diamond source= graph. Each level source=s the next level TWICE,
## so '--external-sources' following re-expands the leaf 2**DEPTH times -- minutes
## of work, far past any outer hook cap. 18 is already pathological (the module
## comment measured >60s past four such sources); the margin over OUTER_TIMEOUT is
## what guarantees the OLD gate is still running when the outer 'timeout' kills it.
DEPTH=18
## Inner per-run cap handed to the gate. Small, so the NEW gate's fallback fires
## almost immediately.
INNER_TIMEOUT=1
## Outer wall-clock the test allows the whole gate. The NEW gate returns in ~a few
## seconds (inner cap + process overhead); the OLD gate hangs past this and is
## killed with rc 124. Comfortably between the two.
OUTER_TIMEOUT=15

## Build the self-contained diamond graph in a NON-repo dir (direct file mode
## reads the working tree; no git needed). Every file is shellcheck-clean on its
## own, so the ONLY verdict-moving factor is the follow explosion / fallback.
graph_dir="$(mktemp --directory --tmpdir="${test_dir}" graph.XXXXXX)"

## Leaf: clean, sources nothing.
printf '%s\n' '#!/bin/bash' 'true' >"${graph_dir}/level_${DEPTH}.sh"
## Intermediate levels: each source=s the next level twice (the branching that
## makes the following exponential).
level=$(( DEPTH - 1 ))
while [ "${level}" -ge 0 ]; do
   next=$(( level + 1 ))
   {
      printf '%s\n' '#!/bin/bash'
      printf '# shellcheck source=./level_%s.sh\n' "${next}"
      printf 'source "./level_%s.sh"\n' "${next}"
      printf '# shellcheck source=./level_%s.sh\n' "${next}"
      printf 'source "./level_%s.sh"\n' "${next}"
   } >"${graph_dir}/level_${level}.sh"
   level=$(( level - 1 ))
done

## The checked file: a fully style-compliant caller that sources the graph root.
## Only THIS file is gated by the non-shellcheck rules, so it carries the strict
## preamble; the graph levels are only FOLLOWED by shellcheck.
cat >"${graph_dir}/caller" <<'CALLER'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=./level_0.sh
source "./level_0.sh"

printf '%s\n' "ok"
CALLER
chmod 0755 -- "${graph_dir}/caller"

## Run the real gate on the caller under the outer wall-clock, with a small inner
## cap. 'timeout' exits 124 when it kills with SIGTERM, or 128+9=137 if --kill-after
## had to escalate to SIGKILL; either is the "did not finish in time" signature.
## Capture rc without tripping errexit.
gate_rc=0
gate_output="$( cd -- "${graph_dir}" \
   && DIST_AI_SHELLCHECK_TIMEOUT="${INNER_TIMEOUT}" \
      timeout --kill-after=5 "${OUTER_TIMEOUT}" "${GATE}" --check ./caller 2>&1 )" \
   || gate_rc=$?

gate_timed_out=0
if [ "${gate_rc}" -eq 124 ] || [ "${gate_rc}" -eq 137 ]; then
   gate_timed_out=1
fi

fail=0

## 1. The gate must NOT have been killed by the outer wall-clock. That is the
## OLD-gate signature (shellcheck followed the graph unbounded).
if [ "${gate_timed_out}" -ne 0 ]; then
   printf '%s\n' "FAIL: gate hung on the follow explosion (rc ${gate_rc}, killed by the ${OUTER_TIMEOUT}s outer cap) -- the inner cap did not fire"
   printf '%s\n' "${gate_output}" | tail -5
   fail=1
else
   printf '%s\n' "PASS: gate returned within ${OUTER_TIMEOUT}s (inner cap bounded the follow explosion)"
fi

## 2. The degrade must be VISIBLE -- never a silent pass.
if grep --quiet --fixed-strings 're-checked without following' <<< "${gate_output}"; then
   printf '%s\n' "PASS: the follow-timeout degrade is reported (visible note)"
else
   printf '%s\n' "FAIL: no visible degrade note -- a silent fallback is a silent pass"
   printf '%s\n' "${gate_output}" | tail -5
   fail=1
fi

## 3. The otherwise-clean graph must be GREEN (rc 0): after the fallback drops the
## forced SC1091 'not following', nothing real remains.
if [ "${gate_timed_out}" -eq 0 ] && [ "${gate_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: gate red (rc=${gate_rc}) on an otherwise-clean graph"
   printf '%s\n' "${gate_output}" | tail -10
   fail=1
elif [ "${gate_rc}" -eq 0 ]; then
   printf '%s\n' "PASS: otherwise-clean graph is green after the no-following fallback"
fi

## 4. The shellcheck tier must actually have run (an absent shellcheck would make
## the whole assertion vacuous -- a skip read as a pass).
if grep --quiet --fixed-strings 'shellcheck not on PATH' <<< "${gate_output}"; then
   printf '%s\n' "FAIL: gate SKIPPED its shellcheck tier -- nothing tested"
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
