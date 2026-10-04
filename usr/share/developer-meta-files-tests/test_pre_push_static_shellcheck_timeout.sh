#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-style's shellcheck tier timeout + forced-no-follow
## fallback.
##
## '--external-sources' following of a deep/branching '# shellcheck source=' graph
## is EXPONENTIAL and hangs the gate for minutes. Without a per-subprocess cap the
## hang reaches the OUTER hook timeout, which FAILS OPEN -- the required gate
## silently stops gating. The fix bounds each run (SHELLCHECK_TIMEOUT, env-
## overridable via DIST_AI_SHELLCHECK_TIMEOUT) and, on expiry, re-runs ONCE with
## following FORCED OFF, dropping the forced SC1091 'not following' infos while
## keeping every other finding and emitting a VISIBLE note.
##
## Cases (the real shipped gate driven as a subprocess):
##   1. Diamond source= graph, NO rcfile -- the gate must return promptly, green,
##      with the degrade note (OLD gate without a cap is killed by the outer
##      'timeout' -> rc 124/137 -> FAIL; 0 fail = 0 coverage).
##   2. SAME graph WITH a '.shellcheckrc' setting 'external-sources=true' -- the
##      fallback must STILL not follow (stripping the argv flag alone would let the
##      rcfile re-enable following and re-explode). Proves the forced-off rcfile.
##   3. DIST_AI_SHELLCHECK_TIMEOUT set to a bad value (nan/inf/0) on a CLEAN file --
##      the gate must fall back to the default, never crash (nan/inf) nor expire
##      every file (0).

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
## comment measured >60s past four such sources; depth 14 alone exceeds 20s on this
## hardware); the margin over OUTER_TIMEOUT is what guarantees the OLD gate is still
## running when the outer 'timeout' kills it.
DEPTH=18
## Inner per-run cap handed to the gate. Small, so the NEW gate's fallback fires
## almost immediately.
INNER_TIMEOUT=1
## Outer wall-clock the test allows the whole gate. The NEW gate returns in ~a few
## seconds (inner cap + process overhead); the OLD gate hangs past this and is
## killed. Comfortably between the two.
OUTER_TIMEOUT=15

fail=0

## Build the self-contained diamond graph + a style-compliant caller in DIR (a
## NON-repo dir; direct file mode reads the working tree, no git needed). Every file
## is shellcheck-clean on its own, so the only verdict-moving factor is the follow
## explosion / fallback.
build_graph() {
   local dir="$1" level next
   printf '%s\n' '#!/bin/bash' 'true' >"${dir}/level_${DEPTH}.sh"
   level=$(( DEPTH - 1 ))
   while [ "${level}" -ge 0 ]; do
      next=$(( level + 1 ))
      {
         printf '%s\n' '#!/bin/bash'
         printf '# shellcheck source=./level_%s.sh\n' "${next}"
         printf 'source "./level_%s.sh"\n' "${next}"
         printf '# shellcheck source=./level_%s.sh\n' "${next}"
         printf 'source "./level_%s.sh"\n' "${next}"
      } >"${dir}/level_${level}.sh"
      level=$(( level - 1 ))
   done
   cat >"${dir}/caller" <<'CALLER'
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
   chmod 0755 -- "${dir}/caller"
}

## Run the gate on <dir>/caller under the outer wall-clock with inner cap <inner>.
## Sets gate_rc, gate_output, gate_timed_out. 'timeout' exits 124 on SIGTERM-kill or
## 137 if --kill-after escalated to SIGKILL; either is "did not finish in time".
gate_rc=0
gate_output=""
gate_timed_out=0
run_gate() {
   local dir="$1" inner="$2"
   gate_rc=0
   gate_output="$( cd -- "${dir}" \
      && DIST_AI_SHELLCHECK_TIMEOUT="${inner}" \
         timeout --kill-after=5 "${OUTER_TIMEOUT}" "${GATE}" --check ./caller 2>&1 )" \
      || gate_rc=$?
   gate_timed_out=0
   if [ "${gate_rc}" -eq 124 ] || [ "${gate_rc}" -eq 137 ]; then
      gate_timed_out=1
   fi
}

## Assert the just-run gate degraded gracefully: not killed by the outer cap, degrade
## note present, green, shellcheck tier actually ran. Arg 1 = case label.
assert_graceful_degrade() {
   local label="$1"
   if [ "${gate_timed_out}" -ne 0 ]; then
      printf '%s\n' "FAIL: ${label}: gate hung (rc ${gate_rc}, killed by the ${OUTER_TIMEOUT}s outer cap) -- the fallback did not bound the follow"
      printf '%s\n' "${gate_output}" | tail -6; fail=1
   else
      printf '%s\n' "PASS: ${label}: gate returned within ${OUTER_TIMEOUT}s"
   fi
   if grep --quiet --fixed-strings 'cross-file source resolution' <<< "${gate_output}"; then
      printf '%s\n' "PASS: ${label}: the follow-timeout degrade is reported (visible note)"
   else
      printf '%s\n' "FAIL: ${label}: no visible degrade note -- a silent fallback is a silent pass"
      printf '%s\n' "${gate_output}" | tail -6; fail=1
   fi
   if [ "${gate_timed_out}" -eq 0 ] && [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: ${label}: gate red (rc=${gate_rc}) on an otherwise-clean graph"
      printf '%s\n' "${gate_output}" | tail -10; fail=1
   elif [ "${gate_rc}" -eq 0 ]; then
      printf '%s\n' "PASS: ${label}: otherwise-clean graph is green after the forced-no-follow fallback"
   fi
   if grep --quiet --fixed-strings 'shellcheck not on PATH' <<< "${gate_output}"; then
      printf '%s\n' "FAIL: ${label}: gate SKIPPED its shellcheck tier -- nothing tested"; fail=1
   fi
}

## Case 1: diamond graph, no rcfile.
graph_dir="$(mktemp --directory --tmpdir="${test_dir}" graph.XXXXXX)"
build_graph "${graph_dir}"
run_gate "${graph_dir}" "${INNER_TIMEOUT}"
assert_graceful_degrade "no-rcfile"

## Case 2: SAME graph, but a '.shellcheckrc' turns external-sources back ON. A
## fallback that only drops the argv flag would re-follow via this rcfile and
## re-explode (then fail CLOSED on its own cap). The forced-off rcfile must win, so
## this must degrade gracefully exactly like case 1.
rc_dir="$(mktemp --directory --tmpdir="${test_dir}" rcfile.XXXXXX)"
build_graph "${rc_dir}"
printf 'external-sources=true\n' >"${rc_dir}/.shellcheckrc"
run_gate "${rc_dir}" "${INNER_TIMEOUT}"
assert_graceful_degrade "rcfile-external-sources-true"

## Case 3: a bad DIST_AI_SHELLCHECK_TIMEOUT must be validated/clamped -- never crash
## the rule (nan/inf, and a huge finite value, all raise in subprocess.run) nor expire
## every file (0/negative). A value above the ceiling is clamped down (overrides may
## only LOWER the cap). Subject: a trivial, shellcheck-clean script.
clean_dir="$(mktemp --directory --tmpdir="${test_dir}" clean.XXXXXX)"
cat >"${clean_dir}/caller" <<'CLEAN'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

printf '%s\n' "ok"
CLEAN
chmod 0755 -- "${clean_dir}/caller"
## nan/inf: non-finite. 0/-1: non-positive. 2147483648/1e20: finite but too large
## for subprocess.run's C timeout (OverflowError) and above the outer-cap budget.
for bad in nan inf 0 -1 2147483648 1e20; do
   run_gate "${clean_dir}" "${bad}"
   if [ "${gate_rc}" -eq 0 ] \
      && ! grep --quiet --extended-regexp 'crashed|Traceback|timed out' <<< "${gate_output}"; then
      printf '%s\n' "PASS: bad-timeout '${bad}': clean file stays green (validated/clamped)"
   else
      printf '%s\n' "FAIL: bad-timeout '${bad}': clean file not green (rc=${gate_rc}) -- bad value not validated"
      printf '%s\n' "${gate_output}" | tail -6; fail=1
   fi
done

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
