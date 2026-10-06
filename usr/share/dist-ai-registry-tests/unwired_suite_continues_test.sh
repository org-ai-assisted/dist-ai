#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: an UNWIRED suite (one in the run set with no wire() case) must fail
## JUST that suite and let the run CONTINUE -- never abort the whole run. Without the
## guard, wire()'s default 'return 1' under the orchestrator's errexit kills every
## remaining suite over one unwired entry -- so a suite registered a beat before its
## wire case lands (a brief window during a concurrent edit) takes the whole run down.
##
## Drives the REAL run_suite() extracted from the shipped orchestrator (no copy, no
## drift), with wire() stubbed to return 1 (simulating an unwired suite). Asserts
## run_suite returns 0 (so the caller's loop continues), marks the suite UNWIRED,
## increments fail_count, and does NOT execute the suite body (wire failed first).
##
## Canary: re-derives run_suite with the guard removed (the old bare 'wire "${suite}"')
## and asserts THAT form aborts under errexit -- proving the guard is load-bearing.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
orch="${test_dir}/../../bin/dist-ai-tests-all"
if [ ! -r "${orch}" ]; then
   orch='/usr/bin/dist-ai-tests-all'
fi
if [ ! -r "${orch}" ]; then
   printf '%s\n' 'FATAL: unwired_suite_continues_test: dist-ai-tests-all not found' >&2
   exit 1
fi

## Extract the real run_suite() -- from its header to the first column-0 '}'.
run_suite_src="$(awk '
   /^run_suite\(\) \{/ { f = 1 }
   f { print }
   f && /^\}$/ { exit }
' "${orch}")"
if [ -z "${run_suite_src}" ]; then
   printf '%s\n' 'FATAL: could not extract run_suite() from dist-ai-tests-all' >&2
   exit 1
fi

work="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## The orchestrator globals/functions run_suite reads. The UNWIRED path returns
## before touching most of them; declare the rest so nounset cannot trip.
mydir="${work}/bin"
log_dir="${work}/logs"
mkdir --parents -- "${mydir}" "${log_dir}"
## Read across the eval'd run_suite via dynamic scope; shellcheck cannot see the
## use through the eval, hence the disables.
# shellcheck disable=SC2034
declare -A suite_elapsed_map=()
# shellcheck disable=SC2034
wire_env=()
# shellcheck disable=SC2034
wire_args=()

## A present, executable entry so run_suite reaches the wire call (an absent entry
## would short-circuit to MISSING before wire). Executing it drops a marker, so the
## test can assert the body was NOT run when wiring failed.
suite='fake-unwired-suite'
cat > "${mydir}/${suite}" <<STUB
#!/bin/bash
printf '%s' x > "${work}/suite-body-ran"
STUB
chmod +x -- "${mydir}/${suite}"

## Capture emit()'s lines so the UNWIRED verdict can be asserted.
emit() {
   printf '%s\n' "$*" >> "${work}/emitted"
}
## wire() stubbed to fail, exactly as the real default 'no wiring' case does.
wire() {
   printf '%s\n' "stub wire: no wiring for ${1}" >&2
   return 1
}
## Not reached on the UNWIRED path, but defined so an accidental reach fails loudly
## rather than erroring on an unbound command.
skip_is_fatal() {
   return 1
}

## ---- Main: the REAL (guarded) run_suite continues on an unwired suite. ----
eval "${run_suite_src}"

printf '%s' '' > "${work}/emitted"
fail_count=0
pass_count=0
# shellcheck disable=SC2034  # read across the eval'd run_suite via dynamic scope
skip_count=0
rc=0
run_suite "${suite}" 'core' 10 || rc=$?

check "run_suite returns 0 on an unwired suite (loop continues)" "${rc}" '0'
check "unwired suite counts as a failure" "${fail_count}" '1'
check "unwired suite does NOT count as a pass" "${pass_count}" '0'

if grep --quiet -- "UNWIRED" "${work}/emitted"; then
   check "run_suite emits an UNWIRED verdict" 'yes' 'yes'
else
   check "run_suite emits an UNWIRED verdict" "$(cat -- "${work}/emitted")" 'UNWIRED'
fi

if [ -e "${work}/suite-body-ran" ]; then
   check "suite body is NOT executed when wiring failed" 'ran' 'not-run'
else
   check "suite body is NOT executed when wiring failed" 'not-run' 'not-run'
fi

## ---- Canary: the OLD bare-wire form aborts the run under errexit. ----
## Re-derive run_suite with the guard collapsed back to a bare 'wire "${suite}"'.
## Fixed-string match (index/==) not regex: the guard text is full of {, }, $, !,
## ? metacharacters -- a literal compare cannot misfire on them. Replace the whole
## 'if ! wire ...; then ... fi' block with the old bare 'wire "${suite}"'.
bare_body="$(printf '%s\n' "${run_suite_src}" | awk '
   index($0, "if ! wire \"${suite}\"; then") { print "   wire \"${suite}\""; skip = 1; next }
   skip && $0 == "   fi"                      { skip = 0; next }
   skip                                       { next }
                                              { print }
')"
if [ "${bare_body}" = "${run_suite_src}" ]; then
   printf '%s\n' 'FATAL: canary could not strip the wire guard (the guard text changed?)' >&2
   exit 1
fi

## Run the bare-wire run_suite in a SEPARATE bash process under errexit, NOT a
## subshell: a subshell whose exit is captured with '||' runs with its own errexit
## SUPPRESSED (the left-of-|| rule reaches into it), and toggling errexit off in the
## parent is forbidden (R-011). A child process keeps its own 'set -e' fully honored,
## and capturing its exit with '||' is safe because it is a distinct process. The
## bare wire failure must abort the child BEFORE it writes the post-call marker.
canary_script="${work}/canary.sh"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'set -o errexit'
   printf '%s\n' 'set -o nounset'
   printf 'mydir=%q\n'   "${mydir}"
   printf 'log_dir=%q\n' "${log_dir}"
   printf 'work=%q\n'    "${work}"
   printf '%s\n' 'declare -A suite_elapsed_map=()'
   printf '%s\n' 'wire_env=()'
   printf '%s\n' 'wire_args=()'
   printf '%s\n' 'fail_count=0'
   printf '%s\n' 'pass_count=0'
   printf '%s\n' 'skip_count=0'
   printf '%s\n' 'emit() { printf "%s\n" "$*" >&2; }'
   printf '%s\n' 'wire() { return 1; }'
   printf '%s\n' 'skip_is_fatal() { return 1; }'
   printf '%s\n' "${bare_body}"
   printf '%s\n' "run_suite \"${suite}\" 'core' 10"
   ## '${work}' is deliberately unexpanded here: it is CHILD-script source that the
   ## child expands against its own 'work=...' line, not a parent expansion.
   # shellcheck disable=SC2016
   printf '%s\n' 'printf "%s" reached > "${work}/canary-reached"'
} > "${canary_script}"

canary_reached='no'
## '|| true' here governs the PARENT, not the child's -e, so it is safe.
bash "${canary_script}" >/dev/null 2>&1 || true
if [ -e "${work}/canary-reached" ]; then
   canary_reached='yes'
fi
check "CANARY: bare 'wire' form aborts under errexit (guard is load-bearing)" \
   "${canary_reached}" 'no'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
