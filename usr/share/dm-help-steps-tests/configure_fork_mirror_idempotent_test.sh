#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'ci/configure-fork-mirror'.
##
## THE BUG IT GUARDS: the helper installs url.<org>.insteadOf rewrites and runs
## MORE THAN ONCE per CI job -- dist-ai's test-config helper calls it, then the
## workflow step calls it again. When both mirror args are the same org (the CI
## case: REPOSITORY_OWNER twice), both rewrites land under ONE git config key, so
## a plain 'git config' set on a second run hits an already-multivalued key and
## dies "cannot overwrite multiple values with a single value" (exit 5), failing
## the whole dist-ai-tests job before a single test runs. The fix makes the helper
## idempotent (--replace-all with a per-value regex). This test drives the SHIPPED
## script twice and fails if idempotency regresses.
##
## Isolated GIT_CONFIG_GLOBAL, so the caller's ~/.gitconfig is never touched.
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

subject_tree="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
helper="${subject_tree}/ci/configure-fork-mirror"
if [ ! -x "${helper}" ]; then
   printf '%s\n' "FATAL: ci/configure-fork-mirror not executable at ${helper}" >&2
   printf '%s\n' "set DERIVATIVE_MAKER_DIR if the checkout lives elsewhere." >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Run the helper against a throwaway global config; return its exit status.
run_helper() {
   local cfg="$1" kick="$2" whonix="$3" status=0
   GIT_CONFIG_GLOBAL="${cfg}" "${helper}" "${kick}" "${whonix}" >/dev/null 2>&1 || status="$?"
   printf '%s' "${status}"
}

count_values() {
   local cfg="$1" key="$2"
   GIT_CONFIG_GLOBAL="${cfg}" git config --global --get-all "${key}" 2>/dev/null | wc --lines
}

## --- same org twice: the CI invocation, and the one that regressed -----------
## git config --global creates GIT_CONFIG_GLOBAL on first write; the fresh
## mktemp dir means each file starts absent, so no pre-truncation is needed.
same_cfg="${work_dir}/same.gitconfig"
same_key='url.https://github.com/org-ai-assisted/.insteadOf'

r1="$( run_helper "${same_cfg}" org-ai-assisted org-ai-assisted )"
r2="$( run_helper "${same_cfg}" org-ai-assisted org-ai-assisted )"
if [ "${r1}" -eq 0 ] && [ "${r2}" -eq 0 ]; then
   pass 'same-org helper is re-runnable (both invocations exit 0)'
else
   fail "same-org re-run failed: run1=${r1} run2=${r2} (the exit-5 multivalue regression)"
fi

## Exactly the two upstream rewrites survive under the shared key, no duplicates.
same_n="$( count_values "${same_cfg}" "${same_key}" )"
if [ "${same_n}" -eq 2 ]; then
   pass 'same-org key holds exactly the two rewrites after repeated runs'
else
   fail "same-org key has ${same_n} values after two runs, expected 2"
fi
same_all="$( GIT_CONFIG_GLOBAL="${same_cfg}" git config --global --get-all "${same_key}" )"
if [[ "${same_all}" == *'https://github.com/Kicksecure/'* ]] \
   && [[ "${same_all}" == *'https://github.com/Whonix/'* ]]; then
   pass 'both Kicksecure/ and Whonix/ rewrites are present'
else
   fail 'a rewrite went missing under the shared key'
fi

## --- distinct orgs twice: keys differ, must not accumulate duplicates --------
diff_cfg="${work_dir}/diff.gitconfig"
d1="$( run_helper "${diff_cfg}" kick-mirror whonix-mirror )"
d2="$( run_helper "${diff_cfg}" kick-mirror whonix-mirror )"
kick_n="$( count_values "${diff_cfg}" 'url.https://github.com/kick-mirror/.insteadOf' )"
whonix_n="$( count_values "${diff_cfg}" 'url.https://github.com/whonix-mirror/.insteadOf' )"
if [ "${d1}" -eq 0 ] && [ "${d2}" -eq 0 ] && [ "${kick_n}" -eq 1 ] && [ "${whonix_n}" -eq 1 ]; then
   pass 'distinct-org keys hold one value each after repeated runs (no duplicate accumulation)'
else
   fail "distinct-org re-run: run1=${d1} run2=${d2} kick=${kick_n} whonix=${whonix_n}, expected 0 0 1 1"
fi

## --- CANARY: the harness can fail at all -------------------------------------
status=0
GIT_CONFIG_GLOBAL="${work_dir}/canary.gitconfig" "${helper}" >/dev/null 2>&1 || status="$?"
if [ "${status}" -ne 0 ]; then
   pass 'canary: helper with no arguments exits non-zero'
else
   fail 'canary broken: helper exits 0 with no arguments'
fi

printf '%s\n' "===== configure-fork-mirror: ${pass_count} pass, ${fail_count} fail ====="
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
