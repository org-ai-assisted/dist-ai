#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for sq_git_run's trust-root / policy-file scope in
## genmkfile make-helper-one.bsh.
##
## THE BUG: sq_git_run assigned 'sq_git_trust_root' and 'sq_git_policy_file'
## WITHOUT 'local', leaking them into the shell. 'make_git_verify' runs a
## commit-verify ('sq_git_run "HEAD"', which fell back to trust_root=HEAD) and
## then a tag-verify in the SAME shell; the leaked "HEAD" satisfied the
## tag-verify's '[ -n "${sq_git_trust_root:-}" ] ||' guard, so the tag was
## verified with trust-root=HEAD instead of the tag commit (wrong whenever
## make_skip_git_describe_output_check lets HEAD differ from the tag).
##
## The contract: sq_git_run must NOT leak these into the caller, trust-root
## precedence is explicit-2nd-arg > caller/env preset > HEAD, and an env-set
## sq_git_trust_root is still honored.
##
## Extracts the REAL sq_git_run (current text, no copy) and drives it with a
## recording 'sq-git' stub. No network, no sq-git install, no git repo.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Shared genmkfile library discovery + checkout capability gate (sibling suites
## source the same helper, so they cannot drift to different subjects/skips).
_common_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../dist-ai-tests-common"
[ -r "${_common_dir}/genmkfile-locate.bash" ] || _common_dir="/usr/share/dist-ai-tests-common"
# shellcheck source=../dist-ai-tests-common/genmkfile-locate.bash
source "${_common_dir}/genmkfile-locate.bash"
genmkfile_require_helper
# shellcheck disable=SC2154  ## set by genmkfile_require_helper in the sourced helper
helper_file="${genmkfile_helper_file}"

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup_handler EXIT

## Source the REAL helper WHOLE (sourced-only lib, was_executed-gated), so sq_git_run and
## every sibling it reaches are defined without running the CLI. A single-function sed cut
## silently drifts the moment the subject gains an intra-file dependency -- the
## extract-a-function anti-pattern dist-ai's CLAUDE.md forbids. The make_require/
## make_output_info stubs below are defined AFTER the source so they override the real ones.
# shellcheck disable=SC1090
source "${helper_file}"
if ! declare -F sq_git_run >/dev/null; then
   printf '%s\n' "ERROR: sq_git_run not defined after sourcing the helper." >&2
   exit 1
fi

## Recording 'sq-git' stub: dumps its argv where the test can read it.
stub_dir="${test_root}/bin"
mkdir --parents -- "${stub_dir}"
args_file="${test_root}/sq_git_args"
cat > "${stub_dir}/sq-git" <<EOF
#!/bin/bash
printf '%s\n' "\$*" > "${args_file}"
EOF
chmod --recursive -- +x "${stub_dir}/sq-git"
PATH="${stub_dir}:${PATH}"
export PATH

## Neutralise sq_git_run's non-recording dependencies (overrides the sourced helper's).
# shellcheck disable=SC2317
make_require() { :; }
# shellcheck disable=SC2317
make_output_info() { :; }

tests_total=0
tests_failed=0

pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; tests_failed=$((tests_failed + 1)); }

## sq_git_run must run in THIS shell (not a subshell) so a global leak would be
## observable; the stub returns 0, so errexit is safe.
recorded_trust_root() {
   ## Echo the token after '--trust-root' from the recorded argv.
   local a; a="$(cat -- "${args_file}")"
   printf '%s\n' "${a}" | sed -n 's/.*--trust-root \([^ ]*\).*/\1/p'
}

## 1) 'HEAD' path: trust-root HEAD, and NOTHING leaks into the caller.
tests_total=$((tests_total + 1))
unset sq_git_trust_root sq_git_policy_file 2>/dev/null || true
printf '%s' "" > "${args_file}"
sq_git_run "HEAD" || true
if [ "$(recorded_trust_root)" = "HEAD" ]; then
   pass "sq_git_run HEAD -> --trust-root HEAD"
else
   fail "sq_git_run HEAD -> --trust-root '$(recorded_trust_root)' (expected HEAD)"
fi

tests_total=$((tests_total + 1))
if [ -v sq_git_trust_root ] || [ -v sq_git_policy_file ]; then
   fail "sq_git_run leaked sq_git_trust_root/sq_git_policy_file into the caller scope"
else
   pass "sq_git_run does not leak trust-root/policy-file into the caller scope"
fi

## 2) explicit 2nd arg wins (a prior 'HEAD' verify cannot override it).
tests_total=$((tests_total + 1))
unset sq_git_trust_root sq_git_policy_file 2>/dev/null || true
printf '%s' "" > "${args_file}"
sq_git_run "refs/tags/v1" "commitABC" || true
if [ "$(recorded_trust_root)" = "commitABC" ]; then
   pass "sq_git_run <ref> commitABC -> --trust-root commitABC (2nd-arg precedence)"
else
   fail "sq_git_run <ref> commitABC -> --trust-root '$(recorded_trust_root)' (expected commitABC)"
fi

## 3) env preset is still honored when no 2nd arg is given.
tests_total=$((tests_total + 1))
unset sq_git_policy_file 2>/dev/null || true
sq_git_trust_root="envroot"
printf '%s' "" > "${args_file}"
sq_git_run "HEAD" || true
if [ "$(recorded_trust_root)" = "envroot" ]; then
   pass "env sq_git_trust_root honored -> --trust-root envroot"
else
   fail "env sq_git_trust_root -> --trust-root '$(recorded_trust_root)' (expected envroot)"
fi
unset sq_git_trust_root

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${tests_failed}/${tests_total} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: sq_git_run keeps trust-root/policy-file local and honors precedence (${tests_total} checks)."
