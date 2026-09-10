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

locate_helper() {
   local candidate from_bin=''
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      from_bin="$(dirname -- "$(dirname -- "${GENMKFILE_BIN}")")/share/genmkfile/make-helper-one.bsh"
   fi
   for candidate in \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${from_bin}" \
      "${HOME:-}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"
   do
      [ -n "${candidate}" ] || continue
      case "${candidate}" in
         '/make-helper-one.bsh' )
            continue
            ;;
      esac
      if test -r "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! helper_file="$(locate_helper)"; then
   printf '%s\n' 'FATAL: make-helper-one.bsh not found (set GENMKFILE_SHARE).' >&2
   exit 1
fi

## Testing the installed copy (which drifts from the tree under review) reads as
## a confusing FAIL against code nobody is changing -- skip unless a checkout is
## wired.
if [ -z "${GENMKFILE_SHARE:-}" ] && [ -z "${GENMKFILE_BIN:-}" ] \
   && [ "${helper_file}" = "/usr/share/genmkfile/make-helper-one.bsh" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup_handler EXIT

## Extract only the function under test.
sed -n '/^sq_git_run() {/,/^}/p' -- "${helper_file}" > "${test_root}/fns.sh"
if ! grep --quiet '^sq_git_run() {' "${test_root}/fns.sh"; then
   printf '%s\n' "ERROR: could not extract sq_git_run." >&2
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

## Neutralise sq_git_run's non-recording dependencies.
# shellcheck disable=SC2317
make_require() { :; }
# shellcheck disable=SC2317
make_output_info() { :; }

# shellcheck disable=SC1091
source "${test_root}/fns.sh"

tests_total=0
tests_failed=0

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; tests_failed=$((tests_failed + 1)); }

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
printf '' > "${args_file}"
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
printf '' > "${args_file}"
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
printf '' > "${args_file}"
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
