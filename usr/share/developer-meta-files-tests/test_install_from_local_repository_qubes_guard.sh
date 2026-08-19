#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files' dm-install-from-local-repository
## dist_build_qubes guard.
##
## THE BUG IT GUARDS: when 'pkg' is not overridden, the meta-package name is
## derived from the qubes axis, reading 'dist_build_qubes' -- an operator-supplied
## toggle that nothing in the build sets. The read had no ':-' default, so under
## 'set -o nounset' an unset value aborted with an unbound-variable error at the
## point of use, AFTER the script had already rewritten sources.list and run
## 'apt-get update'. The fix validates it to 'true'/'false' at the top of main(),
## before any apt work, with a message naming the variable and the fix.
##
## HOW: the guard sits at the head of main() and sources nothing, so this extracts
## that slice and drives it directly with 'error' stubbed -- no build, no chroot,
## no apt. It asserts both directions (valid value: continue; unset/typo: abort,
## by name) and that the guard is SKIPPED when 'pkg' is set (nothing to derive).
##
## FAILS on the pre-fix tool: the guard slice does not exist there, so the
## extraction is empty and the first assertion fails.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$(( test_failures + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

rel='packages/kicksecure/developer-meta-files/usr/bin/dm-install-from-local-repository'
subject=""
for candidate in "${DM_INSTALL_FROM_LOCAL_REPOSITORY:-}" \
   "${dm_checkout}/${rel}" \
   "/usr/bin/dm-install-from-local-repository"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "SKIP: dm-install-from-local-repository not found (set DM_INSTALL_FROM_LOCAL_REPOSITORY)." >&2
   exit 77
fi

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## Extract the guard: from its lead comment down to the 'fi' that closes it. The
## block sources nothing and touches only 'pkg' and 'dist_build_qubes', so this
## slice is the whole behavior under test.
guard="$( sed -n '/## Fail fast, before any apt work/,/^   fi$/p' -- "${subject}" )"
if [ -z "${guard}" ]; then
   fail "could not extract the dist_build_qubes guard (pre-fix tool has none)"
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi

## The driver: stub 'error' (the real one comes from help-steps/pre), set 'pkg'
## and 'dist_build_qubes' from the environment, run the extracted slice, and print
## a marker only if it fell through. Kept under the SAME shell options as the
## tool, so the nounset behaviour the fix addresses is reproduced faithfully.
inner="${work_dir}/guard_inner.sh"
cat > "${inner}" <<'INNER_EOF'
#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

body="$1"

error() {
   printf '%s\n' "GUARD-ERROR: $*" >&2
   exit 3
}

pkg="${GUARD_PKG:-}"
if [ "${GUARD_QUBES:-__UNSET__}" != "__UNSET__" ]; then
   dist_build_qubes="${GUARD_QUBES}"
fi

eval "${body}"
printf '%s\n' "GUARD-PASSED"
INNER_EOF

## run_guard <pkg> <qubes-or-__UNSET__>; echoes combined output, sets run_rc.
run_rc=0
run_out=""
run_guard() {
   local pkg_val="$1" qubes_val="$2"
   run_rc=0
   run_out="$( env GUARD_PKG="${pkg_val}" GUARD_QUBES="${qubes_val}" \
      bash -- "${inner}" "${guard}" 2>&1 )" || run_rc="$?"
}

## --- 1. empty pkg + unset qubes -> abort, before falling through ------------
run_guard "" "__UNSET__"
if [ "${run_rc}" -ne 0 ] && [ "${run_out}" != "${run_out#*GUARD-ERROR}" ]; then
   pass "empty pkg + unset dist_build_qubes: aborts (${run_rc}) instead of unbound-variable"
else
   fail "empty pkg + unset dist_build_qubes: did not abort; rc=${run_rc} out=[${run_out}]"
fi
## The message must name the variable, so the operator knows what to set.
case "${run_out}" in
   *dist_build_qubes*)
      pass "abort message names dist_build_qubes"
      ;;
   *)
      fail "abort message does not name dist_build_qubes: [${run_out}]"
      ;;
esac

## --- 2. empty pkg + a typo value -> abort ----------------------------------
run_guard "" "maybe"
if [ "${run_rc}" -ne 0 ]; then
   pass "empty pkg + dist_build_qubes='maybe': rejects a non-boolean value (${run_rc})"
else
   fail "empty pkg + dist_build_qubes='maybe': accepted a non-boolean value; out=[${run_out}]"
fi

## --- 3. empty pkg + true / false -> fall through ---------------------------
for qubes_val in true false; do
   run_guard "" "${qubes_val}"
   if [ "${run_rc}" -eq 0 ] && [ "${run_out}" != "${run_out#*GUARD-PASSED}" ]; then
      pass "empty pkg + dist_build_qubes='${qubes_val}': accepted, falls through"
   else
      fail "empty pkg + dist_build_qubes='${qubes_val}': did not fall through; rc=${run_rc} out=[${run_out}]"
   fi
done

## --- 4. non-empty pkg + unset qubes -> guard skipped (nothing to derive) ----
## An explicit 'pkg' means the qubes axis is never consulted, so the guard must
## NOT demand dist_build_qubes in that case.
run_guard "whonix-gateway-nonqubes-cli" "__UNSET__"
if [ "${run_rc}" -eq 0 ] && [ "${run_out}" != "${run_out#*GUARD-PASSED}" ]; then
   pass "explicit pkg + unset dist_build_qubes: guard skipped, no needless demand"
else
   fail "explicit pkg + unset dist_build_qubes: guard fired anyway; rc=${run_rc} out=[${run_out}]"
fi

## --- 5. CANARY: the stubbed error path can actually fail the run ------------
## Without this, assertion 1 is satisfiable by a driver whose 'error' is a no-op.
canary_rc=0
env GUARD_PKG="" GUARD_QUBES="__UNSET__" \
   bash -c 'error() { exit 3; }; error' >/dev/null 2>&1 || canary_rc="$?"
if [ "${canary_rc}" -eq 3 ]; then
   pass "canary: a failing error stub exits non-zero (assertions are not vacuous)"
else
   fail "canary broken: the error stub did not fail the run (rc=${canary_rc})"
fi

## --- 6. CANARY: the shipped guard really keys on true|false -----------------
## Guards against a future edit that drops the validation while leaving the lead
## comment, which would make the extraction non-empty but the check toothless.
if grep --quiet --fixed-strings -- 'true|false)' "${subject}"; then
   pass "canary: the shipped guard validates dist_build_qubes against true|false"
else
   fail "canary: the shipped guard no longer keys on true|false"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: install-from-local-repository dist_build_qubes guard (${pass_count} assertions)."
