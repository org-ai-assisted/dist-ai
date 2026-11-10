#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: a *_test.sh case runs under 'set -o errexit' with an EXIT-trap
## 'cleanup' that removes its work dir. If that removal FAILS (a leftover
## undeletable path, an orphaned process, a transient rm error), errexit must NOT
## fire INSIDE the trap and flip an all-assertions-passed case to a non-zero exit:
## the suite runner keys on the case EXIT CODE, so it would mis-count the case as
## FAILED while the case printed '0 fail'. This was a real CI flake in
## try_wait_for_system_ready_test.sh (the one case leaving orphaned processes).
## The fix is '|| true' on every EXIT-trap cleanup removal.
##
## Proven by driving a REAL sibling case (range_arg_glob_test.sh -- fast,
## deterministic, whose only 'safe-rm' is in cleanup) under a PATH-injected
## 'safe-rm' that always fails: a GUARDED case still exits 0; the pre-fix,
## unguarded case exits non-zero. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
sibling="${test_dir}/range_arg_glob_test.sh"
if [ ! -x "${sibling}" ]; then
   printf '%s\n' "FATAL: sibling case not found/executable: '${sibling}'" >&2
   exit 1
fi

work="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}" || true; }
trap cleanup EXIT

## A 'safe-rm' that ALWAYS fails, shadowing the real one on PATH so the sibling's
## EXIT-trap cleanup hits a failing removal.
fail_safe_rm="${work}/safe-rm"
cat > "${fail_safe_rm}" <<'STUB'
#!/bin/bash
printf '%s\n' 'stub safe-rm: deliberate failure (regression fixture)' >&2
exit 1
STUB
chmod 0755 -- "${fail_safe_rm}"

pass_count=0
fail_count=0
ok() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: ${1}"
}
notok() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: ${1}" >&2
   [ -n "${2:-}" ] && printf '%s\n' "      ${2}" >&2
}

## Precondition: the sibling PASSES normally, so a later non-zero is attributable
## to the injected cleanup failure, not a broken sibling or an unwired environment.
normal_rc=0
"${sibling}" >/dev/null 2>&1 || normal_rc=$?
if [ "${normal_rc}" -ne 0 ]; then
   printf '%s\n' "FATAL: sibling '${sibling##*/}' does not pass normally (rc=${normal_rc}); cannot isolate the cleanup-failure contract." >&2
   exit 1
fi

## With a failing 'safe-rm' in the sibling's EXIT-trap cleanup, a GUARDED case
## still exits 0 (assertions passed; cleanup is best-effort). Pre-fix (unguarded)
## the failing removal fires errexit in the trap and the case exits non-zero.
inject_rc=0
PATH="${work}:${PATH}" "${sibling}" >/dev/null 2>&1 || inject_rc=$?
if [ "${inject_rc}" -eq 0 ]; then
   ok "passing case tolerates a failing EXIT-trap cleanup (exit 0)"
else
   notok "a failing cleanup flipped a passing case to a non-zero exit" "inject_rc=${inject_rc}"
fi

printf '%s\n' ""
printf '%s\n' "===== cleanup-failure-tolerated: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
