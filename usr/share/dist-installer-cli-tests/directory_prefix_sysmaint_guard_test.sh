#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for directory_prefix_target_user_default_test.sh's invoker guard: the
## bug it reproduces (target-home default) only manifested under a non-sysmaint
## invoker, so a run UNDER sysmaint would pass Scenario 1 vacuously. The guard must
## therefore SKIP (exit 78) a sysmaint invoker, exactly as it skips root. Drive the
## REAL guarded test with a PATH 'id' stub that reports the invoker as sysmaint (the
## same PATH-stub idiom that test already uses) and a minimal readable standalone so
## the guard is reached, then assert it exits 78. Canary: the pre-fix guard checked
## root only, so under a sysmaint invoker it did NOT exit 78.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
guarded="${test_dir}/directory_prefix_target_user_default_test.sh"
if [ ! -r "${guarded}" ]; then
   printf '%s\n' "FATAL: guarded test not found: ${guarded}" >&2
   exit 1
fi

work="$(mktemp --directory --tmpdir dpx-sysmaint-guard.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## Minimal readable standalone so the guarded test passes its target-absent (77)
## check and reaches the invoker guard; its body is never executed (the guard fires
## first), so an empty file suffices.
fake_repo="${work}/usability-misc"
mkdir --parents -- "${fake_repo}/usr/share/usability-misc"
touch -- "${fake_repo}/usr/share/usability-misc/dist-installer-cli-standalone"

## PATH 'id' stub: report the invoker name as sysmaint AND a nonzero uid, delegating
## every other query to the real coreutils id. The nonzero uid is load-bearing: if the
## suite runs as ROOT, a real 'id -u' of 0 would trip the guard's ROOT branch first and
## exit 78 regardless of the sysmaint clause -- the regression would then pass even with
## the sysmaint clause removed (vacuous). Forcing a nonzero uid makes the exit 78 come
## ONLY from the sysmaint clause this test guards.
stub_bin="${work}/bin"
mkdir --parents -- "${stub_bin}"
# shellcheck disable=SC2016  # these are the GENERATED stub's literals, not expanded here
printf '%s\n' \
   '#!/bin/bash' \
   'if [ "$1" = "-un" ]; then' \
   '   printf "%s\n" sysmaint' \
   '   exit 0' \
   'fi' \
   'if [ "$1" = "-u" ]; then' \
   '   printf "%s\n" 1000' \
   '   exit 0' \
   'fi' \
   'exec /usr/bin/id "$@"' \
   > "${stub_bin}/id"
chmod +x "${stub_bin}/id"

rc=0
USABILITY_MISC_REPO="${fake_repo}" PATH="${stub_bin}:${PATH}" \
   bash -- "${guarded}" >/dev/null 2>&1 || rc=$?

pass=0
fail=0
if [ "${rc}" -eq 78 ]; then
   printf 'PASS: a sysmaint invoker is skipped (exit 78)\n'
   pass=$((pass + 1))
else
   printf 'FAIL: a sysmaint invoker was not skipped (got exit %s, want 78)\n' "${rc}" >&2
   fail=$((fail + 1))
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
