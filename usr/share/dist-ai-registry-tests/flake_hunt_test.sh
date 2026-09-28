#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: dist-ai-flake-hunt must (1) exit 0 when every run of the command passes,
## (2) exit 1 and REPORT when a run fails (a flake caught), (3) reject usage errors with exit 2,
## and (4) stop early under --stop-on-fail. The whole tool exists to turn a rare intermittent
## failure into a reproducible one, so a tool that silently exited 0 on a failing command (or
## never detected one) would be worse than useless -- the canary below pins that it FAILS on a
## deterministically-flaky command.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
## usr/share/dist-ai-registry-tests -> repo root is three levels up (installed: '/').
repo="${DIST_AI_REPO:-${test_dir}/../../..}"
hunt="${repo}/usr/bin/dist-ai-flake-hunt"
[ -x "${hunt}" ] || { printf '%s\n' "FATAL: dist-ai-flake-hunt not found/executable: ${hunt}" >&2; exit 1; }

failures=0
pass() { printf '%s\n' "PASS: $*"; }
fail() { printf '%s\n' "FAIL: $*" >&2; failures=$(( failures + 1 )); }

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

## Run the hunter, capturing its combined output and exit code separately (never through a pipe,
## which would mask the code we are asserting on).
out=''
rc=0
run_hunt() {
   rc=0
   out="$("${hunt}" "$@" 2>&1)" || rc="$?"
}

## Substring test on the captured output WITHOUT a pipe: a `... | grep -q` would close the pipe
## early and, under pipefail, fail the writer -- and R-161 forbids it. `case` is pipe-free.
out_has() {
   case "${out}" in
      *"$1"*)
         return 0
         ;;
   esac
   return 1
}

## 1. Stable command -> exit 0, zero failures reported.
run_hunt --runs 5 -- true
if [ "${rc}" -eq 0 ] && out_has '0/5 run(s) FAILED'; then
   pass 'a passing command over 5 runs -> exit 0, "0/5 FAILED"'
else
   fail "a stable command did not report clean (rc=${rc}): ${out}"
fi

## 2. Always-failing command -> exit 1 and every run counted.
run_hunt --runs 4 --quiet -- false
if [ "${rc}" -eq 1 ] && out_has '4/4 run(s) FAILED'; then
   pass 'an always-failing command -> exit 1, "4/4 FAILED"'
else
   fail "an always-failing command was not caught (rc=${rc}): ${out}"
fi

## 3. CANARY: a DETERMINISTICALLY-flaky command (fails every other serial run via a counter) must
## be CAUGHT -- exit 1 with a non-zero failure count. A tool that reported 0 failures here would
## be the exact silent-pass this gate closes.
flaky="${work}/flaky.sh"
counter="${work}/count"
printf '%s' '0' > "${counter}"
## Quoted heredoc: the arithmetic is written LITERALLY into the generated script (it must expand
## when THAT script runs, not now). The counter path is passed as $1 so nothing needs interpolating.
cat > "${flaky}" <<'FLAKY_EOF'
#!/bin/bash
n=$(cat -- "$1")
printf '%s' "$(( n + 1 ))" > "$1"
## even invocation -> pass, odd -> fail: a fixed ~50% flake over a serial run
test $(( n % 2 )) -eq 0
FLAKY_EOF
chmod +x "${flaky}"
run_hunt --runs 6 --parallel 1 --quiet -- "${flaky}" "${counter}"
flaky_count="$(printf '%s' "${out}" | sed -n 's#.*: \([0-9]\+\)/6 run(s) FAILED.*#\1#p')"
if [ "${rc}" -eq 1 ] && [ -n "${flaky_count}" ] && [ "${flaky_count}" -ge 1 ] && [ "${flaky_count}" -le 5 ]; then
   pass "a deterministically-flaky command is caught (${flaky_count}/6 failed, exit 1)"
else
   fail "canary: a flaky command was NOT caught (rc=${rc}, count='${flaky_count}'): ${out}"
fi

## 4. --stop-on-fail halts at the first failure rather than running all 50.
run_hunt --runs 50 --stop-on-fail --quiet -- false
if [ "${rc}" -eq 1 ] && out_has '1/1 run(s) FAILED'; then
   pass '--stop-on-fail halts at the first failing run ("1/1")'
else
   fail "--stop-on-fail did not halt early (rc=${rc}): ${out}"
fi

## 5. Usage errors -> exit 2 (not 0, not 1): no command, and non-numeric / zero counts.
run_hunt --runs 5 --
if [ "${rc}" -eq 2 ]; then
   pass 'no command -> exit 2'
else
   fail "a missing command did not exit 2 (rc=${rc})"
fi
run_hunt --runs 0 -- true
if [ "${rc}" -eq 2 ]; then
   pass '--runs 0 -> exit 2'
else
   fail "--runs 0 did not exit 2 (rc=${rc})"
fi
run_hunt --parallel x -- true
if [ "${rc}" -eq 2 ]; then
   pass '--parallel non-integer -> exit 2'
else
   fail "--parallel non-integer did not exit 2 (rc=${rc})"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: dist-ai-flake-hunt has ${failures} defect(s)" >&2
   exit 1
fi
printf '%s\n' 'OK: dist-ai-flake-hunt detects flakes, reports counts, and rejects misuse'
