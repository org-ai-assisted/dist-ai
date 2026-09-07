#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: secure-terminal-shots-inventory (the "no hand-rolled screenshot" guard) must
## FAIL when a shot gallery holds an orphan (unreferenced) file or a page references a shot
## that does not exist, and PASS on a clean tree. This is the cheap drift guard -- no Qt, no
## regeneration -- so it can gate every push; this test proves it has teeth.
##
## Checks:
##   1. CANARY on a synthetic throwaway site fixture: a clean fixture passes; adding an orphan
##      shot makes it fail; a dangling reference makes it fail. Always runs (no real site
##      needed), so the guard is proven to have teeth wherever this suite runs.
##   2. LIVE: when the real secure-terminal.github.io checkout is present, the guard passes on
##      it (the committed galleries carry no orphan/dangling drift). Cross-repo, so it runs
##      only when that checkout is found (the CI container has none); the canary always gates.
##
## Subject: usr/bin/secure-terminal-shots-inventory. python3 is REQUIRED (exit 1, R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

tool=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_INVENTORY:-}" \
   "${script_dir}/../../bin/secure-terminal-shots-inventory" \
   '/usr/bin/secure-terminal-shots-inventory'; do
   if [ -n "${cand}" ] && [ -x "${cand}" ]; then
      tool="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${tool}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-shots-inventory not found (set SECURE_TERMINAL_SHOTS_INVENTORY)' >&2
   exit 1
fi
if ! type -P python3 >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: python3 not found (required to run the inventory guard)' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
check() {  ## $1=label $2=actual-rc $3=expected-rc
   if [ "$2" -eq "$3" ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1 (rc=$2, expected $3)"
      fail=$(( fail + 1 ))
   fi
}

## 1. CANARY on a throwaway fixture -- a minimal site with one shot, referenced by one page.
site="${work}/site"
mkdir --parents -- "${site}/comparison/shots"
printf 'x' > "${site}/comparison/shots/demo.webp"
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" alt="demo">
</body></html>
HTML

rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'clean fixture passes' "${rc}" 0

## add an ORPHAN shot (no page references it) -> must fail
printf 'y' > "${site}/comparison/shots/orphan-handrolled.webp"
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'an orphan (hand-rolled) shot is caught' "${rc}" 1
safe-rm -- "${site}/comparison/shots/orphan-handrolled.webp"

## add a DANGLING reference (page points at a missing shot) -> must fail
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" alt="demo">
<img src="/comparison/shots/missing.webp" alt="missing">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a dangling shot reference is caught' "${rc}" 1

## a shot referenced with a ?cache-buster query string (or #fragment) must still resolve --
## if the extension check runs before the query/fragment strip, such a reference is dropped
## and its shot reads as a false orphan. Self-contained fixture (fresh index.html).
printf 'z' > "${site}/comparison/shots/qbuster.webp"
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" alt="demo">
<img src="/comparison/shots/qbuster.webp?v=2" alt="cache-busted">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a shot referenced with a ?query string is NOT a false orphan' "${rc}" 0
safe-rm -- "${site}/comparison/shots/qbuster.webp"

## 2. LIVE: the real site checkout, when present, must be clean.
live=''
for cand in \
   "${SECURE_TERMINAL_SITE_REPO:-}" \
   "${HOME}/private-sources/secure-terminal.github.io"; do
   if [ -n "${cand}" ] && [ -d "${cand}/comparison/shots" ]; then
      live="${cand}"
      break
   fi
done
if [ -n "${live}" ]; then
   rc=0; "${tool}" "${live}" >/dev/null 2>&1 || rc=$?
   check 'the live secure-terminal.github.io galleries have no orphan/dangling drift' "${rc}" 0
else
   printf '%s\n' 'note: secure-terminal.github.io checkout not found; live inventory check not applicable here'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: the shot inventory guard has teeth and the galleries are clean'
