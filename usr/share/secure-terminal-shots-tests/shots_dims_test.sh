#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: secure-terminal-shots-dims (the pinned-dimension guard) must FAIL when a
## gallery <img> pins width/height that do not equal the referenced asset's intrinsic pixels,
## and PASS on a clean tree. The shots are 2x-rendered and the page pins the full intrinsic
## size; a re-capture that changes a window/board/chrome size makes every stale pin ship a
## wrong-aspect, layout-shifting <img>. This is the cheap drift guard (no Qt, no regen) that
## proves the on-page dimensions track the assets; this test proves it has teeth.
##
## Checks:
##   1. CANARY on a synthetic throwaway site with real (convert-generated) webp of known size:
##      correct pins pass; a wrong width/height fails; a partial pin (one axis) fails; an
##      unpinned or non-integer-pinned or non-gallery <img> is (correctly) not flagged. Always
##      runs, so the guard is proven to have teeth wherever this suite runs.
##   2. LIVE: when the real secure-terminal.github.io checkout is present, the guard passes on
##      it (its committed pins match the committed assets). Cross-repo, so it runs only when
##      that checkout is found (the CI container has none); the canary always gates.
##
## Subject: usr/bin/secure-terminal-shots-dims. python3 + ImageMagick (identify/convert) are
## REQUIRED (exit 1, R-220) -- both are declared package dependencies.

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
   "${SECURE_TERMINAL_SHOTS_DIMS:-}" \
   "${script_dir}/../../bin/secure-terminal-shots-dims" \
   '/usr/bin/secure-terminal-shots-dims'; do
   if [ -n "${cand}" ] && [ -x "${cand}" ]; then
      tool="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${tool}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-shots-dims not found (set SECURE_TERMINAL_SHOTS_DIMS)' >&2
   exit 1
fi
if ! type -P python3 >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: python3 not found (required to run the dims guard)' >&2
   exit 1
fi
if ! type -P identify >/dev/null 2>&1 || ! type -P convert >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: ImageMagick (identify + convert) not found (required to read/build shot dimensions)' >&2
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

## make a real webp of an exact intrinsic size (a solid fill; only its pixel dims matter).
mkshot() {  ## $1=path $2=WxH
   convert -size "$2" xc:steelblue "$1"
}

## 1. CANARY on a throwaway fixture -- one gallery shot with a KNOWN intrinsic size.
site="${work}/site"
mkdir --parents -- "${site}/comparison/shots"
mkshot "${site}/comparison/shots/demo.webp" 120x80

## correct pins (declared == intrinsic) -> clean.
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="120" height="80" alt="demo">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'correct pins pass' "${rc}" 0

## a WRONG height (off by 1px, the real drift class) -> must fail.
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="120" height="81" alt="demo">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a stale/wrong pinned dimension is caught' "${rc}" 1

## a WRONG width -> must fail.
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="240" height="80" alt="demo">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a wrong pinned width is caught' "${rc}" 1

## a PARTIAL pin (only one axis) -> must fail (still shifts layout; blinds the other axis).
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="120" alt="demo">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a partial (single-axis) pin is caught' "${rc}" 1

## an UNPINNED gallery <img> (no width/height) -> not this guard's concern -> pass.
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" alt="demo">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'an unpinned gallery image is not flagged' "${rc}" 0

## a NON-INTEGER dimension (responsive '100%') -> not a pixel pin -> pass (not flagged).
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="100%" height="auto" alt="demo">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a non-integer (responsive) dimension is not flagged' "${rc}" 0

## a NON-GALLERY <img> with wrong pins (a logo/favicon) -> out of scope -> pass.
mkshot "${site}/logo.webp" 64x64
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="120" height="80" alt="demo">
<img src="/logo.webp" width="999" height="999" alt="logo">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a non-gallery image with wrong pins is out of scope' "${rc}" 0
safe-rm -- "${site}/logo.webp"

## a MISMATCH reached via a ?cache-buster query string must still be caught (the query is
## stripped before the file lookup, matching the resolver the inventory guard shares).
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp?v=3" width="120" height="81" alt="cache-busted">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a mismatch behind a ?query string is caught' "${rc}" 1

## a dangling reference (missing file) is inventory's job, not this guard's -> pass here.
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="120" height="80" alt="demo">
<img src="/comparison/shots/missing.webp" width="10" height="10" alt="missing">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a dangling reference is not this guard (inventory owns it)' "${rc}" 0

## a DEGENERATE (broken ~1x1) gallery shot must be FLAGGED, never silently accepted -- a
## nothing-mapped capture trims to ~1x1, and a shipped 1x1 xterm.escape.webp once passed the
## guards because the pin was auto-set to the bogus 1x1. Flag it even when the pin "matches".
mkshot "${site}/comparison/shots/broken.webp" 1x1
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="120" height="80" alt="demo">
<img src="/comparison/shots/broken.webp" width="1" height="1" alt="degenerate">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a degenerate (1x1 broken) shot is flagged even when its pin matches' "${rc}" 1
safe-rm -- "${site}/comparison/shots/broken.webp"

## a DUPLICATE width -- the guard must judge the FIRST (what HTML5 lays out with), not dict-last.
mkshot "${site}/comparison/shots/dup.webp" 200x120
cat > "${site}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/dup.webp" width="999" width="200" height="120" alt="dup">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a duplicate width is judged by the FIRST value (HTML5), not the last' "${rc}" 1
safe-rm -- "${site}/comparison/shots/dup.webp"

## a pathological >4300-digit dimension must NOT crash the tool (CPython int() ValueError) --
## it is treated as 'not a pixel pin' (rc 0 here: no valid pinned gallery img), never rc 2.
big="$(printf '9%.0s' $(seq 1 5000))"
cat > "${site}/index.html" <<HTML
<!doctype html><html><body>
<img src="/comparison/shots/demo.webp" width="${big}" height="80" alt="huge">
</body></html>
HTML
rc=0; "${tool}" "${site}" >/dev/null 2>&1 || rc=$?
check 'a >4300-digit dimension does not crash the tool' "${rc}" 0

## --fix rewrites drifted + partial pins to intrinsic in place, and the guard is then clean.
## (This is what the capture driver runs after pulling fresh shots, so a re-capture cannot
## leave a stale pin.) A tag with correct pins and a non-gallery tag must be left untouched.
fixsite="${work}/fixsite"
mkdir --parents -- "${fixsite}/comparison/shots"
mkshot "${fixsite}/comparison/shots/a.webp" 200x120
mkshot "${fixsite}/comparison/shots/b.webp" 80x40
mkshot "${fixsite}/comparison/shots/c.webp" 300x150
mkshot "${fixsite}/logo.webp" 64x64
cat > "${fixsite}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/a.webp" width="200" height="99" loading="lazy" alt="mismatch">
<img src="/comparison/shots/b.webp" width="50" alt="partial">
<img src="/comparison/shots/c.webp" width="300" height="150" alt="already-correct">
<img src="/logo.webp" width="999" height="999" alt="non-gallery-left-alone">
</body></html>
HTML
rc=0; "${tool}" --fix "${fixsite}" >/dev/null 2>&1 || rc=$?
check '--fix exits 0' "${rc}" 0
rc=0; "${tool}" "${fixsite}" >/dev/null 2>&1 || rc=$?
check '--fix leaves the guard clean' "${rc}" 0
rc=0; grep --fixed-strings --quiet '<img src="/comparison/shots/a.webp" width="200" height="120"' "${fixsite}/index.html" || rc=1
check '--fix repins the mismatched height to intrinsic' "${rc}" 0
rc=0; grep --fixed-strings --quiet '<img src="/comparison/shots/b.webp" width="80" height="40"' "${fixsite}/index.html" || rc=1
check '--fix completes the partial pin with both axes' "${rc}" 0
rc=0; grep --fixed-strings --quiet '<img src="/logo.webp" width="999" height="999"' "${fixsite}/index.html" || rc=1
check '--fix leaves a non-gallery image untouched' "${rc}" 0

## --fix must NOT pin a degenerate shot to its bogus size (auto-pinning a 1x1 is exactly how the
## broken xterm.escape.webp slipped past the guard before); it must stay flagged for a human.
degsite="${work}/degsite"
mkdir --parents -- "${degsite}/comparison/shots"
mkshot "${degsite}/comparison/shots/broke.webp" 1x1
cat > "${degsite}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/comparison/shots/broke.webp" width="1500" height="300" alt="broken">
</body></html>
HTML
"${tool}" --fix "${degsite}" >/dev/null 2>&1 || true
if grep --fixed-strings --quiet 'width="1" height="1"' "${degsite}/index.html"; then rc=1; else rc=0; fi
check '--fix does not pin a degenerate shot to its bogus 1x1 size' "${rc}" 0
rc=0; "${tool}" "${degsite}" >/dev/null 2>&1 || rc=$?
check '--fix leaves the degenerate shot flagged for a human' "${rc}" 1

## --fix must not misread data-src/data-width look-alikes (the old \b-regex bug): a tag whose
## real src is a non-gallery placeholder + a data-src lazy-load target must be left UNTOUCHED.
dsite="${work}/dsite"
mkdir --parents -- "${dsite}/comparison/shots"
mkshot "${dsite}/comparison/shots/real.webp" 300x150
cat > "${dsite}/index.html" <<'HTML'
<!doctype html><html><body>
<img src="/placeholder.png" data-src="/comparison/shots/real.webp" width="10" height="10" alt="lazy">
</body></html>
HTML
"${tool}" --fix "${dsite}" >/dev/null 2>&1 || true
if grep --fixed-strings --quiet 'width="10" height="10"' "${dsite}/index.html"; then rc=0; else rc=1; fi
check '--fix does not misread data-src/data-width and corrupt an unrelated tag' "${rc}" 0

## --fix must not rewrite an <img> that lives inside an HTML comment (HTMLParser skips it).
csite="${work}/csite"
mkdir --parents -- "${csite}/comparison/shots"
mkshot "${csite}/comparison/shots/c.webp" 300x150
cat > "${csite}/index.html" <<'HTML'
<!doctype html><html><body>
<!-- <img src="/comparison/shots/c.webp" width="10" height="10"> -->
<img src="/comparison/shots/c.webp" width="300" height="150" alt="real">
</body></html>
HTML
"${tool}" --fix "${csite}" >/dev/null 2>&1 || true
if grep --fixed-strings --quiet 'width="10" height="10"' "${csite}/index.html"; then rc=0; else rc=1; fi
check '--fix leaves an <img> inside a comment untouched' "${rc}" 0

## --fix must repin a SINGLE-QUOTED pin (the old double-quote-only regex missed it -> guard stays red).
qsite="${work}/qsite"
mkdir --parents -- "${qsite}/comparison/shots"
mkshot "${qsite}/comparison/shots/q.webp" 300x150
cat > "${qsite}/index.html" <<'HTML'
<!doctype html><html><body>
<img src='/comparison/shots/q.webp' width='10' height='10' alt="single-quoted">
</body></html>
HTML
"${tool}" --fix "${qsite}" >/dev/null 2>&1 || true
rc=0; "${tool}" "${qsite}" >/dev/null 2>&1 || rc=$?
check '--fix repins a single-quoted pin (guard clean after)' "${rc}" 0

## 2. LIVE: the real site checkout, when present, must have matching pins.
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
   check 'the live secure-terminal.github.io pins match their assets' "${rc}" 0
else
   printf '%s\n' 'note: secure-terminal.github.io checkout not found; live dims check not applicable here'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: the shot dimension guard has teeth and the pins match the assets'
