#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Hostile-input test for dm-packages-html-generator. It builds a synthetic
## reprepro tree whose package metadata is written by an attacker, runs the real
## generator against it, and asserts the published HTML is inert.
##
## The generator turns Packages/Sources indices into the HTML served at
## packages.whonix.org. Every rendered field (Description, Maintainer, Homepage,
## Vcs-Browser, Package) comes from package control metadata, so a malicious or
## compromised upload controls it. Three defects this pins were live at once:
##
##   - Jinja2 autoescape was OFF on every page, because
##     select_autoescape(["html"]) matches the FINAL filename extension and the
##     templates are named '*.html.j2'. Nothing was ever escaped.
##   - Homepage/Vcs-Browser reached an href unvalidated, so a 'javascript:' URI
##     executed on click. Escaping does not stop that; entities are decoded
##     before the URI is dereferenced.
##   - Package names reached output paths unvalidated, and pathlib does not
##     sanitize, so 'Package: /tmp' wrote outside --output entirely.
##
## Also pins two rendering bugs that made the page contradict the control file:
## Files/Checksums rows are a Mapping but not a dict subclass (an isinstance
## check on dict dropped every row), and ArchRestriction field 0 is 'enabled',
## not 'negated', so '[amd64 !i386]' published as '[!amd64 i386]'.
##
## No root, no network; writes only under its own temp dir:
##   ./test_dm_packages_html_generator.sh

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_failures=0
work_dir=''

pass() {
   printf '%s\n' "PASS: $*"
}

fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

## Fail closed. A missing prerequisite is an environment defect: skipping on
## it turns a test that never ran into a green result, which is worse than no
## test at all.
assert_prerequisite() {
   local description

   description="$1"
   shift

   if ! "$@"; then
      printf '%s\n' "FATAL: ${description}" >&2
      exit 1
   fi
}

cleanup() {
   if [ -n "${work_dir}" ] && [ -d "${work_dir}" ]; then
      safe-rm --recursive --force -- "${work_dir}"
   fi
}

assert_prerequisite \
   'helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)' \
   test -r '/usr/libexec/helper-scripts/has.sh'
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

assert_prerequisite 'safe-rm not found' has safe-rm

## Locate the generator: the installed binary, else the checkout the
## entrypoint points at, else a developer-meta-files checkout inside a
## derivative-maker source tree.
locate_generator() {
   local candidate source_dir

   if has dm-packages-html-generator; then
      printf '%s\n' 'dm-packages-html-generator'
      return 0
   fi

   ## CI checks the component out standalone, so DMF_REPO is the checkout
   ## root itself and no derivative-maker tree exists around it.
   if [ -n "${DMF_REPO:-}" ]; then
      candidate="${DMF_REPO}/usr/bin/dm-packages-html-generator"
      if [ -x "${candidate}" ]; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   fi

   source_dir="${DM_SOURCE_DIR:-${HOME}/derivative-maker}"
   candidate="${source_dir}/packages/kicksecure/developer-meta-files/usr/bin/dm-packages-html-generator"
   if [ -x "${candidate}" ]; then
      printf '%s\n' "${candidate}"
      return 0
   fi

   printf '%s\n' ''
}

generator="$(locate_generator)"
assert_prerequisite \
   'dm-packages-html-generator not found, neither installed nor under DM_SOURCE_DIR' \
   test -n "${generator}"

## The generator is present, so its declared runtime dependencies must be too.
## A missing dependency here is a packaging defect.
if ! python3 -c 'import debian.deb822, jinja2' >/dev/null 2>&1; then
   printf '%s\n' \
      'test_dm_packages_html_generator: python3-debian / python3-jinja2 missing, but the generator is installed; that is a broken dependency declaration.' >&2
   exit 1
fi

trap cleanup EXIT

work_dir="$(mktemp --directory)"
readonly repo_dir="${work_dir}/repo"
readonly out_dir="${work_dir}/site"
readonly canary="${work_dir}/CANARY-ESCAPED"
readonly binary_dir="${repo_dir}/dists/trixie/main/binary-amd64"
readonly source_dir_path="${repo_dir}/dists/trixie/main/source"

mkdir --parents -- "${binary_dir}" "${source_dir_path}"
printf '%s\n' 'Suite: trixie' > "${repo_dir}/dists/trixie/Release"

## A well-formed package carrying hostile field values. The hostile package
## NAMES go in a second run below: unvalidated names abort the run outright,
## which would otherwise mask every rendering assertion.
printf '%s\n' \
'Package: good-package' \
'Version: 1:2.0~rc1-1' \
'Architecture: all' \
'Maintainer: Evil <img src=x onerror="alert(1)">' \
'Homepage: javascript:alert(document.domain)' \
'Description: Summary <img src=x onerror="alert(2)">' \
' Long body line.' \
'Depends: dpkg <!nocheck>, libc6 [amd64 !i386]' \
'Filename: pool/main/g/good.deb' \
   | gzip --stdout > "${binary_dir}/Packages.gz"

printf '%s\n' \
'Package: good-package' \
'Version: 1:2.0~rc1-1' \
'Vcs-Browser: javascript:alert(3)' \
'Binary: good-package' \
'Build-Depends: debhelper <!nocheck>' \
'Checksums-Sha256:' \
' aaaa 100 good_1.0.orig.tar.gz' \
' bbbb 200 good_1.0.debian.tar.xz' \
   | gzip --stdout > "${source_dir_path}/Sources.gz"

generator_rc=0
generator_output="$("${generator}" \
   --repo "${repo_dir}" \
   --output "${out_dir}" \
   --base-url 'https://packages.example.com/' \
   --site-name 'Test' \
   --suites 'trixie' 2>&1)" || generator_rc=$?

if [ ! -d "${out_dir}" ]; then
   fail "no output directory produced (rc=${generator_rc}): ${generator_output}"
   printf '\nFAILED: %s check(s) failed\n' "${test_failures}" >&2
   exit 1
fi

rendered="$(cat -- "$(find "${out_dir}" -name 'index.html' -print | head --lines=1)")"
rendered_all="$(find "${out_dir}" -name '*.html' -exec cat -- {} +)"

## A repo with nothing wrong in it must not warn; otherwise the non-zero exit
## asserted further down would be meaningless.
if [ "${generator_rc}" -eq 0 ]; then
   pass 'well-formed repo generates cleanly and exits 0'
else
   fail "well-formed repo did not exit 0 (rc=${generator_rc}): ${generator_output}"
fi

## Escaping.
if printf '%s' "${rendered_all}" | grep --quiet --fixed-strings -- '<img src=x'; then
   fail 'raw <img> tag reached the generated HTML (autoescape is off)'
else
   pass 'attacker HTML is escaped, not emitted as markup'
fi

if printf '%s' "${rendered_all}" | grep --quiet --fixed-strings -- '&lt;img'; then
   pass 'attacker HTML is present in escaped form'
else
   fail 'escaped form of the attacker HTML is missing; field may have been dropped instead of escaped'
fi

## URI scheme.
if printf '%s' "${rendered_all}" | grep --quiet --fixed-strings -- 'href="javascript:'; then
   fail 'javascript: URI reached an href'
else
   pass 'javascript: URI never reaches an href'
fi

## Path traversal, in its own run and its own repo/output pair.
##
## The relative name is '../../CANARY-ESCAPED': from
## '<traversal_out>/trixie/' that resolves to '<work_dir>/CANARY-ESCAPED',
## which is OUTSIDE --output and inside a directory this test can write. A
## deeper prefix would land somewhere unwritable and pass for the wrong
## reason -- the escape has to be genuinely reachable to be a real check.
readonly traversal_repo="${work_dir}/repo2"
readonly traversal_out="${work_dir}/site2"
readonly traversal_binary="${traversal_repo}/dists/trixie/main/binary-amd64"

mkdir --parents -- "${traversal_binary}"
printf '%s\n' 'Suite: trixie' > "${traversal_repo}/dists/trixie/Release"
printf '%s\n' \
'Package: ../../CANARY-ESCAPED' \
'Version: 1.0' \
'Architecture: all' \
'Description: relative traversal attempt' \
'' \
"Package: ${work_dir}/ABSOLUTE-ESCAPED" \
'Version: 1.0' \
'Architecture: all' \
'Description: absolute path attempt' \
'' \
'Package: .' \
'Version: 1.0' \
'Architecture: all' \
'Description: current directory attempt' \
'' \
'Package: index.html' \
'Version: 1.0' \
'Architecture: all' \
'Description: reserved name colliding with the suite index file' \
   | gzip --stdout > "${traversal_binary}/Packages.gz"

traversal_rc=0
traversal_output="$("${generator}" \
   --repo "${traversal_repo}" \
   --output "${traversal_out}" \
   --base-url 'https://packages.example.com/' \
   --site-name 'Test' \
   --suites 'trixie' 2>&1)" || traversal_rc=$?

if [ -e "${canary}" ]; then
   fail 'relative traversal escaped the output directory'
else
   pass 'relative traversal did not escape the output directory'
fi

if [ -e "${work_dir}/ABSOLUTE-ESCAPED" ]; then
   fail 'absolute package name wrote outside the output directory'
else
   pass 'absolute package name did not write outside the output directory'
fi

if printf '%s' "${traversal_output}" | grep --quiet --fixed-strings -- 'skipping invalid package name'; then
   pass 'invalid package names are reported, not silently dropped'
else
   fail 'invalid package names were not reported'
fi

if [ "${traversal_rc}" -eq 0 ]; then
   fail 'run that skipped input still exited 0'
else
   pass 'run that skipped input exits non-zero'
fi

## A package named 'index.html' is legal per the Debian name grammar (dots
## are allowed) but collides with the suite index FILE, so it must be
## rejected by name rather than crashing mid-render.
if printf '%s' "${traversal_output}" | grep --quiet --fixed-strings -- "'index.html'"; then
   pass 'reserved output name is rejected by validation'
else
   fail 'reserved output name index.html was not rejected'
fi

## An incomplete site must not be published; the previous site stays.
if [ -e "${traversal_out}" ]; then
   fail 'incomplete site was published despite warnings'
else
   pass 'incomplete site is not published'
fi

## Rendering fidelity: the page must not contradict the control file.
if printf '%s' "${rendered_all}" | grep --quiet --fixed-strings -- 'good_1.0.orig.tar.gz'; then
   pass 'source file table is rendered'
else
   fail 'source file table is empty (Mapping rows dropped)'
fi

if printf '%s' "${rendered_all}" | grep --quiet --fixed-strings -- '[amd64 !i386]'; then
   pass 'architecture qualifier keeps its polarity'
else
   fail 'architecture qualifier polarity is inverted or missing'
fi

if printf '%s' "${rendered_all}" | grep --quiet --fixed-strings -- '&lt;!nocheck&gt;'; then
   pass 'build-profile qualifier keeps its polarity'
else
   fail 'build-profile qualifier polarity is inverted or missing'
fi

if printf '%s' "${rendered_all}" | grep --quiet --fixed-strings -- 'Content-Security-Policy'; then
   pass 'generated pages carry a Content-Security-Policy'
else
   fail 'Content-Security-Policy meta is missing'
fi

if [ -z "${rendered}" ]; then
   fail 'generated index page is empty'
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '\nFAILED: %s check(s) failed\n' "${test_failures}" >&2
   exit 1
fi

printf '\nAll dm-packages-html-generator hostile-input checks passed.\n'
