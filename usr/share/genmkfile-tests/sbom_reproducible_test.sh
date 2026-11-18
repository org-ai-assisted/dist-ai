#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: 'genmkfile sbom' (emitter sbom-cyclonedx.py) must stay REPRODUCIBLE and
## carry a DETERMINISTIC timestamp taken from the changelog release date (SOURCE_DATE_EPOCH),
## never wall-clock time or a random serial number, and must type every component -- the root
## included -- uniformly as 'library'.
##
## Each assertion (in the sibling sbom_reproducible_assert.py) guards an edit that would
## plausibly reintroduce the bug:
##   - a wall-clock datetime.now() timestamp  -> two runs differ, build non-reproducible
##   - a random uuid4 serialNumber            -> same
##   - the root component typed 'application'  -> non-uniform vs the 'library' deps
## The timestamp and type checks FAIL on the pre-change emitter (which emitted no timestamp and
## typed the root 'application'), so this is a true regression test, not a tautology.
##
## Hermetic: a throwaway source package (debian/control + debian/changelog, NO REUSE metadata
## so the opt-in 'reuse' license path stays off). Only python3-cyclonedx-lib + python3-packageurl
## are needed, and those are genmkfile's own Depends -- a missing one is an ENVIRONMENT bug, so it
## fails loud, never a skip. Exit: 0 pass | 1 fail | 77 skip (no genmkfile checkout wired).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Shared genmkfile binary discovery + checkout capability gate (sibling suites resolve the
## same binary, so they cannot drift to different subjects/skips).
test_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
_common_dir="${test_dir}/../dist-ai-tests-common"
[ -r "${_common_dir}/genmkfile-locate.bash" ] || _common_dir="/usr/share/dist-ai-tests-common"
# shellcheck source=../dist-ai-tests-common/genmkfile-locate.bash
source "${_common_dir}/genmkfile-locate.bash"
genmkfile_require_bin
# shellcheck disable=SC2154  ## set by genmkfile_require_bin in the sourced helper
genmkfile_bin="${genmkfile_bin_path}"
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

workdir="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${workdir}"; }
trap cleanup EXIT
mkdir -- "${workdir}/debian"

## Section drives the component 'section' property; the two Depends become two dependency
## components. No REUSE.toml -> the license path stays off.
cat > "${workdir}/debian/control" <<'EOF'
Source: sbomreprodemo
Section: net
Priority: optional
Maintainer: Test <test@example.com>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.7.2

Package: sbomreprodemo
Architecture: all
Depends: bash, systemd-sysv, ${misc:Depends}
Description: genmkfile SBOM reproducibility fixture
 Throwaway package exercising 'genmkfile sbom'.
EOF

## Fixed PAST release date: a wall-clock timestamp would miss it by years.
cat > "${workdir}/debian/changelog" <<'EOF'
sbomreprodemo (1.0-1) unstable; urgency=medium

  * Fixture.

 -- Test <test@example.com>  Tue, 14 Nov 2023 00:00:00 +0000
EOF

sbom_file="${workdir}/usr/share/sbom/sbomreprodemo.cdx.json"

run_sbom() {
   ( cd -- "${workdir}" && "${genmkfile_bin}" sbom ) >/dev/null 2>&1
}

if ! run_sbom; then
   printf '%s\n' "FATAL: 'genmkfile sbom' failed -- python3-cyclonedx-lib / python3-packageurl absent (genmkfile Depends)?" >&2
   exit 1
fi
cp -- "${sbom_file}" "${workdir}/run1.json"
if ! run_sbom; then
   printf '%s\n' "FATAL: second 'genmkfile sbom' run failed." >&2
   exit 1
fi
cp -- "${sbom_file}" "${workdir}/run2.json"

source_date_epoch="$(dpkg-parsechangelog --file="${workdir}/debian/changelog" --show-field=Timestamp)"

## All JSON-semantic assertions live in the standalone helper (no inline 'python3 -c'), run
## directly via its shebang so its '-Bsu' flags survive. Not exec'd: the EXIT trap must still
## fire to remove the workdir. errexit propagates a non-zero helper exit as the test's own.
"${test_dir}/sbom_reproducible_assert.py" \
   "${workdir}/run1.json" "${workdir}/run2.json" "${source_date_epoch}"
