#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for dist-ai-style's 'libexec-shebang' rule: a file under
## usr/libexec/ that is neither ELF nor a script (no '#!') ships EXECUTABLE in
## the .deb (the dh/genmkfile install mode), so lintian
## executable-not-elf-or-script breaks the build. The local gate otherwise
## passed it -- check-executables-have-shebangs keys on the GIT exec bit (a
## 0644-in-git / 0755-installed data file carries none), so the rule keys on the
## PATH instead.
##
## Pinned here, driving the REAL in-tree gate end to end (file selection +
## text-rule detection + reporting), never a copy of the rule:
##   (a) a usr/libexec file with NO shebang -> FLAGGED;
##   (b) a line-leading '## style-ok: allow-libexec-no-shebang' (and the id
##       spelling '## style-ok: libexec-shebang') -> SPARED;
##   (c) a file carrying a real '#!' shebang -> SPARED;
##   (d) the SAME shebang-less file OUTSIDE usr/libexec/ -> SPARED (path-keyed).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.bsh ; then
   printf '%s\n' "FATAL: helper-scripts has.bsh is not installed (/usr/libexec/helper-scripts/has.bsh)" >&2
   exit 1
fi
# shellcheck source=../../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has git ; then
   printf '%s\n' "FATAL: git not on PATH" >&2
   exit 1
fi
if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/),
## so editing the in-tree gate tests THAT copy, not the packaged one.
## PRE_PUSH_STATIC_BIN aims the suite at an alternate gate copy (the pre-fix
## version for a canary run); otherwise the in-tree copy, then the packaged.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
subject_resolve="${gate_test_dir}/../dist-ai-tests-common/subject-resolve.bash"
if [ ! -r "${subject_resolve}" ]; then
   subject_resolve='/usr/share/dist-ai-tests-common/subject-resolve.bash'
fi
if [ ! -r "${subject_resolve}" ]; then
   printf '%s\n' "FATAL: subject-resolve.bash not found (checkout or installed)" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/subject-resolve.bash
source "${subject_resolve}"
## SET (even empty) override honored exactly; only UNSET falls back in-tree then
## installed; result is absolute so it survives run_gate's cd into a temp repo.
GATE="$(resolve_test_subject PRE_PUSH_STATIC_BIN dist-ai-style "${gate_test_dir}")" || exit 1

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

pass_count=0
fail_count=0

## Build a one-file repo around a file at RELPATH with EXEC mode (0/1) and the
## given body lines, run the gate against the empty base, and return its combined
## output in gate_output and exit code in gate_rc.
## run_gate <relpath> <exec:0|1> <line>...
run_gate() {
   local relpath exec_bit repo base
   relpath="$1"
   exec_bit="$2"
   shift 2
   repo="$(mktemp --directory --tmpdir="${test_dir}" repo.XXXXXX)"
   git -C "${repo}" -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet
   git -C "${repo}" -c core.hooksPath=/dev/null config user.email 'ci-test@example.com'
   git -C "${repo}" -c core.hooksPath=/dev/null config user.name 'ci-test'
   git -C "${repo}" -c core.hooksPath=/dev/null commit --quiet --no-verify --allow-empty --message base
   base="$(git -C "${repo}" rev-parse HEAD)"
   mkdir --parents -- "${repo}/$(dirname -- "${relpath}")"
   printf '%s\n' "$@" > "${repo}/${relpath}"
   if [ "${exec_bit}" = '1' ]; then
      chmod 0755 -- "${repo}/${relpath}"
   else
      chmod 0644 -- "${repo}/${relpath}"
   fi
   git -C "${repo}" -c core.hooksPath=/dev/null add --all
   git -C "${repo}" -c core.hooksPath=/dev/null commit --quiet --no-verify --message fixture
   ## '|| true': the gate exits non-zero whenever a fixture carries a finding,
   ## which is the normal case here -- the assertions read gate_output, not rc.
   gate_output="$( cd -- "${repo}" && "${GATE}" --check --range "${base}" 2>&1 )" || true
}

## Liveness guard: an 'absent' assertion is only meaningful once the gate ran to
## its terminal verdict; a crash before the rule prints no verdict and would make
## absence pass vacuously.
have_verdict() {
   grep --quiet --extended-regexp \
      'all static checks passed|[0-9]+ check\(s\) failed' <<< "${gate_output}"
}

## assert_tag <label> <present|absent>
## Reads gate_output/gate_rc populated by the preceding run_gate.
assert_tag() {
   local label want got
   label="$1"
   want="$2"
   if ! have_verdict; then
      printf '%s\n' "FAIL: ${label} -- gate produced no terminal verdict" >&2
      printf '%s\n' "${gate_output}" | tail -5 >&2
      fail_count=$((fail_count + 1))
      return 0
   fi
   if grep --quiet --fixed-strings -- 'libexec-shebang' <<< "${gate_output}"; then
      got='present'
   else
      got='absent'
   fi
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label} (libexec-shebang ${want})"
      pass_count=$((pass_count + 1))
   else
      printf '%s\n' "FAIL: ${label} -- libexec-shebang expected ${want}, was ${got}" >&2
      printf '%s\n' "${gate_output}" | grep --fixed-strings -- 'libexec-shebang' | head -3 >&2
      fail_count=$((fail_count + 1))
   fi
}

## (a) A usr/libexec file with NO shebang is FLAGGED. 0644 in git (an installed
## data payload), so check-executables-have-shebangs misses it -- the exact gap.
run_gate 'usr/libexec/foo/prog.awk' 0 '{ print }'
assert_tag 'no-shebang usr/libexec file is flagged' 'present'

## (b) A line-leading named waiver clears the rule for the file.
run_gate 'usr/libexec/foo/waived.awk' 0 \
   '## style-ok: allow-libexec-no-shebang' \
   '{ print }'
assert_tag "'allow-libexec-no-shebang' waiver spares it" 'absent'

## (b2) The per-rule id spelling waives it too.
run_gate 'usr/libexec/foo/waived2.awk' 0 \
   '## style-ok: libexec-shebang' \
   '{ print }'
assert_tag "'libexec-shebang' id override spares it" 'absent'

## (c) A real '#!' shebang satisfies the rule (lintian sees a script); the file
## ships executable, the real shape of a usr/libexec helper.
run_gate 'usr/libexec/foo/shebang.awk' 1 \
   '#!/usr/bin/awk -f' \
   '{ print }'
assert_tag 'a real shebang spares it' 'absent'

## (d) The SAME shebang-less body OUTSIDE usr/libexec/ must NOT be flagged -- the
## rule is path-keyed, not a blanket no-shebang check.
run_gate 'usr/share/foo/prog.awk' 0 '{ print }'
assert_tag 'a non-libexec file is not flagged' 'absent'

## (e) a NESTED usr/libexec under another usr/ subtree (e.g. a test fixture) is NOT installed to
## /usr/libexec, so it must NOT be flagged -- the path predicate anchors on the FIRST usr/ being
## immediately followed by libexec, not any usr/libexec substring.
run_gate 'usr/share/foo-tests/fixtures/usr/libexec/sample.dat' 0 'fixture data'
assert_tag 'a nested usr/libexec under usr/share is NOT flagged' 'absent'

## (f) a NUL-containing, non-ELF payload under usr/libexec is STILL flagged: ctx.is_binary (a NUL
## byte) must NOT exempt it -- dh forces +x and lintian flags a non-ELF/non-script. run_gate is
## line-based (no NUL), so write the byte directly and run the gate in per-file mode.
nuldir="$(mktemp --directory)"
mkdir --parents -- "${nuldir}/usr/libexec/foo"
printf '%s\0' 'not-elf' > "${nuldir}/usr/libexec/foo/nul.dat"
printf '%s\n' 'payload' >> "${nuldir}/usr/libexec/foo/nul.dat"
nul_output="$( "${GATE}" "${nuldir}/usr/libexec/foo/nul.dat" 2>&1 )" || true
safe-rm --recursive --force -- "${nuldir}" || true
case "${nul_output}" in
   *libexec-shebang*)
      printf '%s\n' "PASS: a NUL-containing non-ELF usr/libexec file is flagged"
      pass_count=$(( pass_count + 1 ))
      ;;
   *)
      printf '%s\n' "FAIL: a NUL-containing non-ELF usr/libexec file was NOT flagged" >&2
      fail_count=$(( fail_count + 1 ))
      ;;
esac

## (g) Regression: an ABSOLUTE command-line path whose on-disk PREFIX itself contains a 'usr'
## component (a checkout under /usr/src, or any path with a 'usr' segment) must still flag a real
## usr/libexec file. The rule re-anchors such a path to its git top-level; the pre-fix code
## anchored index('usr') on the PREFIX 'usr' and SKIPPED the file -- a gate false-pass. A '.git'
## (here a plain 'git init', no commit) is what marks the top-level the path is relative to.
pfxdir="$(mktemp --directory)"
pfxrepo="${pfxdir}/usr/pfx/repo"
mkdir --parents -- "${pfxrepo}/usr/libexec/foo"
git -C "${pfxrepo}" -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet
printf '%s\n' 'plain payload, no shebang' > "${pfxrepo}/usr/libexec/foo/tool.dat"
pfx_output="$( "${GATE}" "${pfxrepo}/usr/libexec/foo/tool.dat" 2>&1 )" || true
safe-rm --recursive --force -- "${pfxdir}" || true
case "${pfx_output}" in
   *libexec-shebang*)
      printf '%s\n' "PASS: an absolute usr-prefixed path flags a real usr/libexec file"
      pass_count=$(( pass_count + 1 ))
      ;;
   *)
      printf '%s\n' "FAIL: an absolute usr-prefixed path did NOT flag the usr/libexec file" >&2
      fail_count=$(( fail_count + 1 ))
      ;;
esac

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
