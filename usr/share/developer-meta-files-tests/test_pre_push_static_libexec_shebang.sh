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
GATE="${PRE_PUSH_STATIC_BIN:-${gate_test_dir}/../../bin/dist-ai-style}"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
fi
[ -x "${GATE}" ] \
   || { printf '%s\n' "FATAL: gate not executable at '${GATE}'." >&2; exit 1; }

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

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
