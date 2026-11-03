#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Meta-test for dist-ai-tests-common/subject-resolve.bash: the ONE canary for
## the "check one path, run another" false-green class the three override-taking
## suites shared. Sources the REAL helper and drives resolve_test_subject over
## throwaway binaries, asserting:
##   - a RELATIVE override resolves to an ABSOLUTE path (survives a later cd into
##     a temp repo -- the pre-fix bug where run_gate's cd lost it);
##   - an EMPTY-but-SET override FAILS loud (the pre-fix bug where [ -n ] treated
##     set-but-empty as unset and silently fell back to the installed copy);
##   - a SLASH-FREE override resolves to an ABSOLUTE ./-pinned path, never a PATH
##     lookup (the pre-fix bug where -x tested the CWD file but invocation
##     searched PATH and ran the installed copy);
##   - an UNSET override falls back to the in-tree copy.
## On the pre-fix tree the helper does not exist, so this test FATALs at source
## time -- it cannot read green against the old code.

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

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
subject_resolve="${script_dir}/../dist-ai-tests-common/subject-resolve.bash"
if [ ! -r "${subject_resolve}" ]; then
   subject_resolve='/usr/share/dist-ai-tests-common/subject-resolve.bash'
fi
if [ ! -r "${subject_resolve}" ]; then
   printf '%s\n' "FATAL: subject-resolve.bash not found (checkout or installed)" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/subject-resolve.bash
source "${subject_resolve}"

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup_handler EXIT

pass_count=0
fail_count=0

## An in-tree layout: SUITE_DIR/../../bin/mybin is the UNSET fallback target.
suite_dir="${test_dir}/usr/share/suite"
mkdir --parents -- "${suite_dir}" "${test_dir}/usr/bin"
in_tree="${test_dir}/usr/bin/mybin"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${in_tree}"
chmod 0755 -- "${in_tree}"

## A separate executable to point an override at.
mkdir --parents -- "${test_dir}/alt"
alt="${test_dir}/alt/altbin"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${alt}"
chmod 0755 -- "${alt}"

pass() {
   printf '%s\n' "PASS: $1"
   pass_count=$(( pass_count + 1 ))
}
fail() {
   printf '%s\n' "FAIL: $1" >&2
   fail_count=$(( fail_count + 1 ))
}

## (1) A RELATIVE override resolves to an absolute path (the real alt binary).
# shellcheck disable=SC2034  # read BY NAME via resolve_test_subject's indirect expansion
rel_ovr='./alt/altbin'
got="$( cd -- "${test_dir}" && resolve_test_subject rel_ovr mybin "${suite_dir}" )"
if [ "${got:0:1}" = '/' ] && [ "${got}" = "$(readlink --canonicalize -- "${alt}")" ]; then
   pass 'relative override -> absolute path of the named binary'
else
   fail 'relative override -> absolute path of the named binary'
fi

## (2) An EMPTY-but-SET override FAILS loud (non-zero), never a silent fallback.
# shellcheck disable=SC2034  # read BY NAME via resolve_test_subject's indirect expansion
empty_ovr=''
rc=0
got="$( resolve_test_subject empty_ovr mybin "${suite_dir}" 2>/dev/null )" || rc=$?
if [ "${rc}" -ne 0 ] && [ -z "${got}" ]; then
   pass 'empty-but-set override fails loud (no fallback)'
else
   fail 'empty-but-set override fails loud (no fallback)'
fi

## (3) A SLASH-FREE override resolves ./-pinned to CWD, not a PATH lookup. Place
## an executable named 'solo' only in a temp CWD (never on PATH).
cwd3="${test_dir}/cwd3"
mkdir --parents -- "${cwd3}"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${cwd3}/solo"
chmod 0755 -- "${cwd3}/solo"
# shellcheck disable=SC2034  # read BY NAME via resolve_test_subject's indirect expansion
slash_free='solo'
got="$( cd -- "${cwd3}" && resolve_test_subject slash_free mybin "${suite_dir}" )"
if [ "${got}" = "$(readlink --canonicalize -- "${cwd3}/solo")" ]; then
   pass 'slash-free override -> absolute CWD path, not PATH lookup'
else
   fail 'slash-free override -> absolute CWD path, not PATH lookup'
fi

## (4) An UNSET override falls back to the in-tree copy.
unset unset_ovr 2>/dev/null || true
got="$( resolve_test_subject unset_ovr mybin "${suite_dir}" )"
if [ -x "${got}" ] \
   && [ "$(readlink --canonicalize -- "${got}")" = "$(readlink --canonicalize -- "${in_tree}")" ]; then
   pass 'unset override -> in-tree fallback'
else
   fail 'unset override -> in-tree fallback'
fi

## (5) A caller variable whose name collides with a function-internal local must
## still be honored (it is read by INDIRECT expansion). 'subject' was the pre-fix
## local name; a caller var named 'subject' was shadowed (unset inside) and the
## SET override silently fell back to the in-tree copy. The '_rts_'-prefixed
## locals fix it. This case FAILS on the pre-fix helper.
# shellcheck disable=SC2034  # read BY NAME via resolve_test_subject's indirect expansion
subject="${alt}"
got="$( resolve_test_subject subject mybin "${suite_dir}" )"
if [ "${got}" = "$(readlink --canonicalize -- "${alt}")" ]; then
   pass 'override var named like an internal local is honored (no shadow)'
else
   fail 'override var named like an internal local is honored (no shadow)'
fi
unset subject 2>/dev/null || true

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
