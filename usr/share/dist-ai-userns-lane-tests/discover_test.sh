#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dist-ai-userns-lane.sh selects which test files the bare-runner userns lane
## runs. It once used `grep -lF 'pytest.mark.userns'`, which MISSES a marker
## applied indirectly (an alias, or getattr) -- the file has no literal
## 'pytest.mark.userns' substring -> grep skips it -> a real userns test is
## SILENTLY no-op'd (a false green, the opposite of the lane's promise). It also
## must NOT import a component's unrelated tests, whose own helper libs are absent
## on the bare runner (that is the collection-error regression the per-file
## discovery fixes). The INVERSE false-green also matters: a file that DOES carry
## the marker but RAISES on import collects no node, so pure collect-only discovery
## would omit it and a broken userns test would pass as a no-op -- it must be
## SELECTED so the real run fails loud. This drives the REAL
## discover_userns_test_files against a fixture dir and asserts: an indirect marker
## IS found, an unrelated import-erroring sibling is tolerated (not found, no
## crash), a marker-carrying import-erroring file IS found, a plain test is not.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Required dependency: the lane itself runs pytest, so its absence is an
## environment bug, not a reason to skip (dist-ai: required dep absent -> FATAL).
if ! python3 -m pytest --version >/dev/null 2>&1; then
  printf '%s\n' "FATAL: python3 pytest is required but not runnable." >&2
  exit 1
fi

## Locate and source the REAL lane (checkout layout, or an override for installs).
self_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")"
lane="${DIST_AI_USERNS_LANE_SCRIPT:-${self_dir}/../../../ci/dist-ai-userns-lane.sh}"
if [ ! -r "${lane}" ]; then
  printf '%s\n' "FATAL: cannot find dist-ai-userns-lane.sh at '${lane}'." >&2
  exit 1
fi
# shellcheck source=../../../ci/dist-ai-userns-lane.sh disable=SC1091
source "${lane}"
if ! declare -F discover_userns_test_files >/dev/null; then
  printf '%s\n' "FATAL: sourcing the lane did not define discover_userns_test_files." >&2
  exit 1
fi

fixdir="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${fixdir}"; }
trap cleanup EXIT

## Marker registration so '-m userns' is a known marker.
printf '%s\n' \
  'def pytest_configure(config):' \
  '    config.addinivalue_line("markers", "userns: namespace propagation test")' \
  > "${fixdir}/conftest.py"
## (1) INDIRECT marker -- no literal 'pytest.mark.userns' anywhere; grep misses it.
printf '%s\n' \
  'import pytest' \
  'pytestmark = getattr(pytest.mark, "userns")' \
  'def test_indirect(): assert True' \
  > "${fixdir}/test_indirect.py"
## (2) Import-erroring sibling (models a component helper lib absent on the runner).
printf '%s\n' \
  'import nonexistent_helper_lib_xyz  # noqa' \
  'def test_broken(): assert True' \
  > "${fixdir}/test_importerror.py"
## (3) Plain, unmarked test -- must not be selected.
printf '%s\n' 'def test_plain(): assert True' > "${fixdir}/test_plain.py"
## (4) Literal marker -- the easy case, must still be selected.
printf '%s\n' \
  'import pytest' \
  'pytestmark = pytest.mark.userns' \
  'def test_literal(): assert True' \
  > "${fixdir}/test_literal.py"
## (5) Marker-carrying file that RAISES on import -- a BROKEN userns test. Must be
## SELECTED so the real run fails loud, never a silent no-op (inverse false-green).
printf '%s\n' \
  'import pytest' \
  'pytestmark = pytest.mark.userns' \
  'raise RuntimeError("boom at import")' \
  'def test_broken(): assert True' \
  > "${fixdir}/test_broken.py"

## Canary: the OLD grep approach misses the INDIRECT (alias) marker -- it matches
## only the files with the literal substring (test_literal + the broken one), so
## the indirect case below is a real regression that fails on the pre-fix code.
grep_hits="$(grep -rlF --include='*.py' 'pytest.mark.userns' -- "${fixdir}" | sed "s|${fixdir}/||" | sort | tr '\n' ' ')"
case " ${grep_hits} " in
  *" test_indirect.py "*)
    printf '%s\n' "FATAL(canary): grep unexpectedly matched the alias file; got '${grep_hits}'." >&2
    exit 1
    ;;
esac

mapfile -t found < <(discover_userns_test_files "${fixdir}" | sed "s|${fixdir}/||" | sort)
got="${found[*]:-}"
want="test_broken.py test_indirect.py test_literal.py"

pass=0
fail=0
check() {
  local desc="$1" got_v="$2" want_v="$3"
  if [ "${got_v}" = "${want_v}" ]; then
    printf '%s\n' "PASS: ${desc}"
    pass=$(( pass + 1 ))
  else
    printf '%s\n' "FAIL: ${desc} (got '${got_v}', want '${want_v}')"
    fail=$(( fail + 1 ))
  fi
}

check "discover selects broken + indirect + literal userns tests" "${got}" "${want}"
case " ${got} " in *" test_indirect.py "*) r=y ;; *) r=n ;; esac
check "indirect-marker userns test IS discovered (grep would miss it)" "${r}" "y"
case " ${got} " in *" test_broken.py "*) r=y ;; *) r=n ;; esac
check "marker file that errors on import IS selected (fails loud, not no-op)" "${r}" "y"
case " ${got} " in *" test_importerror.py "*) r=y ;; *) r=n ;; esac
check "unrelated import-erroring sibling is tolerated, not selected" "${r}" "n"
case " ${got} " in *" test_plain.py "*) r=y ;; *) r=n ;; esac
check "plain unmarked test is not selected" "${r}" "n"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || { printf '%s\n' "FAILED"; exit 1; }
printf '%s\n' "OK"
