#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Run the website mobile-overflow guard (check_mobile.py) as a MANDATORY CI
## lane: install Playwright + the chromium engine, then require the check to
## actually run. check_mobile.py exits 77 (SKIP) when the browser is absent; on
## a developer box that is a clean skip, but in this lane the browser is the
## whole point, so a 77 is a setup failure and is turned into a hard fail here.
## A 0 (no sideways overflow) passes; a 1 (overflow found) fails.
##
## Args: one or more site roots (each a directory with index.html).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
check_mobile="${script_dir}/../usr/share/website-tests/check_mobile.py"
venv_dir="${TMP}/website-mobile-venv"

if [ ! -f "${check_mobile}" ]; then
   printf '%s\n' "FAIL: check_mobile.py not found at '${check_mobile}'" >&2
   exit 1
fi

if [ "$#" -eq 0 ]; then
   printf '%s\n' 'FAIL: no site root given' >&2
   exit 1
fi

## Playwright's python bindings + the chromium engine. A venv because the CI
## runner's system python is PEP668 externally-managed; --with-deps pulls the
## chromium apt dependencies (passwordless sudo on the runner).
python3 -m venv "${venv_dir}"
## shellcheck disable=SC1091
source "${venv_dir}/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet playwright
playwright install --with-deps chromium

rc=0
python3 -Bsu -- "${check_mobile}" "$@" || rc=$?

if [ "${rc}" -eq 77 ]; then
   printf '%s\n' 'FAIL: check_mobile.py SKIPped (exit 77) -- Playwright/chromium unavailable; this CI lane requires the browser, a skip is a setup failure here.' >&2
   exit 1
fi

exit "${rc}"
