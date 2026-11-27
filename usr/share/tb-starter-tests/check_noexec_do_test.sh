#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## tb-starter torbrowser check_noexec_do: noexec detection for ~/.tb.
##
## check_noexec_do decides whether tb_home_folder (~/.tb) is executable. Its
## RETURN POLARITY matches both callers (remount_exec, check_noexec): success (0)
## means "executable, no remount needed", failure (1) means "noexec, remount".
##
## REGRESSION this guards: detecting an INHERITED noexec on a path that may not
## exist yet. check_noexec_do must report noexec when ~/.tb sits under a noexec
## mount (e.g. a noexec /home) even though ~/.tb is not its own mount line and
## often does not exist when the check runs. It uses 'findmnt --target' to resolve
## the COVERING mount and matches the OPTIONS token-wise -- but findmnt needs an
## EXISTING path (it exits non-zero on a missing one, see the findmnt stub), so
## the function must first resolve the nearest existing ANCESTOR. It also FAILS
## SAFE: any uncertainty (findmnt failure, empty / non-absolute folder) returns 1
## (noexec -> remount), never 0, which would launch TB on a noexec home. This
## pins the ancestor-resolution, the fail-safe direction, and the polarity.
##
## Drives the REAL torbrowser (sourced; it is source-able via its was_executed
## guard) with a stub findmnt. A missing dependency is a HARD FAIL, never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
findmnt_stub="${tool_dir}/check_noexec_do_findmnt_stub.sh"
probe="${tool_dir}/torbrowser_source_probe.sh"

[ -v TB_STARTER_REPO ] || TB_STARTER_REPO=""
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${TB_STARTER_REPO}" ]; then
  subject="${TB_STARTER_REPO}/usr/bin/torbrowser"
else
  subject='/usr/bin/torbrowser'
fi

## torbrowser sources check_runtime.bsh at load; its prefix is HELPER_SCRIPTS_PATH
## (empty -> the installed /usr). helper_root is that prefix.
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
  helper_root="${HELPER_SCRIPTS_REPO}"
else
  helper_root=""
fi
check_runtime="${helper_root}/usr/libexec/helper-scripts/check_runtime.bsh"
has_lib="${helper_root}/usr/libexec/helper-scripts/has.bsh"

## The SUBJECT (torbrowser) and the helper-scripts libs it sources are REQUIRED
## dependencies: absent means tb-starter / helper-scripts is not checked out or
## installed, an environment bug -> FATAL (exit 1), never a skip (R-220).
if [ ! -r "${subject}" ]; then
  printf '%s\n' "FATAL: torbrowser not readable at '${subject}'" >&2
  printf '%s\n' "set TB_STARTER_REPO to a tb-starter checkout, or install tb-starter" >&2
  exit 1
fi
if [ ! -r "${check_runtime}" ] || [ ! -r "${has_lib}" ]; then
  printf '%s\n' "FATAL: helper-scripts libs not readable under '${helper_root}/usr'" >&2
  printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
  exit 1
fi
if [ ! -x "${findmnt_stub}" ] || [ ! -x "${probe}" ]; then
  printf '%s\n' "FATAL: test support scripts missing under '${tool_dir}'" >&2
  exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${has_lib}"
if ! has safe-rm; then
  printf '%s\n' "FATAL: safe-rm not on PATH" >&2
  exit 1
fi

## torbrowser resolves its libs via HELPER_SCRIPTS_PATH; the probe reads SUBJECT.
export HELPER_SCRIPTS_PATH="${helper_root}"
export SUBJECT="${subject}"

test_dir="$(mktemp --directory)"
cleanup_handler() {
  ## Best-effort: a cleanup failure must not fire errexit in the trap and flip a
  ## passing run to a non-zero exit (the runner keys on the exit code).
  # shellcheck disable=SC2317  # reached via the EXIT trap, not a direct call.
  safe-rm --recursive --force -- "${test_dir}" || true
}
trap cleanup_handler EXIT

## The stub goes on PATH under the real tool name findmnt.
bindir="${test_dir}/bin"
mkdir --parents -- "${bindir}"
ln --symbolic -- "${findmnt_stub}" "${bindir}/findmnt"
export PATH="${bindir}:${PATH}"

pass=0
fail=0

## (1) Source-ability: sourcing torbrowser must not auto-run, must not leak
## strict-mode, and must define check_noexec_do + main (run in a child shell).
probe_rc=0
"${probe}" >/dev/null 2>&1 || probe_rc=$?
if [ "${probe_rc}" -eq 0 ]; then
  pass=$((pass + 1))
  printf '%s\n' "PASS: source-able (no auto-run, no strict leak, functions defined)"
else
  fail=$((fail + 1))
  printf '%s\n' "FAIL: source probe exit ${probe_rc} (0 expected)"
fi

## (2) Behavior: source the REAL torbrowser and drive check_noexec_do.
# shellcheck disable=SC1090,SC1091
source "${subject}"

## Invoke check_noexec_do without aborting the strict runner on its non-zero
## return (a return is not an ERR), capturing its exit code.
run_check_noexec_do() {
  local rc=0
  if check_noexec_do; then
    rc=0
  else
    rc=$?
  fi
  printf '%s' "${rc}"
}

## desc | tb_home_folder | FINDMNT_STUB_OPTIONS | FINDMNT_STUB_RC | expect_rc
check_case() {
  local desc="$1"
  ## Read by the sourced check_noexec_do, which shellcheck cannot follow.
  # shellcheck disable=SC2034
  tb_home_folder="$2"
  export FINDMNT_STUB_OPTIONS="$3"
  export FINDMNT_STUB_RC="$4"
  local expect="$5"
  local got
  got="$(run_check_noexec_do)"
  if [ "${got}" = "${expect}" ]; then
    pass=$((pass + 1))
    printf '%s\n' "PASS: ${desc} (rc=${got})"
  else
    fail=$((fail + 1))
    printf '%s\n' "FAIL: ${desc} (expected rc=${expect}, got rc=${got})"
  fi
}

## The ~/.tb test paths below do NOT exist, so the stub findmnt exits non-zero on
## them directly; check_noexec_do must walk up to an existing ancestor (ending at
## '/'), where the stub returns the scenario OPTIONS. This is THE canary: the
## pre-fix code called findmnt on the missing ~/.tb, got a non-zero exit, and
## fail-OPENED (returned 0) -- so the noexec cases return 1 here only once the
## ancestor walk is in place.

## Inherited noexec: ~/.tb (nonexistent) sits under a noexec covering mount; the
## ancestor walk resolves it and noexec is detected -> return 1.
check_case "inherited noexec (covering mount)" \
  "/test-home/.tb" "rw,nosuid,nodev,noexec,relatime" "0" "1"

## The covering mount is its own noexec mount (the Qubes bind-mount shape) -> 1.
check_case "own noexec mount" \
  "/test-home/.tb" "rw,noexec" "0" "1"

## Covering mount WITHOUT noexec -> executable -> return 0. (Also proves the walk
## reached an EXISTING ancestor: a failed walk would fail safe to 1.)
check_case "executable (no noexec in options)" \
  "/test-home/.tb" "rw,nosuid,nodev,relatime" "0" "0"

## 'noexec' must be matched as an OPTIONS token, never as a substring of the
## PATH (the original bug grepped the path). A path literally containing
## 'noexec' with exec options must still be executable -> return 0.
check_case "noexec in path, not in options" \
  "/noexec/.tb" "rw,nodev,relatime" "0" "0"

## findmnt fails even on the resolved ancestor -> fail SAFE (assume noexec) -> 1,
## never 0. Returning 0 here would launch TB on a possibly-noexec home.
check_case "findmnt failure -> fail-safe noexec" \
  "/test-home/.tb" "" "1" "1"

## An empty tb_home_folder is a caller bug: real findmnt --target '' silently
## judges '/', so guard it and fail safe -> return 1 (the stub is not reached).
check_case "empty tb_home_folder -> fail-safe noexec" \
  "" "rw,nosuid,nodev,relatime" "0" "1"

## A non-absolute folder (incl. a leading '-' that findmnt would parse as a flag)
## is a caller bug -> fail safe -> return 1.
check_case "non-absolute tb_home_folder -> fail-safe noexec" \
  "relative/.tb" "rw,nosuid,nodev,relatime" "0" "1"

printf '%s\n' ""
printf '%s\n' "$((pass + fail)) case(s), ${pass} passed, ${fail} failed"
if [ "${fail}" -ne 0 ]; then
  exit 1
fi
exit 0
