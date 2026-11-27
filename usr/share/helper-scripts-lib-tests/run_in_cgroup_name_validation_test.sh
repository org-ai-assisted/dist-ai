#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## run-in-cgroup: a caller-supplied --cgroup-name is validated (via
## validate_safe_filename) to a safe single path component before it is joined
## into cgroup_path="/sys/fs/cgroup/${name}".
##
## The bug: an unvalidated name with '/' and '..' (e.g. '../../../tmp/evil')
## escaped /sys/fs/cgroup, so the root-run 'printf > ${cgroup_path}/cgroup.procs'
## wrote/truncated an arbitrary file. Fix: reject '', '.', '..' and any name
## containing '/' BEFORE the findmnt/mkdir, so a traversal is refused with no
## filesystem effect.
##
## Canary: drive the REAL run-in-cgroup with traversal names and assert each is
## refused with the validation error (absent pre-fix, where the name flowed
## straight into the path). A traversal is also shown to create no escape dir. A
## VALID single-component name is asserted to pass validation (no false reject).
## Unprivileged: the valid-name run then fails harmlessly at the /sys/fs/cgroup
## mkdir, creating nothing. Drives the real script; a missing dependency is a
## HARD FAIL, never a skip (R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
  subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/run-in-cgroup"
  libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
else
  subject='/usr/libexec/helper-scripts/run-in-cgroup'
  libdir='/usr/libexec/helper-scripts'
fi

if [ ! -r "${subject}" ]; then
  printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
  printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
  exit 1
fi
if [ ! -r "${libdir}/log_run_die.sh" ] || [ ! -r "${libdir}/has.bsh" ]; then
  printf '%s\n' "FATAL: helper-scripts libs not readable under '${libdir}'" >&2
  exit 1
fi

# shellcheck disable=SC1090,SC1091
source "${libdir}/has.bsh"

if ! has safe-rm ; then
  printf '%s\n' "FATAL: safe-rm not on PATH" >&2
  exit 1
fi

## The subject sources its own libs (log_run_die.sh, strings.bsh) from here.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"

test_dir="$(mktemp --directory)"
cleanup_handler() {
  safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

pass=0
fail=0
check() {
  local label got want
  label="$1"
  got="$2"
  want="$3"
  if [ "${got}" = "${want}" ]; then
    printf '%s\n' "PASS: ${label}"
    pass=$((pass + 1))
  else
    printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
    fail=$((fail + 1))
  fi
}

## Run the subject with a given --cgroup-name and a trivial command; return the
## combined output. The exit code is irrelevant (the happy path cannot complete
## unprivileged), so it is swallowed.
run_name() {
  local name
  name="$1"
  "${subject}" --cgroup-name "${name}" -- /bin/true 2>&1 || true
}

## A validation-refused name emits this marker (and never reaches findmnt/mkdir).
invalid_marker='Invalid --cgroup-name'

## --- traversal / multi-component names are REFUSED by validation ---
for bad in '../../../tmp/evil' '..' '.' 'foo/bar' '/abs' '' ; do
  out="$(run_name "${bad}")"
  if grep --quiet --fixed-strings -- "${invalid_marker}" <<< "${out}"; then
    verdict=refused
  else
    verdict=accepted
  fi
  check "traversal name '${bad}' refused" "${verdict}" "refused"
done

## --- escape proof: a traversal cannot create a dir outside /sys/fs/cgroup ---
## /sys/fs/cgroup is depth 3, so '../../..' reaches '/'. Point the name at a
## writable temp path; pre-fix (no validation, host has cgroup2) this created
## the dir, post-fix validation refuses before any mkdir. Post-fix the dir never
## appears, regardless of cgroup2 presence.
escape_target="${test_dir}/pwned"
run_name "../../..${test_dir}/pwned" >/dev/null 2>&1 || true
if [ -e "${escape_target}" ]; then
  escape_state=created
else
  escape_state=absent
fi
check "traversal does not create an escape dir" "${escape_state}" "absent"

## --- a VALID single-component name passes validation (no false reject) ---
## Unprivileged, the run then fails harmlessly at the /sys/fs/cgroup mkdir; it
## must NOT fail with the validation marker.
valid_out="$(run_name "run-in-cgroup-test-$$")"
if grep --quiet --fixed-strings -- "${invalid_marker}" <<< "${valid_out}"; then
  valid_verdict=rejected
else
  valid_verdict=accepted
fi
check "valid single-component name accepted by validation" "${valid_verdict}" "accepted"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
  printf '%s\n' "FAILED"
  exit 1
fi
printf '%s\n' "OK"
