#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 1200_prepare-build-machine username-plain-for-sudoers gates a value that is
## interpolated verbatim into a sudoers rule. It must:
##   - REFUSE anything carrying a sudoers metacharacter (space, '%', '=', ',',
##     ':') or the reserved word 'ALL' -- else the build could write a rule that
##     grants far more than intended;
##   - ACCEPT a plain [A-Za-z0-9_-] name AND one with a single trailing '$'
##     (Samba machine account), which /etc/adduser.conf NAME_REGEX also permits
##     -- else a legitimate username is wrongly rejected.
##
## Needs no root, no network, no build: the function is extracted and run with
## dm-build-step-fn.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DIST_AI_DIR:-}" ]; then
   dist_ai_dir="${DIST_AI_DIR}"
else
   dist_ai_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../../.." && pwd )"
fi
tool="${dist_ai_dir}/usr/bin/dm-build-step-fn"
if [ ! -x "${tool}" ]; then
   tool="$( type -P dm-build-step-fn || true )"
fi
if [ -z "${tool}" ] || [ ! -x "${tool}" ]; then
   printf '%s\n' "FAIL: dm-build-step-fn not found or not executable" >&2
   exit 1
fi

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
step_file="${dm_checkout}/build-steps.d/1200_prepare-build-machine"
if [ ! -r "${step_file}" ]; then
   printf '%s\n' "FAIL: cannot read ${step_file}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Exit 0 == accepted, non-zero == refused. dm-build-step-fn --run propagates
## the function's own exit code.
verdict() {
   local file candidate status
   file="$1"
   candidate="$2"
   status=0
   "${tool}" --file "${file}" --fn username-plain-for-sudoers --run "${candidate}" \
      >/dev/null 2>&1 || status="$?"
   printf '%s\n' "${status}"
}

check_accept() {
   if [ "$( verdict "${step_file}" "$1" )" = "0" ]; then
      pass "accepts '$1'"
   else
      fail "expected '$1' accepted, was refused"
   fi
}
check_reject() {
   if [ "$( verdict "${step_file}" "$1" )" != "0" ]; then
      pass "refuses '$1'"
   else
      fail "expected '$1' refused, was accepted"
   fi
}

## --- accepted: plain names and a single trailing '$' -----------------------
check_accept alice
check_accept root
check_accept _svc
check_accept build-user
check_accept x9
check_accept 'host$'

## --- refused: reserved word and sudoers metacharacters ---------------------
check_reject ''
check_reject ALL
check_reject 'a b'
check_reject 'a%b'
check_reject 'a=b'
check_reject 'a,b'
check_reject 'a:b'
check_reject 'a$b'
## Only ONE trailing '$' is tolerated.
check_reject 'host$$'
## A lone '$' strips to empty.
check_reject '$'

## --- CANARY: the accept of a trailing '$' is the actual fix -----------------
## The pre-fix form did not strip a trailing '$', so 'host$' hit the
## metacharacter class and was refused. Build that form and confirm it refuses
## 'host$' (proving the accept assertion above has teeth) while still refusing a
## real metacharacter (proving the canary form is otherwise faithful).
buggy="${work_dir}/9997_buggy"
cat > "${buggy}" <<'BUGGY'
#!/bin/bash
username-plain-for-sudoers() {
   local candidate
   candidate="$1"
   case "${candidate}" in
      ''|*[!A-Za-z0-9_-]*)
         return 1
         ;;
      ALL)
         return 1
         ;;
   esac
   return 0
}
BUGGY
if [ "$( verdict "${buggy}" 'host$' )" != "0" ] \
   && [ "$( verdict "${buggy}" 'a b' )" != "0" ]; then
   pass "canary: the pre-fix form refuses 'host\$' (and still refuses metachars)"
else
   fail "canary broken: pre-fix form did not refuse 'host\$' as expected"
fi

summary_line="===== username-plain-for-sudoers: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
