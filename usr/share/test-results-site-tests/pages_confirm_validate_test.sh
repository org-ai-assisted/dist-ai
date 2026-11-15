#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests pages_confirm_published's INPUT VALIDATION by sourcing the real lib. The confirm feeds
## the sha into the Pages deployment query and the timeout into bash arithmetic, so:
##  - an EMPTY or ABBREVIATED sha must be refused BEFORE any API call -- else 'sha=' is treated as
##    "no filter" and the newest success FALSE-CONFIRMS an unrelated commit (the dangerous direction);
##  - a NON-INTEGER timeout/poll must be refused before arithmetic (no expression re-evaluation);
##  - a ZERO-PADDED integer timeout must WORK (base-10), not abort as invalid octal.
## github-api is stubbed as a TRIPWIRE: any call on a refused-input case is itself a failure.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
lib="${repo_root}/usr/libexec/dist-ai/pages-confirm.bsh"
[ -r "${lib}" ] || lib='/usr/libexec/dist-ai/pages-confirm.bsh'
if [ ! -r "${lib}" ]; then
   printf '%s\n' "pages-confirm.bsh not found" >&2
   exit 1
fi
# shellcheck source=../../libexec/dist-ai/pages-confirm.bsh
source "${lib}"

pass=0
fail=0

work="$(mktemp --directory)"
cleanup() {
   # shellcheck disable=SC2317  ## invoked via the EXIT trap
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

bin="${work}/bin"
mkdir --parents -- "${bin}"
api_log="${work}/api.calls"

## github-api stub. Default: a TRIPWIRE that records any call and returns a deployment that WOULD
## confirm success -- so a validation gap (reaching the API on bad input) both trips the wire and
## would false-confirm. make_api 'live' switches it to a normal success responder for the valid case.
make_api() {
   cat > "${bin}/github-api" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "${api_log}"
case "\$2" in
   */statuses*) printf '%s\n' '[{"state":"success"}]' ;;
   *)           printf '%s\n' '[{"id":101}]' ;;
esac
EOF
   chmod +x -- "${bin}/github-api"
}
make_api
true > "${api_log}"

full_sha='cafe1234cafe1234cafe1234cafe1234cafe1234'

run() {
   ## $1 sha, $2 timeout, $3 poll -> sets globals rc, called(0/1). Fresh api log each run.
   true > "${api_log}"
   if PATH="${bin}:${PATH}" pages_confirm_published 'org/repo' "$1" "$2" "$3" 'test' >/dev/null 2>&1; then
      rc=0
   else
      rc=$?
   fi
   [ -s "${api_log}" ] && called=1 || called=0
}

check_refused() {
   ## $1 description; expects rc!=0 AND the API was never called.
   if [ "${rc}" -ne 0 ] && [ "${called}" -eq 0 ]; then
      printf '%s\n' "PASS: $1 (refused, no API call)"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: $1 (rc=${rc}, api-called=${called})" >&2
      fail=$((fail + 1))
   fi
}

## CANARY: empty sha -> refuse before the API (old code queried sha= and confirmed the newest).
run '' 5 1
check_refused "empty sha"

## Abbreviated sha -> refuse before the API (would exact-miss and time out, or over-match).
run 'cafe123' 5 1
check_refused "abbreviated sha"

## Non-integer timeout -> refuse before arithmetic (no expression re-evaluation).
run "${full_sha}" 'BASH_VERSINFO[0]' 1
check_refused "non-integer timeout"

## Non-integer poll -> refuse before arithmetic.
run "${full_sha}" 5 'x1'
check_refused "non-integer poll"

## Zero-padded integer timeout -> MUST work (base-10), confirm success, call the API, exit 0.
run "${full_sha}" 09 1
if [ "${rc}" -eq 0 ] && [ "${called}" -eq 1 ]; then
   printf '%s\n' "PASS: zero-padded timeout '09' works (base-10, not octal)"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: zero-padded timeout '09' (rc=${rc}, api-called=${called})" >&2
   fail=$((fail + 1))
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
