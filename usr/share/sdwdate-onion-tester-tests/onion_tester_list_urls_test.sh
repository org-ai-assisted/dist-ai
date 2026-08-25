#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Offline regression suite for onion-tester-list-urls: the conf URL enumerator
## the warm-up sweep consumes. Driven against a FAKE sdwdate.config on PYTHONPATH
## (no installed sdwdate, no conf, no network), so the enumeration contract is
## tested in isolation: emit real URLs only, and never let read_pools' stdout
## diagnostics leak out as URLs.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

payload_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
list_urls="${ONION_TESTER_LIST_URLS_BIN:-${payload_dir}/../../bin/onion-tester-list-urls}"
work_dir=""
passed=0
failed=0

# shellcheck disable=SC2317  ## reached via the EXIT trap in main()
onion_tester_list_urls_test_cleanup() {
   if [ -n "${work_dir}" ]; then
      safe-rm --recursive --force -- "${work_dir}"
   fi
}

## A fake sdwdate.config whose read_pools mimics the real one's two behaviours,
## selected by FAKE_READ_POOLS: return per-pool URLs, or print a stdout
## diagnostic and return an empty list (what the real one does with no conf).
write_fake_sdwdate() {
   mkdir --parents -- "${work_dir}/pylib/sdwdate"
   touch -- "${work_dir}/pylib/sdwdate/__init__.py"
   cat > "${work_dir}/pylib/sdwdate/config.py" <<'FAKE_CONFIG_EOF'
import os


def read_pools(pool, mode):
    if os.environ.get("FAKE_READ_POOLS", "urls") == "diagnostic":
        ## The real read_pools prints diagnostics to STDOUT and returns [].
        print('User configuration folder "/etc/sdwdate.d" does not exist.')
        return [], []
    return (["http://pool%dexampleonionaddresspaddingtofiftysix.onion" % pool],
            ["comment"])
FAKE_CONFIG_EOF
}

check() {
   local label expected actual

   label="$1"
   expected="$2"
   actual="$3"

   if [ "${expected}" = "${actual}" ]; then
      passed=$((passed + 1))
      printf '%s\n' "PASS: ${label}"
      return 0
   fi
   failed=$((failed + 1))
   printf '%s\n' "FAIL: ${label}: expected '${expected}', got '${actual}'" >&2
   return 0
}

check_absent() {
   local label needle file

   label="$1"
   needle="$2"
   file="$3"

   if grep --quiet --fixed-strings -- "${needle}" "${file}"; then
      failed=$((failed + 1))
      printf '%s\n' "FAIL: ${label}: '${needle}' unexpectedly present in output" >&2
      return 0
   fi
   passed=$((passed + 1))
   printf '%s\n' "PASS: ${label}"
   return 0
}

## Normal conf: every pool's URLs are emitted, one per line, and nothing else.
case_lists_every_pool_url() {
   local rc=0

   FAKE_READ_POOLS=urls \
   PYTHONPATH="${work_dir}/pylib" \
      "${list_urls}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "list: exits 0" "0" "${rc}"
   check "list: one URL per pool (3)" "3" "$(wc --lines < "${work_dir}/out.log")"
   check_absent "list: no diagnostic text mixed in" "does not exist" "${work_dir}/out.log"
}

## Missing conf: read_pools prints a diagnostic to stdout and returns []. That
## diagnostic must be SUPPRESSED, not emitted as a URL -- otherwise the warm-up
## HEADs a garbage string and its empty-list skip never fires.
case_suppresses_read_pools_diagnostics() {
   local rc=0

   FAKE_READ_POOLS=diagnostic \
   PYTHONPATH="${work_dir}/pylib" \
      "${list_urls}" > "${work_dir}/out.log" 2>&1 || rc=$?

   check "diagnostic: exits 0" "0" "${rc}"
   check "diagnostic: emits nothing (no URLs, no diagnostics)" \
      "0" "$(wc --lines < "${work_dir}/out.log")"
   check_absent "diagnostic: the stdout diagnostic did not leak as a URL" \
      "does not exist" "${work_dir}/out.log"
}

main() {
   if [ ! -x "${list_urls}" ]; then
      printf '%s\n' \
         "FATAL: onion-tester-list-urls not found at '${list_urls}' -- set ONION_TESTER_LIST_URLS_BIN" >&2
      exit 1
   fi
   local total

   work_dir="$(mktemp --directory)"
   trap onion_tester_list_urls_test_cleanup EXIT
   write_fake_sdwdate

   case_lists_every_pool_url
   case_suppresses_read_pools_diagnostics

   total=$((passed + failed))
   printf '%s\n' "onion-tester-list-urls-test: ${total} checks, ${passed} pass, ${failed} fail, 0 skip"
   if [ "${failed}" -ne 0 ]; then
      exit 1
   fi
   exit 0
}

main "${@}"
