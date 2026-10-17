#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## curl.anondist proxy-injection + passthrough logic.
##
## curl cannot resolve .onion via torsocks, so the wrapper instead PREPENDS a
## '--proxy socks5h://...' plus a randomized '--proxy-user <torS0X>0:...' pair
## (Tor stream isolation) before handing argv to uwtwrapper. The decisions
## under test:
##   - UWT_DEV_PASSTHROUGH=1 on entry   -> exec original argv verbatim.
##   - a caller-supplied --proxy / -x / --proxy-user / -U
##                                      -> isolation disabled, original argv.
##   - a loopback 127.0.0.1 or [::1] target
##                                      -> isolation disabled, original argv.
##   - --ipv6 / -6                      -> proxy address becomes [::1]:9050.
##   - --config / -K                    -> exit 1 (two message variants:
##                                         curl.anondist-orig present vs absent).
##   - a failing curl.anondist-orig proxy probe
##                                      -> isolation disabled, original argv.
##   - otherwise                        -> PREPEND the four stream-isolation
##                                         args, then original argv.
## Plus random_alpha_numeric's length/charset contract (the proxy password),
## now SOURCED from strings.bsh rather than duplicated in the wrapper.
##
## Drives the REAL curl.anondist by SOURCING it (it is source-able: pure
## functions + a was_executed-guarded main) via curl_wrapper_probe.sh, which
## records the exec seam's argv. check_runtime.bsh (for was_executed) and
## strings.bsh (for random_alpha_numeric) resolve via HELPER_SCRIPTS_PATH. No
## real uwtwrapper, Tor or proxy is touched; curl.anondist-orig presence is
## controlled by a hermetic per-case bin (coreutils only, so a host curl cannot
## flip a result).
##
## A missing subject / check_runtime.bsh / strings.bsh is a REQUIRED-dependency
## environment bug -> exit 1 (FATAL), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Never inherit a passthrough flag from the caller's env; cases set it explicitly.
if [ -v UWT_DEV_PASSTHROUGH ]; then
   unset UWT_DEV_PASSTHROUGH
fi

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
probe="${tool_dir}/curl_wrapper_probe.sh"

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   subject="${UWT_REPO}/usr/bin/curl.anondist"
else
   subject='/usr/bin/curl.anondist'
fi

## check_runtime.bsh (defines was_executed) and strings.bsh (defines
## random_alpha_numeric): HELPER_SCRIPTS_PATH points at a helper-scripts
## checkout (set by dist-ai-tests-all's wire); unset -> installed /usr/libexec.
## The subject sources both on load, so both must resolve.
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
check_runtime="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/check_runtime.bsh"
strings_bsh="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh"

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set UWT_REPO to a uwt checkout, or install uwt" >&2
   exit 1
fi
if [ ! -r "${check_runtime}" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable at '${check_runtime}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -r "${strings_bsh}" ]; then
   printf '%s\n' "FATAL: strings.bsh not readable at '${strings_bsh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi
if [ ! -x "${probe}" ]; then
   printf '%s\n' "FATAL: test support probe missing or not executable: '${probe}'" >&2
   exit 1
fi

## tr + head: random_alpha_numeric needs them; wc: strings.bsh sources wc-test.sh
## on load. A REQUIRED coreutils dependency.
tr_bin="$(type -P tr)"
head_bin="$(type -P head)"
wc_bin="$(type -P wc)"

test_dir="$(mktemp --directory)"
cleanup_handler() {
   ## '|| true': a cleanup failure must not clobber the script's real exit code.
   safe-rm -r -f -- "${test_dir}" || true
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

## A hermetic bin holding ONLY tr + head + wc (random_alpha_numeric + the
## wc-test.sh strings.bsh sources on load) and, per mode, a curl.anondist-orig
## stub. With no stub the subject's proxy probe ('command -v curl.anondist-orig')
## finds nothing and is skipped, so a host curl.anondist-orig can never leak in
## and flip a result.
##   none      -> no curl.anondist-orig (probe skipped, injection proceeds)
##   curl-ok   -> curl.anondist-orig present, exits 0 (functional Tor probe)
##   curl-fail -> curl.anondist-orig present, exits non-zero (failing probe)
make_bin() {
   local curl_mode="$1" bin
   bin="$(mktemp --directory --tmpdir="${test_dir}")"
   ln --symbolic -- "${tr_bin}" "${bin}/tr"
   ln --symbolic -- "${head_bin}" "${bin}/head"
   ln --symbolic -- "${wc_bin}" "${bin}/wc"
   case "${curl_mode}" in
      curl-ok)
         {
            printf '%s\n' '#!/bin/bash'
            printf '%s\n' 'exit 0'
         } > "${bin}/curl.anondist-orig"
         chmod 0755 -- "${bin}/curl.anondist-orig"
         ;;
      curl-fail)
         {
            printf '%s\n' '#!/bin/bash'
            printf '%s\n' 'exit 1'
         } > "${bin}/curl.anondist-orig"
         chmod 0755 -- "${bin}/curl.anondist-orig"
         ;;
   esac
   printf '%s\n' "${bin}"
}

## Drive main "$@" and populate the globals from the recorded exec argv:
## rec_lines (one recorded arg per element), drive_rc (the probe's exit status),
## drive_err (main's stderr).
## $1 passthrough (1 = set UWT_DEV_PASSTHROUGH=1 on entry), $2 curl mode
## ('none' = no curl.anondist-orig; 'curl-ok'/'curl-fail' = present + exits
## 0/non-zero), remaining args = the curl argv passed to main.
rec_lines=()
drive_rc=0
drive_err=""
drive_main() {
   local passthrough="$1" curl_mode="$2"
   shift 2
   local bin rec err
   bin="$(make_bin "${curl_mode}")"
   rec="$(mktemp --tmpdir="${test_dir}")"
   err="$(mktemp --tmpdir="${test_dir}")"
   local -a env_prefix=(
      "SUBJECT=${subject}"
      "HELPER_SCRIPTS_PATH=${HELPER_SCRIPTS_PATH}"
      "PROBE_MODE=main"
      "PROBE_RECORD=${rec}"
      "PATH=${bin}"
   )
   if [ "${passthrough}" = 1 ]; then
      env_prefix+=( "UWT_DEV_PASSTHROUGH=1" )
   fi
   drive_rc=0
   env "${env_prefix[@]}" "${probe}" "$@" 2> "${err}" || drive_rc=$?
   mapfile -t rec_lines < "${rec}"
   drive_err="$(cat -- "${err}")"
}

## 'yes' iff any recorded arg is a prepended socks5h proxy URL (the injection
## marker); 'no' otherwise. Distinguishes inject from disable/passthrough.
injected_socks5h() {
   local arg
   for arg in "${rec_lines[@]}"; do
      case "${arg}" in
         socks5h://*)
            printf '%s\n' "yes"
            return 0
            ;;
      esac
   done
   printf '%s\n' "no"
}

## Run random_alpha_numeric via the probe and print its output. $@ -> argv for
## random_alpha_numeric (empty = default length 43).
run_rand() {
   local bin
   bin="$(make_bin none)"
   SUBJECT="${subject}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
      PROBE_MODE=rand PATH="${bin}" "${probe}" "$@"
}

## --- Case 1: random_alpha_numeric length + charset (sourced from strings.bsh). ---
rand_default="$(run_rand)"
check "random_alpha_numeric: default length 43" "${#rand_default}" "43"

rand_ten="$(run_rand 10)"
check "random_alpha_numeric: n=10 length 10" "${#rand_ten}" "10"

if [[ "${rand_default}" =~ ^[A-Za-z0-9]*$ ]]; then
   rand_charset=ok
else
   rand_charset=bad
fi
check "random_alpha_numeric: charset [A-Za-z0-9]" "${rand_charset}" "ok"

## --- Case 2: UWT_DEV_PASSTHROUGH=1 -> verbatim argv, no injection. ---
drive_main 1 none 'https://example.com'
check "passthrough: exec gets exactly 1 original arg" "${#rec_lines[@]}" "1"
check "passthrough: arg[0] verbatim"                  "${rec_lines[0]:-}" "https://example.com"
check "passthrough: no proxy injection"               "$(injected_socks5h)" "no"
check "passthrough: probe exits 0"                    "${drive_rc}" "0"

## --- Case 3: a caller-supplied --proxy / -x disables isolation (no injection). ---
drive_main 0 none '--proxy'
check "--proxy: exec gets exactly 1 arg"      "${#rec_lines[@]}" "1"
check "--proxy: original arg passed through"  "${rec_lines[0]:-}" "--proxy"
check "--proxy: no proxy injection"           "$(injected_socks5h)" "no"
if [[ "${drive_err}" == *"WARNING: Detected '--proxy' or '-x' argument."* ]]; then
   proxy_warn=ok
else
   proxy_warn=bad
fi
check "--proxy: warning printed" "${proxy_warn}" "ok"

drive_main 0 none '-x'
check "-x: exec gets exactly 1 arg"     "${#rec_lines[@]}" "1"
check "-x: original arg passed through" "${rec_lines[0]:-}" "-x"
check "-x: no proxy injection"          "$(injected_socks5h)" "no"

## --- Case 4: a caller-supplied --proxy-user / -U disables isolation. ---
drive_main 0 none '--proxy-user'
check "--proxy-user: exec gets exactly 1 arg"     "${#rec_lines[@]}" "1"
check "--proxy-user: original arg passed through" "${rec_lines[0]:-}" "--proxy-user"
check "--proxy-user: no proxy injection"          "$(injected_socks5h)" "no"
if [[ "${drive_err}" == *"WARNING: Detected '--proxy-user' or '-U' argument."* ]]; then
   proxyuser_warn=ok
else
   proxyuser_warn=bad
fi
check "--proxy-user: warning printed" "${proxyuser_warn}" "ok"

drive_main 0 none '-U'
check "-U: exec gets exactly 1 arg"     "${#rec_lines[@]}" "1"
check "-U: original arg passed through" "${rec_lines[0]:-}" "-U"
check "-U: no proxy injection"          "$(injected_socks5h)" "no"

## A loopback target disables isolation but the wrapper STILL execs curl with the
## original argv verbatim. Assert BOTH: no socks5h injection AND the original
## operand reaches the exec seam unchanged (exactly one recorded arg equal to it).
## Checking only "no injection" would also pass if a regression dropped or
## rewrote the request (empty rec_lines), so the passthrough assertion is load-bearing.
check_loopback_passthrough() {
   local label="$1" operand="$2"
   check "${label}: exec gets exactly 1 arg"     "${#rec_lines[@]}" "1"
   check "${label}: original arg passed through" "${rec_lines[0]:-}" "${operand}"
   check "${label}: no proxy injection"          "$(injected_socks5h)" "no"
}

## --- Case 5: a loopback 127.0.0.1 / [::1] target disables isolation. ---
drive_main 0 none 'http://127.0.0.1:8080/'
check_loopback_passthrough "loopback v4" 'http://127.0.0.1:8080/'
if [[ "${drive_err}" == *"NOTE: Detected loopback address."* ]]; then
   loopback_note=ok
else
   loopback_note=bad
fi
check "loopback v4: note printed" "${loopback_note}" "ok"

drive_main 0 none 'http://[::1]:8080/'
check_loopback_passthrough "loopback v6" 'http://[::1]:8080/'

## A loopback address anywhere in 127.0.0.0/8, not just 127.0.0.1.
drive_main 0 none 'http://127.0.0.53:53/'
check_loopback_passthrough "loopback 127/8 (.53)" 'http://127.0.0.53:53/'
drive_main 0 none 'http://127.0.1.1/'
check_loopback_passthrough "loopback 127/8 (.0.1.1)" 'http://127.0.1.1/'

## The 'localhost' hostname is loopback too.
drive_main 0 none 'http://localhost:8080/'
check_loopback_passthrough "loopback localhost" 'http://localhost:8080/'
if [[ "${drive_err}" == *"NOTE: Detected loopback address."* ]]; then
   localhost_note=ok
else
   localhost_note=bad
fi
check "loopback localhost: note printed" "${localhost_note}" "ok"

## A BARE loopback operand (no scheme) must be detected -- the common form for a
## local service. The old ^[^-].* anchor consumed the first char and missed these.
drive_main 0 none 'localhost:8080'
check_loopback_passthrough "loopback bare localhost:port" 'localhost:8080'
drive_main 0 none '127.0.0.1'
check_loopback_passthrough "loopback bare 127.0.0.1" '127.0.0.1'
drive_main 0 none '[::1]'
check_loopback_passthrough "loopback bare [::1]" '[::1]'

## A loopback host behind HTTP basic-auth userinfo (common for local admin APIs)
## is still loopback -- the userinfo is skipped and the real host matched.
drive_main 0 none 'http://admin:secret@127.0.0.1:8080/api'
check_loopback_passthrough "loopback w/ userinfo (127.0.0.1)" 'http://admin:secret@127.0.0.1:8080/api'
drive_main 0 none 'http://user@localhost/'
check_loopback_passthrough "loopback w/ userinfo (localhost)" 'http://user@localhost/'

## ... but a REMOTE host with a loopback literal as the USERNAME must keep its
## isolated circuit (the host is the part after '@', not 'localhost').
drive_main 0 none 'http://localhost:password@example.com/'
check "remote host, 'localhost' as username: proxy injected" "$(injected_socks5h)" "yes"
drive_main 0 none 'http://127.0.0.1@evil.com/'
check "remote host, '127.0.0.1' as username: proxy injected" "$(injected_socks5h)" "yes"

## The authority ends at the first '?' or '#', so a loopback literal in a
## query/fragment of a remote host is NOT the host -- keep isolation.
drive_main 0 none 'http://example.com?email=user@localhost'
check "remote host, loopback in QUERY userinfo-lookalike: proxy injected" "$(injected_socks5h)" "yes"

## An option flag whose VALUE contains '@localhost' is not a destination.
drive_main 0 none '--user=alice@localhost' 'https://example.com/'
check "flag --user=...@localhost + remote URL: proxy injected" "$(injected_socks5h)" "yes"

## An empty port ('http://localhost:/', valid per RFC 3986, curl defaults to 80)
## is still loopback.
drive_main 0 none 'http://localhost:/'
check_loopback_passthrough "loopback empty port" 'http://localhost:/'

## A non-loopback host must STILL be injected. Guards against over-match: a
## loopback literal in the PATH/QUERY, a 'localhost'/'127.'-prefixed SUBDOMAIN or
## a public IP with '127' in a non-leading octet are all REMOTE and must keep
## their isolated circuit.
drive_main 0 none 'http://127examplehost.com/'
check "non-loopback host (127examplehost): proxy injected" "$(injected_socks5h)" "yes"
drive_main 0 none 'https://example.com/localhost'
check "remote URL, localhost in PATH: proxy injected" "$(injected_socks5h)" "yes"
drive_main 0 none 'https://example.com/127.0.0.53'
check "remote URL, 127.x in PATH: proxy injected" "$(injected_socks5h)" "yes"
drive_main 0 none 'http://example.com/?x=127.2.3.4'
check "remote URL, 127.x in QUERY: proxy injected" "$(injected_socks5h)" "yes"
drive_main 0 none 'http://localhost.example/'
check "remote host 'localhost.example': proxy injected" "$(injected_socks5h)" "yes"
drive_main 0 none 'http://127.evil.example/'
check "remote host '127.evil.example': proxy injected" "$(injected_socks5h)" "yes"
drive_main 0 none 'http://1.127.0.0.1/'
check "public IP with non-leading 127: proxy injected" "$(injected_socks5h)" "yes"

## --- Case 6: --ipv6 / -6 -> proxy address becomes [::1]:9050. ---
drive_main 0 none '--ipv6' 'https://example.com'
check "--ipv6: exec gets 6 args (4 injected + 2 original)" "${#rec_lines[@]}" "6"
check "--ipv6: arg[0] --proxy"       "${rec_lines[0]:-}" "--proxy"
check "--ipv6: arg[1] socks5h [::1]" "${rec_lines[1]:-}" "socks5h://[::1]:9050/"
check "--ipv6: arg[4] --ipv6 (original)"       "${rec_lines[4]:-}" "--ipv6"
check "--ipv6: arg[5] url (original)"          "${rec_lines[5]:-}" "https://example.com"
if [[ "${drive_err}" == *"NOTICE: Detected '--ipv6' or '-6' argument"* ]]; then
   ipv6_notice=ok
else
   ipv6_notice=bad
fi
check "--ipv6: notice printed" "${ipv6_notice}" "ok"

drive_main 0 none '-6' 'https://example.com'
check "-6: arg[1] socks5h [::1]" "${rec_lines[1]:-}" "socks5h://[::1]:9050/"

## --- Case 7: --config / -K -> exit 1, two message variants. ---
drive_main 0 curl-ok '-K'
check "-K present: probe exits 1" "${drive_rc}" "1"
check "-K present: no exec"       "${#rec_lines[@]}" "0"
if [[ "${drive_err}" == *"Please use '"* ]] \
   && [[ "${drive_err}" == *"curl.anondist-orig' instead."* ]]; then
   k_present_msg=ok
else
   k_present_msg=bad
fi
check "-K present: message names curl.anondist-orig" "${k_present_msg}" "ok"

drive_main 0 none '-K'
check "-K absent: probe exits 1" "${drive_rc}" "1"
check "-K absent: no exec"       "${#rec_lines[@]}" "0"
if [[ "${drive_err}" == *"cannot handle this."* ]] \
   && [[ "${drive_err}" != *"Please use"* ]]; then
   k_absent_msg=ok
else
   k_absent_msg=bad
fi
check "-K absent: message omits 'Please use'" "${k_absent_msg}" "ok"

drive_main 0 none '--config'
check "--config absent: probe exits 1" "${drive_rc}" "1"
check "--config absent: no exec"       "${#rec_lines[@]}" "0"

## --- Case 8: curl.anondist-orig present but failing probe -> isolation off. ---
drive_main 0 curl-fail 'https://example.com'
check "curl probe fails: exec gets exactly 1 original arg" "${#rec_lines[@]}" "1"
check "curl probe fails: original arg passed through"      "${rec_lines[0]:-}" "https://example.com"
check "curl probe fails: no proxy injection"               "$(injected_socks5h)" "no"
if [[ "${drive_err}" == *"WARNING: Tor proxy doesn't seem to be functional."* ]]; then
   torfail_warn=ok
else
   torfail_warn=bad
fi
check "curl probe fails: warning printed" "${torfail_warn}" "ok"

## --- Case 9: normal argv, curl.anondist-orig absent -> four args PREPENDED. ---
drive_main 0 none 'https://example.com'
check "injection: exec gets 5 args (4 injected + 1 original)" "${#rec_lines[@]}" "5"
check "injection: arg[0] --proxy"           "${rec_lines[0]:-}" "--proxy"
check "injection: arg[1] socks5h 127.0.0.1" "${rec_lines[1]:-}" "socks5h://127.0.0.1:9050/"
check "injection: arg[2] --proxy-user"      "${rec_lines[2]:-}" "--proxy-user"
case "${rec_lines[3]:-}" in
   '<torS0X>0:curl-wrapper_'*)
      injection_user_prefix=ok
      ;;
   *)
      injection_user_prefix=bad
      ;;
esac
check "injection: arg[3] proxy-user prefix" "${injection_user_prefix}" "ok"
injection_user_tail="${rec_lines[3]:-}"
injection_user_tail="${injection_user_tail#'<torS0X>0:curl-wrapper_'}"
check "injection: proxy-user random tail length 43" "${#injection_user_tail}" "43"
if [[ "${injection_user_tail}" =~ ^[A-Za-z0-9]*$ ]]; then
   injection_tail_charset=ok
else
   injection_tail_charset=bad
fi
check "injection: proxy-user random tail charset [A-Za-z0-9]" "${injection_tail_charset}" "ok"
check "injection: arg[4] url (original)" "${rec_lines[4]:-}" "https://example.com"
check "injection: probe exits 0"         "${drive_rc}" "0"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
