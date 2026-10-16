#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dnf-3.anondist proxy-injection + passthrough logic.
##
## dnf uses curl, which cannot resolve .onion via torsocks, so the wrapper
## instead injects a '--setopt=proxy=socks5h://...' plus a randomized
## username/password pair (Tor stream isolation) before handing argv to
## uwtwrapper. The decisions under test:
##   - UWT_DEV_PASSTHROUGH=1 on entry  -> exec original argv verbatim, no wait.
##   - a caller-supplied --setopt=proxy / proxy_username / proxy_password
##                                     -> isolation disabled, original argv.
##   - a failing curl.anondist-orig proxy probe
##                                     -> isolation disabled, original argv.
##   - otherwise                       -> PREPEND the three stream-isolation
##                                        args, then original argv.
## Plus random_alpha_numeric's length/charset contract (the proxy password).
##
## Drives the REAL dnf-3.anondist by SOURCING it (it is source-able: pure
## functions + a was_executed-guarded main) via dnf3_wrapper_probe.sh, which
## records the exec seam's argv and no-ops the Tor wait. check_runtime.bsh (for
## was_executed) resolves via HELPER_SCRIPTS_PATH. No real uwtwrapper, Tor,
## leaprun or proxy is touched; curl.anondist-orig presence is controlled by a
## hermetic per-case bin (coreutils only, so a host curl cannot flip a result).
##
## A missing subject / check_runtime.bsh is a REQUIRED-dependency environment
## bug -> exit 1 (FATAL), never a skip.

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
probe="${tool_dir}/dnf3_wrapper_probe.sh"

[ -v UWT_REPO ] || UWT_REPO=""
if [ -n "${UWT_REPO}" ]; then
   subject="${UWT_REPO}/usr/bin/dnf-3.anondist"
else
   subject='/usr/bin/dnf-3.anondist'
fi

## check_runtime.bsh (defines was_executed): HELPER_SCRIPTS_PATH points at a
## helper-scripts checkout (set by dist-ai-tests-all's wire); unset -> installed
## /usr/libexec. The subject sources it on load, so it must resolve.
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""
check_runtime="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/check_runtime.bsh"

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
## wc-test.sh strings.bsh sources on load) and, for 'curl-fail', a
## curl.anondist-orig stub that exits non-zero. With no stub
## the subject's proxy probe ('command -v curl.anondist-orig') finds nothing and
## is skipped, so a host curl.anondist-orig can never leak in and flip a result.
make_bin() {
   local curl_mode="$1" bin
   bin="$(mktemp --directory --tmpdir="${test_dir}")"
   ln --symbolic -- "${tr_bin}" "${bin}/tr"
   ln --symbolic -- "${head_bin}" "${bin}/head"
   ln --symbolic -- "${wc_bin}" "${bin}/wc"
   if [ "${curl_mode}" = 'curl-fail' ]; then
      {
         printf '%s\n' '#!/bin/bash'
         printf '%s\n' 'exit 1'
      } > "${bin}/curl.anondist-orig"
      chmod 0755 -- "${bin}/curl.anondist-orig"
   fi
   printf '%s\n' "${bin}"
}

## Drive main "$@" and populate the globals from the recorded exec argv:
## rec_lines (one recorded arg per element), wait_lines (non-empty iff the Tor
## wait was reached), drive_rc (the probe's exit status).
## $1 passthrough (1 = set UWT_DEV_PASSTHROUGH=1 on entry), $2 curl mode
## ('none' = no curl.anondist-orig; 'curl-fail' = present + exits non-zero),
## remaining args = the dnf argv passed to main.
rec_lines=()
wait_lines=()
drive_rc=0
drive_main() {
   local passthrough="$1" curl_mode="$2"
   shift 2
   local bin rec wait_file
   bin="$(make_bin "${curl_mode}")"
   rec="$(mktemp --tmpdir="${test_dir}")"
   wait_file="$(mktemp --tmpdir="${test_dir}")"
   local -a env_prefix=(
      "SUBJECT=${subject}"
      "HELPER_SCRIPTS_PATH=${HELPER_SCRIPTS_PATH}"
      "PROBE_MODE=main"
      "PROBE_RECORD=${rec}"
      "PROBE_WAIT=${wait_file}"
      "PATH=${bin}"
   )
   if [ "${passthrough}" = 1 ]; then
      env_prefix+=( "UWT_DEV_PASSTHROUGH=1" )
   fi
   drive_rc=0
   env "${env_prefix[@]}" "${probe}" "$@" || drive_rc=$?
   mapfile -t rec_lines < "${rec}"
   mapfile -t wait_lines < "${wait_file}"
}

## Run random_alpha_numeric via the probe and print its output. $@ -> argv for
## random_alpha_numeric (empty = default length 43).
run_rand() {
   local bin
   bin="$(make_bin none)"
   SUBJECT="${subject}" HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" \
      PROBE_MODE=rand PATH="${bin}" "${probe}" "$@"
}

## --- Case 1: random_alpha_numeric length + charset. ---
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

## --- Case 2: a caller-supplied proxy arg disables isolation (no injection). ---
drive_main 0 none '--setopt=proxy=socks5h://x'
check "proxy arg: exec gets exactly 1 arg"        "${#rec_lines[@]}" "1"
check "proxy arg: original arg passed through"    "${rec_lines[0]:-}" "--setopt=proxy=socks5h://x"
check "proxy arg: Tor wait was reached"           "${#wait_lines[@]}" "1"
check "proxy arg: probe exits 0"                  "${drive_rc}" "0"

drive_main 0 none '--setopt=proxy_username=foo'
check "proxy_username arg: exec gets exactly 1 arg"     "${#rec_lines[@]}" "1"
check "proxy_username arg: original arg passed through" "${rec_lines[0]:-}" "--setopt=proxy_username=foo"

drive_main 0 none '--setopt=proxy_password=bar'
check "proxy_password arg: exec gets exactly 1 arg"     "${#rec_lines[@]}" "1"
check "proxy_password arg: original arg passed through" "${rec_lines[0]:-}" "--setopt=proxy_password=bar"

## --- Case 3: UWT_DEV_PASSTHROUGH=1 -> verbatim argv, no injection, no wait. ---
drive_main 1 none 'install' 'vim'
check "passthrough: exec gets exactly original 2 args" "${#rec_lines[@]}" "2"
check "passthrough: arg[0] install"                    "${rec_lines[0]:-}" "install"
check "passthrough: arg[1] vim"                        "${rec_lines[1]:-}" "vim"
check "passthrough: Tor wait NOT reached"              "${#wait_lines[@]}" "0"
passthrough_injected=no
for arg in "${rec_lines[@]}"; do
   case "${arg}" in
      --setopt=proxy=*)
         passthrough_injected=yes
         ;;
   esac
done
check "passthrough: no proxy injection" "${passthrough_injected}" "no"

## --- Case 4: normal argv, curl.anondist-orig absent -> three args PREPENDED. ---
drive_main 0 none 'install' 'vim'
check "injection: exec gets 5 args (3 injected + 2 original)" "${#rec_lines[@]}" "5"
check "injection: arg[0] proxy socks5h" \
   "${rec_lines[0]:-}" "--setopt=proxy=socks5h://127.0.0.1:9050/"
check "injection: arg[1] proxy_username" \
   "${rec_lines[1]:-}" "--setopt=proxy_username=<torS0X>0"
case "${rec_lines[2]:-}" in
   --setopt=proxy_password=dnf-wrapper_*)
      injection_pw_prefix=ok
      ;;
   *)
      injection_pw_prefix=bad
      ;;
esac
check "injection: arg[2] proxy_password prefix" "${injection_pw_prefix}" "ok"
injection_pw_tail="${rec_lines[2]:-}"
injection_pw_tail="${injection_pw_tail#--setopt=proxy_password=dnf-wrapper_}"
if [ -n "${injection_pw_tail}" ]; then
   injection_pw_tail_ok=ok
else
   injection_pw_tail_ok=bad
fi
check "injection: proxy_password random tail is non-empty" "${injection_pw_tail_ok}" "ok"
check "injection: arg[3] install (original)" "${rec_lines[3]:-}" "install"
check "injection: arg[4] vim (original)"     "${rec_lines[4]:-}" "vim"
check "injection: Tor wait was reached"      "${#wait_lines[@]}" "1"
check "injection: probe exits 0"             "${drive_rc}" "0"

## --- Case 5: normal argv, curl.anondist-orig present but failing probe
##             -> isolation disabled, original argv (no injection). ---
drive_main 0 curl-fail 'install' 'vim'
check "curl probe fails: exec gets exactly 2 original args" "${#rec_lines[@]}" "2"
check "curl probe fails: arg[0] install"                    "${rec_lines[0]:-}" "install"
check "curl probe fails: arg[1] vim"                        "${rec_lines[1]:-}" "vim"
curlfail_injected=no
for arg in "${rec_lines[@]}"; do
   case "${arg}" in
      --setopt=proxy=*)
         curlfail_injected=yes
         ;;
   esac
done
check "curl probe fails: no proxy injection" "${curlfail_injected}" "no"
check "curl probe fails: Tor wait was reached" "${#wait_lines[@]}" "1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
