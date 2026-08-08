#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## tor-ctrl's get_socket(): the two pipelines whose grep finds nothing.
##
## THE BUG: get_socket discovers the control port by piping 'tor
## --verify-config' output through grep. When that grep matches nothing --
## which is the COMMON case, not an error, because the default Debian torrc
## defines neither ControlPort nor ControlSocket -- the pipeline returns
## non-zero and 'set -o pipefail' aborted the script, jumping straight over the
## empty-value guard that exists to handle exactly that case.
##
## Each case here drives get_socket directly and asserts that it RUNS TO THE
## END and reports the value it should. Reaching the end is not sufficient on
## its own: a version that discovered nothing at all would reach the end too,
## so the discovered socket value is asserted as well.
##
## get_socket is extracted and run on its own rather than through the real
## tor-ctrl, which would need a live tor. 'tor' itself is stubbed to print what
## the real one prints for a non-root caller and exit 1 -- the non-zero exit the
## script's own comment says to ignore, and the trigger for the abort.
##
## No tor, no network, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v TOR_CTRL_REPO ] || TOR_CTRL_REPO=""

if [ -n "${TOR_CTRL_REPO}" ]; then
   tor_ctrl_bin="${TOR_CTRL_REPO}/usr/bin/tor-ctrl"
else
   tor_ctrl_bin="/usr/bin/tor-ctrl"
fi

if [ ! -r "${tor_ctrl_bin}" ]; then
   printf '%s\n' "SKIP: tor-ctrl not found at '${tor_ctrl_bin}'" >&2
   printf '%s\n' "set TOR_CTRL_REPO to a tor-ctrl checkout, or install the package" >&2
   exit 77
fi

## The subject is a bash FUNCTION lifted out of the file. If the definition
## stops matching this anchor -- a rename, or a reformat to 'get_socket ()' --
## the extraction yields an empty driver that runs clean and reports nothing,
## which is the exact way three sibling harnesses silently stopped testing
## anything. Fail loudly instead.
if ! grep --quiet -- '^get_socket(){' "${tor_ctrl_bin}"; then
   printf '%s\n' "FATAL: no 'get_socket(){' definition in '${tor_ctrl_bin}'" >&2
   printf '%s\n' "the extraction anchor no longer matches; this test would pass vacuously" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/tor-ctrl-get-socket-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the driver and stub bodies below are LITERAL code written to a file,
## not text this shell should expand.
# shellcheck disable=SC2016
run_get_socket() {
   local torrc verify base verify_real verify_quoted

   torrc="$1"
   verify="$2"

   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   mkdir --parents -- "${base}/bin"
   printf '%s' "${torrc}" >"${base}/torrc"

   ## The placeholder becomes the FIXTURE's torrc path. Without it the script
   ## greps a literal file named TORRC, and the case meant to FIND a ControlPort
   ## silently reads the HOST's real tor configuration instead.
   verify_real="${verify//TORRC/${base}/torrc}"
   ## '@Q' shell-quotes the value for the generated stub, so the fixture text
   ## is embedded exactly, newlines and all, without a printf format verb here.
   verify_quoted="${verify_real@Q}"
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' "printf '%s' ${verify_quoted}"
      printf '%s\n' 'exit 1'
   } >"${base}/bin/tor"
   chmod 0755 -- "${base}/bin/tor"

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
         'set -o errtrace' 'shopt -s inherit_errexit'
      printf '%s\n' 'tor_start_command=""' 'tor_config_files=""' \
         'tor_control_socket_filesystem=""'
      sed -n '/^get_socket(){/,/^}/p' "${tor_ctrl_bin}"
      printf '%s\n' 'get_socket'
      printf '%s\n' 'printf "%s\n" "socket=[${tor_control_socket_filesystem}]"'
      printf '%s\n' 'printf "%s\n" "REACHED_END"'
   } >"${base}/driver"

   ## /lib/systemd/system/tor@default.service MUST be hidden. get_socket reads
   ## it to set tor_start_command, and on any host where it exists the driver
   ## then runs the REAL tor instead of the stub and parses the REAL system
   ## torrc -- so the fixture is ignored and the case silently tests the host.
   ## Binding /dev/null over it makes 'test -f' false (a character device is not
   ## a regular file) without touching anything outside the namespace.
   bwrap --dev-bind / / \
      --bind /dev/null /lib/systemd/system/tor@default.service \
      -- env PATH="${base}/bin:${PATH}" timeout 20 bash "${base}/driver" 2>&1 || true
}

## check <description> <expected socket line> <torrc> <verify-config output>
check() {
   local description expected_socket output verdict

   description="$1"
   expected_socket="$2"
   shift 2

   output="$(run_get_socket "$@")"

   verdict=PASS
   if ! printf '%s\n' "${output}" | grep --fixed-strings -- 'REACHED_END' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: get_socket aborted before the end"
   elif ! printf '%s\n' "${output}" | grep --fixed-strings -- "${expected_socket}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${expected_socket}'"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}: ${expected_socket}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

including_line='Jan 1 00:00:00.000 [notice] Including configuration file "TORRC".'

## The DEFAULT Debian torrc: neither ControlPort nor ControlSocket. This is the
## common case, and it is the one that aborted.
check 'torrc with no ControlPort or ControlSocket' 'socket=[]' \
   'SocksPort 9050
Log notice syslog
' "${including_line}"

## A torrc that does define one must still be found, unchanged.
check 'torrc with a ControlPort is still found' 'socket=[9051]' \
   'SocksPort 9050
ControlPort 9051
' "${including_line}"

## tor --verify-config printing nothing at all: the other no-match pipeline.
check 'verify-config prints nothing at all' 'socket=[]' \
   'SocksPort 9050
' ''

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
