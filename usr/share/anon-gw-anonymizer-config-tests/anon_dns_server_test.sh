#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## anon-dns: where the nameserver value comes from, and what happens when
## qubesdb-read fails or prints nothing.
##
## THE BUG: a FAILING qubesdb-read killed the script under errexit, and an
## EMPTY one wrote a bare "nameserver " line into /etc/resolv.conf -- a
## resolv.conf with no address, silently. The fix refuses in both cases rather
## than guessing, so each is asserted here as a refusal AND as the absence of
## any nameserver line.
##
## anon-dns hardcodes /etc/resolv.conf and sources helper-scripts from an
## absolute path, so every case runs under bwrap with both bound over. Nothing
## touches the real system, and qubesdb-read is stubbed PER CASE and kept off
## PATH entirely for the 'absent' case -- letting the host's real qubesdb-read
## decide is how an earlier version of this left the Qubes branch outside the
## test's control.
##
## No root, no network, no Qubes.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v ANON_GW_ANONYMIZER_CONFIG_REPO ] || ANON_GW_ANONYMIZER_CONFIG_REPO=""

if [ -n "${ANON_GW_ANONYMIZER_CONFIG_REPO}" ]; then
   subject="${ANON_GW_ANONYMIZER_CONFIG_REPO}/usr/bin/anon-dns"
else
   subject='/usr/bin/anon-dns'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: anon-dns not found at '${subject}'" >&2
   printf '%s\n' "set ANON_GW_ANONYMIZER_CONFIG_REPO to a checkout, or install the package" >&2
   exit 77
fi

work_dir="$(mktemp --directory -- "${TMP}/anon-dns-test.XXXXXX")"

test_cleanup_handler() {
   chmod --recursive u+rwX -- "${work_dir}" 2>/dev/null || true
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the stub bodies below are LITERAL code written to a file; '$1'/'$2'
## must reach the stub unexpanded.
## SC2086: env_spec is a pre-split assignment list and is deliberately
## unquoted -- quoting it hands env the whole string as ONE name.
# shellcheck disable=SC2016,SC2086
run_anon_dns() {
   local qubesdb_mode env_spec base bin etc helpers tool real

   qubesdb_mode="$1"
   env_spec="$2"

   base="${work_dir}/case"
   chmod --recursive u+rwX -- "${base}" 2>/dev/null || true
   safe-rm --recursive --force -- "${base}"
   bin="${base}/bin"
   etc="${base}/etc"
   helpers="${base}/helpers"
   mkdir --parents -- "${bin}" "${etc}" "${helpers}"

   ## ONLY the tools the script needs, so 'absent' genuinely means absent.
   for tool in bash sh grep sed cat touch chmod id timeout printf tee; do
      ## 'type -P' rather than R-090's 'has': what is wanted here is the PATH,
      ## not a yes/no, and 'has' answers only the latter.
      real="$(type -P "${tool}" || true)"
      if [ -n "${real}" ]; then
         ln --symbolic --force -- "${real}" "${bin}/${tool}"
      fi
   done

   case "${qubesdb_mode}" in
      good)
         printf '%s\n' '#!/bin/bash' 'printf "%s\n" "10.139.1.1"' >"${bin}/qubesdb-read"
         ;;
      fail)
         printf '%s\n' '#!/bin/bash' 'exit 1' >"${bin}/qubesdb-read"
         ;;
      empty)
         printf '%s\n' '#!/bin/bash' 'exit 0' >"${bin}/qubesdb-read"
         ;;
      absent)
         true "qubesdb-read deliberately not created"
         ;;
   esac
   if [ ! "${qubesdb_mode}" = absent ]; then
      chmod 0755 -- "${bin}/qubesdb-read"
   fi

   printf '%s\n' '#!/bin/bash' 'printf "%s\n" "$2" >>"$1"' >"${bin}/append-once"
   chmod 0755 -- "${bin}/append-once"

   ## as_root must be a no-op: the real one re-execs under sudo.
   printf '%s\n' 'as_root() { true; }' >"${helpers}/as_root.sh"
   ## 'type -t' rather than 'command -v': R-090 forbids the latter, and the
   ## gate greps this line even though it is a stub BODY. For this fixture the
   ## two are equivalent -- anon-dns only uses 'has' to probe whether
   ## qubesdb-read exists, and the 'absent' case removes it from PATH entirely.
   printf '%s\n' 'has() { [ -n "$(type -t "$1")" ]; }' >"${helpers}/has.sh"

   true >"${etc}/resolv.conf"

   ## The 'true "INFO: ..."' lines are the script's ONLY user-visible output
   ## under set -x, so they are kept; every other '+' line is a command trace,
   ## which necessarily changes when the code is restructured and says nothing
   ## about behaviour.
   bwrap --dev-bind / / \
      --bind "${helpers}" /usr/libexec/helper-scripts \
      --bind "${etc}" /etc \
      -- env PATH="${bin}" ${env_spec} timeout 20 bash "${subject}" 2>&1 \
      | grep --invert-match --extended-regexp -- '^\++ ' || true
   printf '%s' "__RESOLV__$(tr '\n' '|' <"${etc}/resolv.conf" 2>/dev/null)"
}

## check <description> <must-contain, anywhere> <resolv.conf must NOT contain, or ''>
##       <qubesdb mode> <env spec>
##
## The second assertion is scoped to the resolv.conf CONTENT, after the
## __RESOLV__ marker, not to the whole output: the refusal message itself
## mentions the word 'nameserver', so a blunt whole-output check fails a
## correct script.
check() {
   local description must_contain resolv_must_not_contain output resolv verdict

   description="$1"
   must_contain="$2"
   resolv_must_not_contain="$3"
   shift 3

   output="$(run_anon_dns "$@")"
   resolv="${output##*__RESOLV__}"

   verdict=PASS
   if ! printf '%s\n' "${output}" | grep --fixed-strings -- "${must_contain}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${must_contain}'"
   elif [ -n "${resolv_must_not_contain}" ] \
      && printf '%s\n' "${resolv}" | grep --fixed-strings -- "${resolv_must_not_contain}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: resolv.conf must NOT contain '${resolv_must_not_contain}'"
      printf '%s\n' "  resolv.conf: [${resolv}]"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

check 'not Qubes: the 10.0.2.3 fallback is used' \
   'nameserver 10.0.2.3' '' absent '--unset=dns_server'
check 'Qubes: qubesdb-read value is used' \
   'nameserver 10.139.1.1' '' good '--unset=dns_server'
check 'a preset dns_server wins over qubesdb-read' \
   'nameserver 192.0.2.53' '' good 'dns_server=192.0.2.53'

## The two the fix is about. Asserting the refusal alone is not enough: the
## point is that NO nameserver is guessed, so the absence of the line is
## asserted too. Before the fix, 'fail' killed the script under errexit and
## 'empty' wrote a bare "nameserver " with no address.
check 'Qubes: a FAILING qubesdb-read refuses, and writes no nameserver' \
   'ERROR' 'nameserver' fail '--unset=dns_server'
check 'Qubes: an EMPTY qubesdb-read refuses, and writes no nameserver' \
   'ERROR' 'nameserver' empty '--unset=dns_server'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
