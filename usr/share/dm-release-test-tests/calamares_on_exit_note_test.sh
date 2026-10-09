#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-calamares-install's on_exit writes a FAILED note into the published check-log.
## It must only point at "the published screenshot" when one was ACTUALLY published
## (a non-empty ${shot} after the stuck-screenshot copy); otherwise a bare 'FAILED
## (rc=N)' note. Previously the screenshot sentence was unconditional, so a run that
## captured no screenshot still told the results plane to "see the published
## screenshot" -- a false diagnostic. Sources the REAL script (no copy) and drives
## on_exit; vm_started=false so no VBox call is made.
##
## --keep-failed: a kept VM must have EVERY configured NIC unplugged, else it is
## powered off, and a failed poweroff must be reported as an error -- never as
## "network unplugged" or "powered it off". Driven with a recording VBoxManage stub.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_CALAMARES_INSTALL_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-calamares-install" ]; then
      subject="${test_dir}/../../bin/dm-calamares-install"
   else
      subject='/usr/bin/dm-calamares-install'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found at ${subject}" >&2; exit 1; }

# shellcheck source=../../bin/dm-calamares-install
source "${subject}"

workdir="$(mktemp --directory --tmpdir calamares-on-exit-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s\n' "${label}"
      pass=$((pass + 1))
   else
      printf 'FAIL: %s (got %s, want %s)\n' "${label}" "${got}" "${want}"
      fail=$((fail + 1))
   fi
}

## Drive the real on_exit with a simulated exit rc, a given shot path, and whether a
## stuck screenshot exists; print the resulting check-log, classified: 'shot-note'
## (points at a screenshot), 'generic' (bare FAILED), or 'empty' (nothing written).
run_on_exit() {
   local rc="$1" shot_arg="$2" want_stuck="$3" shot_dir_arg="${4:-}"
   local run_home="${workdir}/home.$$.${RANDOM}"
   local clog="${workdir}/clog.$$.${RANDOM}"
   mkdir --parents -- "${run_home}"
   touch -- "${clog}"
   if [ "${want_stuck}" = yes ]; then
      printf 'STUCK-SCREENSHOT-BYTES' > "${run_home}/dm-calamares-install-stuck.png"
   fi
   ## on_exit reads these as globals via dynamic scope -- shellcheck cannot see the
   ## use through the eval'd function, hence SC2034. The subshell inherits them and
   ## on_exit's final 'exit' terminates only that subshell. shot_dir is the milestone
   ## "full story" dir (empty for the single-shot cases).
   # shellcheck disable=SC2034
   local me='dm-calamares-install' shot="${shot_arg}" check_log="${clog}" \
      shot_dir="${shot_dir_arg}" vm_started='false' VBOXMANAGE=':' HOME="${run_home}"
   (
      ## Set $? to the simulated run rc that on_exit reads as 'local rc=$?'.
      ( exit "${rc}" )
      on_exit
   ) >/dev/null 2>&1 || true
   local out
   out="$(cat -- "${clog}")"
   case "${out}" in
      '')
         printf 'empty'
         ;;
      *'see the published screenshot'*)
         printf 'shot-note'
         ;;
      *FAILED*)
         printf 'generic'
         ;;
      *)
         printf 'other:%s' "${out}"
         ;;
   esac
}

## 1. A real screenshot WAS published (stuck copied into the empty shot) -> the note
##    may point at it.
shot_a="${workdir}/shot_a.png"
touch -- "${shot_a}"
check "published screenshot -> note points at it" "$(run_on_exit 5 "${shot_a}" yes)" 'shot-note'

## 2. A shot path was given but NO screenshot captured (no stuck) -> generic note,
##    never 'see the published screenshot'. (Canary: the pre-fix note was unconditional.)
shot_b="${workdir}/shot_b.png"
touch -- "${shot_b}"
check "shot path but none captured -> generic note" "$(run_on_exit 5 "${shot_b}" no)" 'generic'

## 3. No --shot at all -> generic note, no screenshot text.
check "no shot configured -> generic note" "$(run_on_exit 5 '' no)" 'generic'

## 4. A successful run writes no failure note at all.
check "rc 0 writes no note" "$(run_on_exit 0 '' no)" 'empty'

## 5. On a FAILED run with a --shot-dir set, the stuck screen is appended to the
##    milestone "full story" as 99-failure.png, so the sequence ends on the error.
story_home="${workdir}/story_home"
story_dir="${story_home}/shots"
mkdir --parents -- "${story_dir}"
printf 'STUCK' > "${story_home}/dm-calamares-install-stuck.png"
(
   # shellcheck disable=SC2034
   me='dm-calamares-install' shot='' check_log="${workdir}/story_clog" \
      shot_dir="${story_dir}" vm_started='false' VBOXMANAGE=':' HOME="${story_home}"
   touch -- "${check_log}"
   ( exit 5 )
   on_exit
) >/dev/null 2>&1 || true
check "failed run appends 99-failure.png to the full-story dir" \
   "$([ -s "${story_dir}/99-failure.png" ] && printf yes || printf no)" 'yes'

## --keep-failed. The stub reports the NICs in STUB_NICS (index=type), fails
## setlinkstateN for N in STUB_FAIL_NICS, fails poweroff when STUB_POWEROFF_FAIL=1,
## and logs every call. Prints: <stderr verdict> <poweroff attempted yes|no>.
vbox_stub="${workdir}/VBoxManage"
cat > "${vbox_stub}" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${STUB_LOG}"
case "$1 ${3:-}" in
   'showvminfo --machinereadable')
      for entry in ${STUB_NICS}; do
         printf '%s\n' "nic${entry%%=*}=\"${entry#*=}\""
      done
      ;;
   'controlvm setlinkstate'*)
      nic="${3#setlinkstate}"
      case " ${STUB_FAIL_NICS} " in
         *" ${nic} "*)
            exit 1
            ;;
      esac
      ;;
   'controlvm poweroff')
      [ "${STUB_POWEROFF_FAIL}" != 1 ] || exit 1
      ;;
esac
exit 0
EOF
chmod +x -- "${vbox_stub}"

run_keep_failed() {
   local nic_spec="$1" fail_nics="$2" poweroff_fail="$3"
   local stub_log="${workdir}/stub.$$.${RANDOM}" stub_err="${workdir}/err.$$.${RANDOM}"
   local verdict poweroff
   touch -- "${stub_log}"
   # shellcheck disable=SC2034
   local me='dm-calamares-install' shot='' check_log='' shot_dir='' \
      vm='vm-under-test' vm_started='true' keep_failed='true' \
      VBOXMANAGE="${vbox_stub}" HOME="${workdir}"
   (
      export STUB_LOG="${stub_log}" STUB_NICS="${nic_spec}" STUB_FAIL_NICS="${fail_nics}" \
         STUB_POWEROFF_FAIL="${poweroff_fail}"
      ( exit 5 )
      on_exit
   ) >/dev/null 2>"${stub_err}" || true
   case "$(cat -- "${stub_err}")" in
      *ERROR*'poweroff FAILED'*)
         verdict='error'
         ;;
      *'powered it off instead'*)
         verdict='poweroff'
         ;;
      *'network unplugged'*)
         verdict='kept'
         ;;
      *)
         verdict='other'
         ;;
   esac
   poweroff='no'
   grep --quiet -- 'controlvm vm-under-test poweroff' "${stub_log}" && poweroff='yes'
   printf '%s\n' "${verdict} ${poweroff}"
}

check "keep-failed: every NIC unplugged -> kept, no poweroff" \
   "$(run_keep_failed '1=nat 2=intnet 3=none' '' 0)" 'kept no'
check "keep-failed: a NIC beyond 8 (ICH9) is unplugged too; its failure -> powered off" \
   "$(run_keep_failed '1=nat 12=nat' '12' 0)" 'poweroff yes'
check "keep-failed: a secondary NIC unplug fails -> powered off" \
   "$(run_keep_failed '1=nat 2=nat' '2' 0)" 'poweroff yes'
check "keep-failed: unplug AND poweroff fail -> loud error, no success claim" \
   "$(run_keep_failed '1=nat 2=nat' '2' 1)" 'error yes'
check "keep-failed: no NIC readable -> powered off" \
   "$(run_keep_failed '' '' 0)" 'poweroff yes'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
