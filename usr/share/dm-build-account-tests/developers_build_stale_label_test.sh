#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-developers-build labels the ISO from `git describe` of the reference checkout, so a
## missing release tag silently ships a MISLABELLED ISO. Drive the REAL script under a stub
## PATH (no root, no network, no build) and assert both preconditions DIE before seeding:
## a failed tag fetch, and a describe that is empty or not a release tag. rsync (the
## first step after the check) is stubbed to exit 99, the "reached seeding" sentinel.
## Canary: downgrading either die back to a warning lets rsync run and fails a case below.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_DEVELOPERS_BUILD_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-developers-build" ]; then
      subject="${test_dir}/../../bin/dm-developers-build"
   else
      subject='/usr/bin/dm-developers-build'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-developers-build not found at ${subject}" >&2; exit 1; }

failures=0
ok()  { printf '%s\n' "ok: $1"; }
bad() { printf '%s\n' "FAIL: $1" >&2; failures=$((failures + 1)); }

work="$(mktemp --directory)"
## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
test_cleanup_handler() {
   safe-rm --recursive --force -- "${work}" || true
}
trap test_cleanup_handler EXIT

stub_bin="${work}/bin"
calls="${work}/calls.log"
source_checkout="${work}/reference"
mkdir --parents -- "${stub_bin}" "${source_checkout}/.git" "${work}/home"

make_stub() {
   local name="$1" body="$2"
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' "printf '%s\\n' \"${name} \$*\" >> \"${calls}\""
      printf '%s\n' "${body}"
   } > "${stub_bin}/${name}"
   chmod +x "${stub_bin}/${name}"
}
## The single-quoted bodies expand in the STUB, not here.
make_stub id 'printf "0\n"'
make_stub dm-build-account 'printf "persist-bild-kicksecure\n"'
make_stub getent "printf 'persist-bild-kicksecure:x:1:1::%s:/bin/bash\n' '${work}/home'"
make_stub stat 'printf "admin\n"'
## runuser -u USER -- CMD...: drop the account switch, run CMD.
# shellcheck disable=SC2016
make_stub runuser 'shift 3; exec "$@"'
## describe models a HEAD carrying help-steps/sign-tag-head's ephemeral
## '<tag>_<commit>_<fingerprint>' tag: real git returns it unless the caller passes
## --exclude '*_*_*', so a describe without the exclude sees the signing tag.
# shellcheck disable=SC2016
make_stub git '
case "$*" in
   *" fetch "*) exit "${STUB_FETCH_RC:-0}" ;;
   *" describe "*)
      [ -n "${STUB_DESC:-}" ] || exit 128
      case "$*" in
         *"--exclude *_*_*"*) printf "%s\n" "${STUB_DESC}" ;;
         *) printf "%s\n" "${STUB_DESC%%-[0-9]*-g*}_0123abcd_F31F9496" ;;
      esac
      ;;
esac'
make_stub rsync 'exit 99'

## run_case NAME FETCH_RC DESC WANT(die|seed)
run_case() {
   local name="$1" fetch_rc="$2" desc="$3" want="$4" rc=0 err="${work}/stderr"
   true >| "${calls}"
   PATH="${stub_bin}:${PATH}" \
      DM_BUILD_ACCOUNT="${stub_bin}/dm-build-account" \
      STUB_FETCH_RC="${fetch_rc}" STUB_DESC="${desc}" \
      bash -- "${subject}" kicksecure --source-checkout "${source_checkout}" \
      >/dev/null 2>"${err}" || rc=$?
   if [ "${want}" = 'die' ]; then
      if [ "${rc}" -eq 1 ] && grep --quiet -- 'ERROR:' "${err}" \
         && ! grep --quiet -- '^rsync ' "${calls}"; then
         ok "${name}: died before seeding"
      else
         bad "${name}: expected die (rc 1, no rsync), got rc=${rc}; stderr: $(cat -- "${err}")"
      fi
   else
      if [ "${rc}" -eq 99 ] && grep --quiet -- '^rsync ' "${calls}"; then
         ok "${name}: reached seeding"
      else
         bad "${name}: expected to reach seeding (rc 99), got rc=${rc}; stderr: $(cat -- "${err}")"
      fi
   fi
}

run_case 'tag fetch fails' 1 '18.2.3.6-developers-only-3-gabcdef0' die
run_case 'describe empty' 0 '' die
run_case 'describe bare version, no release suffix' 0 '18.2.3.6' die
run_case 'describe non-release tag' 0 'adrelanos_f65a6f9f' die
run_case 'describe exact developers-only tag' 0 '18.2.3.6-developers-only' seed
run_case 'describe developers-only plus commits' 0 '18.2.3.6-developers-only-3-gabcdef0' seed
run_case 'describe testers-only tag' 0 '18.2.3.6-testers-only' seed
run_case 'describe stable plus commits' 0 '18.2.3.6-stable-2-g0123abc' seed

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "${failures} case(s) failed" >&2
   exit 1
fi
printf '%s\n' 'all dm-developers-build stale-label cases passed'
