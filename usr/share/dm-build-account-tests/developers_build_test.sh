#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-developers-build drives a real ISO build as the persist-bild-<guest> account. Drive
## the REAL script under a stub PATH (no root, no build, no network) and assert the
## guest -> flavor mapping and the built-ISO detection. Canary: a fixed
## 'kicksecure-lxqt' default fails case 1; path-only ISO detection fails case 4.

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
[ -r "${subject}" ] || { printf 'FATAL: dm-developers-build not found at %s\n' "${subject}" >&2; exit 1; }

failures=0
ok()  { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }

work="$(mktemp --directory)"
## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
test_cleanup_handler() {
   safe-rm --recursive --force -- "${work}" || true
}
trap test_cleanup_handler EXIT

stub_bin="${work}/bin"
calls="${work}/calls.log"
stub_home="${work}/home"
source_checkout="${work}/src"
iso_dir="${stub_home}/derivative-binary"
mkdir --parents -- "${stub_bin}" "${stub_home}" "${source_checkout}/.git"

## Stubs: record argv. runuser answers the reference tag fetch/describe and, for the
## build call, writes ONE ISO at a fixed path (in place, like a rebuild of the same
## version) unless STUB_NO_ISO is set. The sleep lets the coarse filesystem clock tick
## so a rewrite gets a ctime distinct from the pre-build snapshot.
make_stub() {
   local name="$1" body="$2"
   {
      printf '#!/bin/bash\n'
      printf 'printf "%%s %%s\\n" "%s" "$*" >> "%s"\n' "${name}" "${calls}"
      printf '%s\n' "${body}"
   } > "${stub_bin}/${name}"
   chmod +x "${stub_bin}/${name}"
}
make_stub id      'printf "0\n"'
# shellcheck disable=SC2016
make_stub getent  'printf "%s:x:1:1::%s:/bin/bash\n" "$2" "'"${stub_home}"'"'
make_stub stat    'printf "admin\n"'
make_stub rsync   'exit 0'
make_stub chown   'exit 0'
# shellcheck disable=SC2016
make_stub dm-build-account 'printf "persist-bild-%s\n" "$1"'
# shellcheck disable=SC2016
make_stub runuser '
case "$*" in
   *" describe "*)
      printf "18.2.3.6-developers-only\n"
      ;;
   *"DM_FLAV="*)
      [ -z "${STUB_NO_ISO:-}" ] || exit 0
      sleep 0.1
      printf "built %s\n" "$(date +%s%N)" > "'"${iso_dir}"'/stub.Intel_AMD64.iso"
      ;;
esac'

run_subject() {
   PATH="${stub_bin}:${PATH}" \
   DM_BUILD_ACCOUNT="${stub_bin}/dm-build-account" \
   DM_SOURCE_CHECKOUT="${source_checkout}" \
      bash "${subject}" "$@"
}

built_flavor() {
   grep --only-matching --extended-regexp 'DM_FLAV=[^ ]+' "${calls}" | cut -d= -f2
}

iso="${iso_dir}/stub.Intel_AMD64.iso"

## 1. whonix defaults to the Whonix ISO flavor, never a Kicksecure one.
true >| "${calls}"
if out="$(run_subject whonix 2>&1)" && [ "$(built_flavor)" = 'whonix-host-lxqt' ]; then
   ok 'whonix defaults to flavor whonix-host-lxqt'
else
   bad "whonix default flavor wrong ($(built_flavor)): ${out}"
fi

## 2. kicksecure keeps its default.
true >| "${calls}"
safe-rm --force -- "${iso}"
if out="$(run_subject kicksecure 2>&1)" && [ "$(built_flavor)" = 'kicksecure-lxqt' ]; then
   ok 'kicksecure defaults to flavor kicksecure-lxqt'
else
   bad "kicksecure default flavor wrong ($(built_flavor)): ${out}"
fi

## 3. a flavor of the other guest is refused before any build.
true >| "${calls}"
rc=0
run_subject whonix --flavor kicksecure-lxqt >/dev/null 2>&1 || rc=$?
if [ "${rc}" = '2' ] && [ -z "$(built_flavor)" ]; then
   ok 'mismatched guest/flavor refused (exit 2), no build'
else
   bad "mismatched guest/flavor not refused (rc=${rc}, flavor=$(built_flavor))"
fi

## 4. a rebuild that rewrites the ISO at an EXISTING path is found (the output dir
## persists across builds, so a same-version rebuild reuses the name).
printf '%s\n' 'previous build' > "${iso}"
true >| "${calls}"
rc=0
out="$(run_subject kicksecure 2>&1)" || rc=$?
if [ "${rc}" = '0' ] && [ "$(printf '%s\n' "${out}" | tail -1)" = "${iso}" ]; then
   ok 'ISO rewritten at an existing path is reported'
else
   bad "ISO rewritten at an existing path not reported (rc=${rc}): ${out}"
fi

## 5. a build that leaves the old ISO untouched is still a failure, not a stale success.
printf '%s\n' 'previous build' > "${iso}"
true >| "${calls}"
rc=0
out="$(STUB_NO_ISO=1 run_subject kicksecure 2>&1)" || rc=$?
if [ "${rc}" -ne 0 ] && grep --quiet 'no new or rewritten ISO' <<< "${out}"; then
   ok 'untouched pre-existing ISO is not reported as built'
else
   bad "untouched pre-existing ISO reported as built (rc=${rc}): ${out}"
fi

if [ "${failures}" -eq 0 ]; then
   printf '%s: all checks passed\n' "${0##*/}"
   exit 0
fi
printf '%s: %s check(s) FAILED\n' "${0##*/}" "${failures}" >&2
exit 1
