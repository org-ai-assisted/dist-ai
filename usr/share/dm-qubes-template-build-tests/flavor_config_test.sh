#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-qubes-template-build's pure logic:
##   - flavor_to_config maps each supported flavor to its qubes-builderv2 example-config:
##       kicksecure-18         -> example-configs/kicksecure.yml
##       whonix-gateway-18     -> example-configs/qubes-os-r4.3.yml
##       whonix-workstation-18 -> example-configs/qubes-os-r4.3.yml
##     and returns non-zero for an unknown flavor (so main() errors instead of building nothing).
##   - write_builder_conf emits a builder.yml that includes the mapped config AND overrides the
##     executor to docker with the builder image -- the override is what makes the build run off
##     Qubes (the example-configs ship executor type qubes).
## Drives the REAL functions, sourced define-only (the subject's BASH_SOURCE guard skips main()).
## No docker, no network, no git, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_QUBES_TEMPLATE_BUILD:-}" \
  "${test_dir}/../../bin/dm-qubes-template-build" \
  "/usr/bin/dm-qubes-template-build"; do
  [ -n "${candidate}" ] || continue
  if [ -x "${candidate}" ]; then
    subject="$(readlink --canonicalize -- "${candidate}")"
    break
  fi
done
[ -n "${subject}" ] || {
  printf '%s\n' "FATAL: dm-qubes-template-build not found (set DM_QUBES_TEMPLATE_BUILD)." >&2
  exit 1
}

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

# shellcheck disable=SC1090
source "${subject}"

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then
  pass=$((pass + 1))
  printf '%s\n' "PASS: $1"
else
  fail=$((fail + 1))
  printf '%s\n' "FAIL: $1"
fi; }

## expect_config FLAVOR EXPECTED: flavor_to_config prints EXPECTED and returns 0.
expect_config() {
  local flavor_in="$1" expected="$2" got rc=0
  got="$(flavor_to_config "${flavor_in}")" || rc=$?
  if [ "${rc}" -eq 0 ] && [ "${got}" = "${expected}" ]; then
    check "flavor_to_config ${flavor_in} -> ${expected}" 0
  else
    printf '%s\n' "  got rc=${rc} out='${got}' want='${expected}'" >&2
    check "flavor_to_config ${flavor_in} -> ${expected}" 1
  fi
}

expect_config kicksecure-18 "example-configs/kicksecure.yml"
expect_config whonix-gateway-18 "example-configs/qubes-os-r4.3.yml"
expect_config whonix-workstation-18 "example-configs/qubes-os-r4.3.yml"

## Unknown flavor must return non-zero.
unknown_rc=0
flavor_to_config "not-a-real-flavor" >/dev/null 2>&1 || unknown_rc=$?
if [ "${unknown_rc}" -ne 0 ]; then
  check "flavor_to_config rejects unknown flavor" 0
else
  check "flavor_to_config rejects unknown flavor" 1
fi

## write_builder_conf emits include + docker executor override.
dir="${work}/co"
# shellcheck disable=SC2034  ## consumed by the sourced write_builder_conf (reads the global)
image="qubes-builder-fedora:latest"
mkdir -p -- "${dir}"
write_builder_conf "example-configs/kicksecure.yml"
conf="${dir}/builder.yml"

grep --quiet --line-regexp --fixed-strings "include:" "${conf}" && c1=0 || c1=1
check "builder.yml has include:" "${c1}"

grep --quiet --fixed-strings "example-configs/kicksecure.yml" "${conf}" && c2=0 || c2=1
check "builder.yml includes the mapped config" "${c2}"

grep --quiet --fixed-strings "type: docker" "${conf}" && c3=0 || c3=1
check "builder.yml overrides executor to docker" "${c3}"

grep --quiet --fixed-strings "image: \"qubes-builder-fedora:latest\"" "${conf}" && c4=0 || c4=1
check "builder.yml pins the builder image" "${c4}"

printf '%s\n' "" "flavor_config_test: ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ]
