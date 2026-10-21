#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## env-generator-emit is a systemd environment generator: symlinked into a
## systemd-environment-generators dir under the name of an /etc/profile.d/<name>.sh
## script, it sources that script and emits the variables it set/changed as
## systemd 'NAME="value"' lines on stdout.
##
## The emit loop reads the computed diff via 'done <<< "${out_env_data}"'. A prior
## version left the loop's 'done' with NO input redirection, so the diff was never
## consumed: run as a generator (stdin /dev/null) it emitted NOTHING, silently
## loading none of the profile.d variables into systemd.
##
## Drives the REAL generator inside an unprivileged bwrap mount namespace whose
## /etc/profile.d is a controlled fixture dir, so the subject reads a known
## 'env-generator-emit.sh' without touching the host /etc. Asserts the variable it
## sets is emitted as a systemd line. On the old (unconsumed-loop) code the output
## is empty and the assertion fails. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
# shellcheck source=./bwrap_capability.bash
source "${script_dir}/bwrap_capability.bash"

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts/env-generator-emit"
else
   subject='/usr/libexec/helper-scripts/env-generator-emit'
fi

## The SUBJECT is a REQUIRED dependency: absent means helper-scripts is not
## installed / HELPER_SCRIPTS_REPO is unset -> FATAL, never a skip (R-220).
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

bwrap_require

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT

## The generator derives the profile.d script name from its own basename: invoked
## as .../env-generator-emit it reads /etc/profile.d/env-generator-emit.sh.
emit_dir="${work}/profile.d"
mkdir --parents -- "${emit_dir}"
printf '%s\n' 'export TEST_EMIT_VAR=hello' > "${emit_dir}/env-generator-emit.sh"

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

## Bind the fixture dir over /etc/profile.d inside the namespace and run the REAL
## generator; stdin /dev/null mirrors how systemd runs a generator.
out="$(bwrap --bind / / --dev /dev --proc /proc \
   --unsetenv TEST_EMIT_VAR \
   --ro-bind "${emit_dir}" /etc/profile.d \
   /usr/bin/bash "${subject}" </dev/null 2>/dev/null)" || out='<bwrap-run-failed>'

if grep --quiet --fixed-strings --line-regexp -- 'TEST_EMIT_VAR="hello"' <<< "${out}"; then
   ok "emits the sourced variable as a systemd line"
else
   notok "expected a 'TEST_EMIT_VAR=\"hello\"' line; got: '${out}'"
fi

## Defensive: no line is a bare 'NAME=' with an empty name (the empty-input guard).
if grep --quiet -- '^="' <<< "${out}"; then
   notok "emitted a bogus empty-name line"
else
   ok "no bogus empty-name line"
fi

printf '%s\n' ""
printf '%s\n' "===== env-generator-emit: ${pass_count} pass, ${fail_count} fail ====="
[ "${fail_count}" -eq 0 ]
