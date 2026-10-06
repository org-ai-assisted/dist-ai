#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Consistency guard: a runner that SOURCES suite-exit.bash must actually CALL
## the vocabulary (suite_exit or a result_* emitter). Catches "source-and-forget"
## -- a runner that wires in the canonical helper but whose exit path bypasses it,
## silently reverting to a bare `exit 0` that cannot surface a skip.
##
## SCOPE (honest, deliberately narrow): this guards ONLY opt-in files (those that
## source the helper). It does NOT require every runner to use suite_exit -- many
## surface skips honestly by other means (a pytest rc 5 -> FAIL mapping, an
## all-skip -> exit 77 guard, tor-ctrl's `[ skips -eq 0 ] || exit 77`). A rule
## demanding suite_exit everywhere would false-flag those, so it is not made.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"

## Runners live in usr/bin beside usr/share (checkout) or /usr/bin (installed);
## ../../bin resolves both.
bin_dir="${script_dir}/../../bin"
if [ ! -d "${bin_dir}" ]; then
   bin_dir='/usr/bin'
fi

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

## Does the file source the canonical helper? (the suite_exit_helper resolution
## line is present in every runner that sources it.)
sources_helper() {
   grep --quiet --extended-regexp 'suite-exit\.bash' -- "$1"
}

## Does the file CALL the vocabulary? Anchored to a statement (optional indent
## then the name), so a comment mentioning suite_exit cannot mask a forget, and
## the 'suite_exit_helper' assignment (no space before '_') is not a call.
## SCOPE (heuristic, deliberately not a shell parser): this grep cannot tell a
## real call from a 'suite_exit' line sitting in a here-document body, so a
## runner that only MENTIONS the token in a heredoc would read as calling it.
## That is a contrived shape, not the forgot-to-call ACCIDENT this guards; a
## heredoc parser here would be the fragile-parser trap, so it is out of scope.
calls_vocabulary() {
   grep --quiet --extended-regexp \
      '^[[:space:]]*(suite_exit[[:space:]]|result_(pass|fail|skip_target_absent|skip_env_unmet)([[:space:]]|$|\)))' \
      -- "$1"
}

## "sources but forgets to call" -> violation.
forgets() {
   sources_helper "$1" && ! calls_vocabulary "$1"
}

## --- canary: the checker must have teeth ---
work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

cat >"${work}/forgets" <<'EOF'
#!/bin/bash
suite_exit_helper='/usr/share/dist-ai-tests-common/suite-exit.bash'
source "${suite_exit_helper}"
## never calls suite_exit -- exit path bypasses the helper
exit 0
EOF
if forgets "${work}/forgets"; then
   check "canary: source-and-forget is detected" "detected" "detected"
else
   check "canary: source-and-forget is detected" "missed" "detected"
fi

cat >"${work}/calls" <<'EOF'
#!/bin/bash
suite_exit_helper='/usr/share/dist-ai-tests-common/suite-exit.bash'
source "${suite_exit_helper}"
suite_exit "${failed}" "${skipped}" "${env_unmet}"
EOF
if forgets "${work}/calls"; then
   check "canary: a real call is not flagged" "flagged" "clean"
else
   check "canary: a real call is not flagged" "clean" "clean"
fi

## --- the real fleet ---
shopt -s nullglob
offenders=()
for runner in "${bin_dir}"/*-tests; do
   if forgets "${runner}"; then
      offenders+=( "${runner##*/}" )
   fi
done
shopt -u nullglob

if [ "${#offenders[@]}" -ne 0 ]; then
   printf '%s\n' "sources suite-exit.bash but never calls it: ${offenders[*]}" >&2
fi
check "every runner sourcing suite-exit.bash also calls it" "${#offenders[@]}" "0"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
