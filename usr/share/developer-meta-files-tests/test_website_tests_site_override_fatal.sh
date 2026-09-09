#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Pins a silent-green regression in usr/bin/website-tests site-root resolution: an
## EXPLICIT override (OUTPUT_LIES_REPO / SECURE_TERMINAL_SITE_REPO / ORG_AI_ASSISTED_REPO
## set non-empty) that points at a path lacking the site marker (index.html for add_root,
## comparison/shots for resolve_st_site) must FATAL -- it must NOT silently fall back to
## the private-sources default, which would report PASS on a DIFFERENT site than the
## operator asked for. An UNSET override legitimately uses the default.
##
## Drives the REAL shipped functions (no synthetic copy): the two resolver functions are
## self-contained (add_root touches only its args + the roots array; resolve_st_site only
## its args + st_site), so extract them verbatim from the runner and source them, then
## exercise the branches with tempdir fixtures. Pre-fix (silent fallback) the two
## explicit-but-invalid cases return rc 0 and pick the default -> those assertions FAIL.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
runner="${test_dir}/../../bin/website-tests"
[ -r "${runner}" ] || runner='/usr/bin/website-tests'
if [ ! -r "${runner}" ]; then
   printf '%s\n' "FATAL: website-tests not found" >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Extract the two resolver functions verbatim from the real runner and source them.
fn_file="${work}/resolvers.bash"
sed -n '/^add_root(){/,/^}/p'        -- "${runner}" >  "${fn_file}"
sed -n '/^resolve_st_site(){/,/^}/p' -- "${runner}" >> "${fn_file}"
if ! grep --quiet --fixed-strings 'add_root(){' "${fn_file}" \
      || ! grep --quiet --fixed-strings 'resolve_st_site(){' "${fn_file}"; then
   printf '%s\n' "FATAL: could not extract resolver functions from ${runner}" >&2
   exit 1
fi
declare -a roots=()
st_site=''
# shellcheck disable=SC1090 # dynamic path: the resolvers are extracted at runtime
source "${fn_file}"

## Fixtures.
valid_site="${work}/valid_site"          # has index.html
valid_shots="${work}/valid_shots"        # has comparison/shots
no_marker="${work}/no_marker"            # exists, but neither marker
missing="${work}/does_not_exist"         # never created
mkdir --parents -- "${valid_site}" "${valid_shots}/comparison/shots" "${no_marker}"
touch -- "${valid_site}/index.html"

## Run a resolver in a subshell so its FATAL `exit 1` is caught (not the test's own exit).
## Captures stderr; returns the child rc via the global `sub_rc`, stderr via `sub_err`.
run_sub() {
   sub_rc=0
   sub_err="$( ( "$@" ) 2>&1 1>/dev/null )" || sub_rc=$?
}

## --- add_root (index.html marker) ---

## Unset override + valid default -> default is used.
roots=(); add_root '' "${valid_site}"
if [ "${#roots[@]}" -eq 1 ] && [ "${roots[0]}" = "${valid_site}" ]; then
   pass 'add_root: unset override falls back to a valid default'
else
   fail "add_root: unset override did not use the default (roots=${roots[*]:-})"
fi

## Valid explicit override -> the override is used.
roots=(); add_root "${valid_site}" "${missing}"
if [ "${#roots[@]}" -eq 1 ] && [ "${roots[0]}" = "${valid_site}" ]; then
   pass 'add_root: valid explicit override is used'
else
   fail "add_root: valid explicit override not used (roots=${roots[*]:-})"
fi

## Explicit-but-invalid override (exists, no index.html) -> FATAL, NOT silent default.
run_sub add_root "${no_marker}" "${valid_site}"
if [ "${sub_rc}" -eq 1 ] && [[ "${sub_err}" == *FATAL* ]] && [[ "${sub_err}" == *"${no_marker}"* ]]; then
   pass 'add_root: explicit-but-invalid override is FATAL (not a silent default fallback)'
else
   fail "add_root: explicit-but-invalid override did not FATAL (rc=${sub_rc}, err=${sub_err})"
fi

## Unset override + absent default -> nothing added (preserves the no-checkout SKIP path).
roots=(); add_root '' "${missing}"
if [ "${#roots[@]}" -eq 0 ]; then
   pass 'add_root: unset override + absent default adds nothing (SKIP path preserved)'
else
   fail "add_root: unset override + absent default wrongly added (roots=${roots[*]:-})"
fi

## --- resolve_st_site (comparison/shots marker) ---

## Valid explicit override -> the override is used.
st_site=''; resolve_st_site "${valid_shots}" "${missing}"
if [ "${st_site}" = "${valid_shots}" ]; then
   pass 'resolve_st_site: valid explicit override is used'
else
   fail "resolve_st_site: valid explicit override not used (st_site=${st_site})"
fi

## Explicit-but-invalid override (no comparison/shots) -> FATAL, NOT silent default.
run_sub resolve_st_site "${no_marker}" "${valid_shots}"
if [ "${sub_rc}" -eq 1 ] && [[ "${sub_err}" == *FATAL* ]] && [[ "${sub_err}" == *"${no_marker}"* ]]; then
   pass 'resolve_st_site: explicit-but-invalid override is FATAL (not a silent default fallback)'
else
   fail "resolve_st_site: explicit-but-invalid override did not FATAL (rc=${sub_rc}, err=${sub_err})"
fi

## Unset override + valid default -> default is used.
st_site=''; resolve_st_site '' "${valid_shots}"
if [ "${st_site}" = "${valid_shots}" ]; then
   pass 'resolve_st_site: unset override falls back to a valid default'
else
   fail "resolve_st_site: unset override did not use the default (st_site=${st_site})"
fi

## Unset override + absent default -> st_site stays empty (the shot guard is simply skipped).
st_site=''; resolve_st_site '' "${missing}"
if [ -z "${st_site}" ]; then
   pass 'resolve_st_site: unset override + absent default leaves st_site empty'
else
   fail "resolve_st_site: unset override + absent default wrongly set st_site=${st_site}"
fi

printf '%s\n' "" "test_website_tests_site_override_fatal: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
