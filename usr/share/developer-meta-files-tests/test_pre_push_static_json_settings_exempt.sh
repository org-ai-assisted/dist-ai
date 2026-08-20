#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression suite for pre-push-static's pretty-format-json exemption of app-managed
## Claude Code settings files (claude/settings.json, settings.local.json). The app rewrites
## those files itself -- unsorted and human-grouped -- on every settings change, so enforcing
## pretty-format-json's default key-SORT on them is futile and destructive. The exemption
## skips ONLY the formatter; check-json still validates their syntax. Pins:
##   * an UNSORTED claude/settings.json does NOT fail the gate (formatter exempted) and the
##     skip note names it -- proven with a canary that the fixture really is unsorted;
##   * the exemption is SCOPED: an unsorted non-settings JSON still fails pretty-format-json;
##   * check-json still runs -- a syntactically INVALID settings.json still fails the gate.
## Drives the REAL shipped gate as a subprocess (no private copy).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${tool_test_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi
if [ ! -x "${GATE}" ]; then
   printf '%s\n' "FATAL: pre-push-static not found (looked at '${GATE}')." >&2
   exit 1
fi

for prereq in git safe-rm ; do
   if ! type -P "${prereq}" >/dev/null 2>&1 ; then
      printf '%s\n' "FATAL: '${prereq}' not on PATH; this test cannot run." >&2
      exit 1
   fi
done

## pretty-format-json / check-json ship with pre-commit-hooks. Without them the gate SKIPS
## that whole layer, so the exemption cannot be exercised: SKIP (exit 77), never a false pass.
for binary in check-json pretty-format-json ; do
   if ! type -P "${binary}" >/dev/null 2>&1 ; then
      printf '%s\n' "SKIP: pre-commit-hooks ('${binary}') not on PATH; cannot verify the JSON exemption (apt-get install pre-commit-hooks)." >&2
      exit 77
   fi
done

test_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${test_dir}"; }
trap cleanup EXIT

fail=0
passc=0
note_pass() { printf '%s\n' "PASS: ${1}" ; passc=$(( passc + 1 )) ; }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2 ; fail=$(( fail + 1 )) ; }

exit_gate() {
   if [ "${fail}" -ne 0 ]; then
      printf '%s\n' "json-settings-exempt: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
      exit 1
   fi
   printf '%s\n' "json-settings-exempt: ${passc} pass, 0 fail, 0 skip -- all canaries passed."
   exit 0
}

## Self-test the FAIL gate on every run, so a forced failure cannot silently exit 0.
if [ -n "${TEST_SELFCHECK_FAIL_GATE:-}" ]; then
   note_fail "self-test: forced failure to exercise the FAIL gate"
   exit_gate
fi
if TEST_SELFCHECK_FAIL_GATE=1 "$0" >/dev/null 2>&1; then
   printf '%s\n' "json-settings-exempt: FAIL gate regressed -- a forced failure still exits 0" >&2
   exit 1
fi

## A fresh repo with a base commit; -c core.hooksPath=/dev/null so the operator's own hooks
## never run against this fixture (we are testing pre-push-static, not the host hooks).
repo="${test_dir}/repo"
mkdir --parents -- "${repo}/claude" "${repo}/.claude" "${repo}/data"
git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
gitc() { git -C "${repo}" -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com "${@}"; }
gitc commit --quiet --allow-empty --message "base"
base_sha="$(git -C "${repo}" rev-parse HEAD)"

## Deliberately UNSORTED keys: pretty-format-json's default sort would reorder them.
unsorted='{
  "zebra": 1,
  "alpha": 2
}
'

## Canary: prove the fixture is genuinely unsorted, i.e. pretty-format-json WOULD rewrite it.
## Without this, an exemption that silently passed everything would look correct.
printf '%s' "${unsorted}" > "${test_dir}/canary.json"
if pretty-format-json "${test_dir}/canary.json" >/dev/null 2>&1; then
   note_fail "canary: the unsorted fixture already satisfies pretty-format-json -- test is vacuous"
else
   note_pass "canary: the unsorted fixture genuinely fails pretty-format-json"
fi

## --- 1: an unsorted claude/settings.json does NOT fail the gate (formatter exempted) ------
printf '%s' "${unsorted}" > "${repo}/claude/settings.json"
gitc add --all
gitc commit --quiet --message "settings"
rc=0
out="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || rc=$?
if [ "${rc}" -eq 0 ] \
   && grep --quiet --fixed-strings "pretty-format-json skipped: 'claude/settings.json'" <<< "${out}" \
   && ! grep --quiet --fixed-strings 'FAIL pretty-format-json' <<< "${out}" ; then
   note_pass "unsorted claude/settings.json is exempted (skip note present, gate green)"
else
   note_fail "settings.json exemption wrong (rc=${rc}); out: ${out}"
fi

## --- 1b: the hidden .claude/settings.json spelling is exempted too ------------------------
printf '%s' "${unsorted}" > "${repo}/.claude/settings.json"
gitc add --all
gitc commit --quiet --message "hidden settings"
rc=0
out="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || rc=$?
if [ "${rc}" -eq 0 ] \
   && grep --quiet --fixed-strings "pretty-format-json skipped: '.claude/settings.json'" <<< "${out}" ; then
   note_pass "the hidden .claude/settings.json spelling is exempted too"
else
   note_fail ".claude/settings.json exemption wrong (rc=${rc}); out: ${out}"
fi

## --- 2: exemption is SCOPED -- an unsorted non-settings JSON still fails pretty-format-json -
printf '%s' "${unsorted}" > "${repo}/data/other.json"
gitc add --all
gitc commit --quiet --message "other json"
rc=0
out="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || rc=$?
if [ "${rc}" -ne 0 ] && grep --quiet --fixed-strings 'FAIL pretty-format-json' <<< "${out}" ; then
   note_pass "a non-settings JSON is NOT exempted (pretty-format-json still fails it)"
else
   note_fail "exemption leaked to a non-settings JSON (rc=${rc}); out: ${out}"
fi

## --- 2b: 'myclaude/' is NOT a 'claude' path component -- still formatted (anchor proof) ----
## A fresh repo so the still-broken data/other.json above does not confound the result.
repo3="${test_dir}/repo3"
mkdir --parents -- "${repo3}/myclaude"
git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo3}"
git -C "${repo3}" -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   commit --quiet --allow-empty --message "base"
base3="$(git -C "${repo3}" rev-parse HEAD)"
printf '%s' "${unsorted}" > "${repo3}/myclaude/settings.json"
git -C "${repo3}" -c core.hooksPath=/dev/null add --all
git -C "${repo3}" -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "myclaude"
rc=0
out="$( cd -- "${repo3}" && "${GATE}" "${base3}" 2>&1 )" || rc=$?
if [ "${rc}" -ne 0 ] && grep --quiet --fixed-strings 'FAIL pretty-format-json' <<< "${out}" ; then
   note_pass "myclaude/settings.json is NOT exempted (component-anchored, not a suffix match)"
else
   note_fail "myclaude/ wrongly exempted (rc=${rc}); out: ${out}"
fi

## --- 3: check-json still runs -- a syntactically invalid settings.json still fails ---------
## Fresh repo so the still-broken data/other.json above does not confound the result.
repo2="${test_dir}/repo2"
mkdir --parents -- "${repo2}/claude"
git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo2}"
git -C "${repo2}" -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   commit --quiet --allow-empty --message "base"
base2="$(git -C "${repo2}" rev-parse HEAD)"
## Not valid JSON (trailing comma, no close): check-json must reject it despite the exemption.
## A valid FINAL NEWLINE so end-of-file-fixer stays green -- then the ONLY failure is check-json,
## and the assertion below matches the 'FAIL check-json' line specifically (not the mere string
## 'check-json', which also appears in the pretty-format-json skip note).
printf '%s\n' '{"zebra": 1,' > "${repo2}/claude/settings.json"
git -C "${repo2}" -c core.hooksPath=/dev/null add --all
git -C "${repo2}" -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "broken settings"
rc=0
out="$( cd -- "${repo2}" && "${GATE}" "${base2}" 2>&1 )" || rc=$?
if [ "${rc}" -ne 0 ] && grep --quiet --fixed-strings 'FAIL check-json' <<< "${out}" ; then
   note_pass "check-json still validates settings.json syntax (exemption is formatter-only)"
else
   note_fail "invalid settings.json was not caught by check-json (rc=${rc}); out: ${out}"
fi

exit_gate
