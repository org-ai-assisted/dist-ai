#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Offline unit tests for mediawiki-shell: pure functions and helpers that
## need no live wiki -- the filename<->title codec (mw-urlencode), the import
## XML builder (mw-build-import-xml), and the security/iteration helpers in
## usr/share/mediawiki-shell/common (path-traversal guard, continue-from
## logic, backup-item encode/decode round-trip, exit-code propagation).
##
## Subject resolved from MEDIAWIKI_SHELL_REPO (the checkout root); self-skips
## (77) when it is absent. common sources helper-scripts and runs collect_reqs,
## so HELPER_SCRIPTS_PATH plus retry/curl/jq/safe-rm/moreutils/coreutils and
## helper-scripts' str_replace/stprint must be present -- the consumer declares
## them (dm-consumer.yml helper-scripts: true + apt-packages).
##
## Live-wiki coverage lives in dist-encrypted's
## .github/scripts/wiki-mediawiki-shell-test.sh, not here.

## common is sourced from a runtime-resolved path (MEDIAWIKI_SHELL_REPO).
# shellcheck disable=SC1090

set -o errexit
set -o nounset
set -o errtrace
set -o pipefail
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v MEDIAWIKI_SHELL_REPO ] || MEDIAWIKI_SHELL_REPO=""
mw_bin="${MEDIAWIKI_SHELL_REPO}/usr/bin"
mw_common="${MEDIAWIKI_SHELL_REPO}/usr/share/mediawiki-shell/common"
import_xml_builder="${MEDIAWIKI_SHELL_REPO}/usr/libexec/mediawiki-shell/mw-build-import-xml"

if [ ! -x "${mw_bin}/mw-urlencode" ] || [ ! -r "${mw_common}" ] \
   || [ ! -x "${import_xml_builder}" ]; then
  printf '%s\n' "$0: SKIP: mediawiki-shell subject not found; set MEDIAWIKI_SHELL_REPO to a checkout" >&2
  ## style-ok: allow-skip: mediawiki-shell is an optional target -- absent in a --repo-root run without this submodule; a wired run always resolves it.
  exit 77
fi

## Required external tools: their absence is an ENVIRONMENT bug, not a subject failure. A missing
## xmllint would otherwise fall to the "XML not well-formed" branch and blame mediawiki-shell for
## the environment; a missing safe-rm would fail the fixture cleanup.
for _tool in xmllint safe-rm; do
  if ! type -P "${_tool}" >/dev/null 2>&1; then
    printf '%s\n' "$0: FATAL: required tool '${_tool}' not found (install: xmllint = libxml2-utils; safe-rm)" >&2
    exit 1
  fi
done

## mw-build-import-xml resolves mw-urlencode via PATH (shutil.which); the tests
## call mw-urlencode by bare name. Put the checkout's bin first.
PATH="${mw_bin}:${PATH}"

PASS=0
FAIL=0
ERRORS=""

pass() { printf '%s\n' "PASS: $1"; PASS=$(( PASS + 1 )); }
fail() { printf '%s\n' "FAIL: $1" >&2; FAIL=$(( FAIL + 1 )); ERRORS="${ERRORS}  FAIL: $1"$'\n'; }

assert_eq() {
  ## assert_eq DESC EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}

assert_rc() {
  ## assert_rc DESC EXPECTED_RC ACTUAL_RC
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected rc '$2', got '$3')"; fi
}

## ===========================================================================
printf '%s\n' "=== mw-urlencode: filename <-> title round-trip ==="
## ===========================================================================
## set_backup_page_item / decode_backup_page_item are built on these two.
## Round-trip is EXACT for canonical (underscore-form) titles. Spaces are
## intentionally normalized to underscores (MediaWiki treats space and
## underscore as equivalent in titles; git-mediawiki filename convention), so
## display-form titles with spaces are tested as a normalization below, not
## here. These cover the characters that MUST percent-encode to be
## filesystem-safe and decode back unchanged.
roundtrip_titles=(
  "Documentation"
  "Dev/mediawiki"
  "Template:Header"
  "Widget:CodeSelect"
  "A_page_with_underscores"
  "Foo&Bar"
  "100%Done"
  "C++Programming"
  "Question?Mark"
  "Hash#Fragment"
  "Category:Tor"
)
for title in "${roundtrip_titles[@]}"; do
  rc=0
  enc="$(mw-urlencode --encode-page-to-filename "${title}")" || rc=$?
  if [ "${rc}" != "0" ]; then
    fail "encode '${title}' errored"
    continue
  fi
  ## Encoded form must be a single line and contain no '/' (subpage separator
  ## must be percent-encoded so it cannot create directories) and no spaces.
  if [[ "${enc}" == */* ]]; then
    fail "encoded '${title}' still contains '/': '${enc}'"
    continue
  fi
  if [[ "${enc}" == *" "* ]]; then
    fail "encoded '${title}' still contains a space: '${enc}'"
    continue
  fi
  rc=0
  dec="$(mw-urlencode --decode-filename-to-page "${enc}")" || rc=$?
  if [ "${rc}" != "0" ]; then
    fail "decode '${enc}' errored"
    continue
  fi
  assert_eq "round-trip '${title}' (enc='${enc}')" "${title}" "${dec}"
done

## Spaces specifically must become underscores (git-mediawiki convention).
enc_space="$(mw-urlencode --encode-page-to-filename "A page with spaces")" || enc_space="<error>"
assert_eq "space -> underscore" "A_page_with_spaces" "${enc_space}"

## Decoding the underscore form yields the underscore (canonical) title, NOT a
## space. MediaWiki treats space and underscore as equivalent in titles, so
## this is lossless at the wiki level; assert it as intended behavior.
dec_us="$(mw-urlencode --decode-filename-to-page "A_page_with_spaces")" || dec_us="<error>"
assert_eq "decode keeps underscore canonical form (space==underscore)" "A_page_with_spaces" "${dec_us}"

## '/' must become %2F (preserve subpage, no directory traversal).
enc_slash="$(mw-urlencode --encode-page-to-filename "Dev/mediawiki")" || enc_slash="<error>"
assert_eq "slash -> %2F" "Dev%2Fmediawiki" "${enc_slash}"

## ===========================================================================
printf '%s\n' "=== mw-build-import-xml: XML construction + unsafe-title skip ==="
## ===========================================================================
fixture_dir="$(mktemp -d)"
xml_out="$(mktemp)"
cleanup_fixtures() { safe-rm --recursive --force -- "${fixture_dir}" "${xml_out}"; }
trap cleanup_fixtures EXIT

## Three legitimate pages across namespaces, with content needing XML escaping.
printf '%s\n' "Hello <world> & friends" > "${fixture_dir}/Documentation.mw"
printf '%s\n' "subpage body"            > "${fixture_dir}/Dev%2Fmediawiki.mw"
printf '%s\n' "{{#widget:CodeSelect}}"  > "${fixture_dir}/Widget:CodeSelect.mw"
## A non-.mw file must be ignored.
printf '%s\n' "ignore me"               > "${fixture_dir}/README.txt"

count="$("${import_xml_builder}" "${fixture_dir}" "${xml_out}")" || count="<error>"
assert_eq "import-xml page count (3 .mw files, 1 non-.mw ignored)" "3" "${count}"

## XML well-formedness + content escaping + subpage title decode. xmllint is a
## guaranteed dependency (libxml2-utils, declared by the consumer).
if xmllint --noout "${xml_out}" 2>/dev/null; then pass "import XML is well-formed"; else fail "import XML is not well-formed"; fi
if grep --quiet '<title>Dev/mediawiki</title>' "${xml_out}"; then pass "subpage filename %2F decoded back to '/' in title"; else fail "subpage title not decoded"; fi
if grep --quiet 'Hello &lt;world&gt; &amp; friends' "${xml_out}"; then pass "page text XML-escaped"; else fail "page text not XML-escaped"; fi

## Unsafe titles must be skipped, not written (path traversal / absolute / control).
unsafe_dir="$(mktemp -d)"
unsafe_xml="$(mktemp)"
printf '%s\n' "evil" > "${unsafe_dir}/%2E%2E%2Fescape.mw"   # decodes to "../escape"
printf '%s\n' "ok"   > "${unsafe_dir}/Safe.mw"
unsafe_count="$("${import_xml_builder}" "${unsafe_dir}" "${unsafe_xml}" 2>/dev/null)" || unsafe_count="<error>"
assert_eq "import-xml skips traversal title (only 'Safe' kept)" "1" "${unsafe_count}"
safe-rm --recursive --force -- "${unsafe_dir}" "${unsafe_xml}"

## ===========================================================================
printf '%s\n' "=== common: assert_path_within_dir (traversal guard) ==="
## ===========================================================================
## Run each in a subshell so common's 'set -o errexit'/traps don't abort the
## harness; capture the exit code (die -> non-zero).
run_in_common() { ( source "${mw_common}" >/dev/null 2>&1; "$@" ) >/dev/null 2>&1; }

base_dir="$(mktemp -d)"
rc=0; run_in_common assert_path_within_dir "${base_dir}" "${base_dir}/sub/file.mw" || rc=$?
assert_rc "assert_path_within_dir allows path inside base" "0" "${rc}"

rc=0; run_in_common assert_path_within_dir "${base_dir}" "${base_dir}/../escape" || rc=$?
if [ "${rc}" != "0" ]; then pass "assert_path_within_dir blocks '..' traversal"; else fail "assert_path_within_dir allowed traversal"; fi

rc=0; run_in_common assert_path_within_dir "${base_dir}" "/etc/passwd" || rc=$?
if [ "${rc}" != "0" ]; then pass "assert_path_within_dir blocks absolute outside path"; else fail "assert_path_within_dir allowed outside path"; fi
rmdir "${base_dir}" 2>/dev/null || true

## ===========================================================================
printf '%s\n' "=== common: should_start_processing (--continue-from) ==="
## ===========================================================================
## Empty continue-from -> always process. Integer -> from that 1-based index.
## String -> from the matching title (ASCII case-insensitive under LC_ALL=C).
ssp() {
  ## ssp INDEX TITLE CONTINUE_FROM INITIAL_STATE -> prints "process" or "skip"
  ( source "${mw_common}" >/dev/null 2>&1
    # shellcheck disable=SC2034  # consumed by should_start_processing via nameref ($4)
    state="$4"
    if should_start_processing "$1" "$2" "$3" state; then printf '%s' "process"; else printf '%s' "skip"; fi )
}
assert_eq "continue-from empty -> process"            "process" "$(ssp 1 Alpha '' no)"
assert_eq "continue-from int 3, index 2 -> skip"      "skip"    "$(ssp 2 Beta 3 no)"
assert_eq "continue-from int 3, index 3 -> process"   "process" "$(ssp 3 Gamma 3 no)"
assert_eq "continue-from int 3, index 4 -> process"   "process" "$(ssp 4 Delta 3 no)"
assert_eq "continue-from already-yes -> process"      "process" "$(ssp 1 Alpha SomeTitle yes)"
assert_eq "continue-from title match (case-insens)"   "process" "$(ssp 5 documentation Documentation no)"
assert_eq "continue-from title no-match -> skip"      "skip"    "$(ssp 5 Other Documentation no)"

## ===========================================================================
printf '%s\n' "=== common: set_backup_page_item/decode round-trip ==="
## ===========================================================================
## The encode/decode pair used by the backup/restore filename mapping.
bp_roundtrip() {
  ( source "${mw_common}" >/dev/null 2>&1
    enc="$(set_backup_page_item "$1")"
    decode_backup_page_item "${enc}" )
}
for t in "Documentation" "Dev/mediawiki" "Template:Header" "Foo&Bar"; do
  assert_eq "set/decode_backup_page_item round-trip '${t}'" "${t}" "$(bp_roundtrip "${t}")"
done

## ===========================================================================
printf '%s\n' "=== common: exit_handler exit-code propagation ==="
## ===========================================================================
## A caller that cleans up before exiting clobbers $?, so it saves the code and
## passes it explicitly. exit_handler must honor that argument, otherwise a
## failing command exits 0 (silent failure). With no argument it reads $?.
rc=0
( source "${mw_common}" >/dev/null 2>&1
  true  ## clobber $? to 0, as a cleanup step would
  exit_handler 7 ) >/dev/null 2>&1 || rc=$?
assert_rc "exit_handler honors explicit code over clobbered \$?" "7" "${rc}"

rc=0
( source "${mw_common}" >/dev/null 2>&1
  ( exit 5 ); exit_handler ) >/dev/null 2>&1 || rc=$?
assert_rc "exit_handler falls back to \$? with no argument" "5" "${rc}"

## ===========================================================================
printf '%s\n' "=== help-flag detection: no unanchored '=~ (-h|--help)' ==="
## ===========================================================================
## Regression: `[[ "${1-}" =~ (-h|--help) ]]` is an UNANCHORED regex, so it
## matches any argument merely CONTAINING "-h" (a path like
## /home/.../-home-user/... , or a filename with "-h"), wrongly printing usage
## and refusing to run. The anchored `== "-h" || == "--help"` form must be used.
## Assert the buggy substring appears in no usr/bin script. grep rc: 0 = offender(s)
## found, 1 = clean (no match), >=2 = scan error (e.g. unreadable dir) -- a scan error
## must FAIL, never silently pass, so distinguish rc 1 from rc >=2 (a bare '|| true'
## would mask the error into a false green).
grep_rc=0
unanchored="$(grep -rlE '=~ \(-h\|--help\)' "${mw_bin}")" || grep_rc=$?
if [ "${grep_rc}" -ge 2 ]; then
  fail "help-flag scan errored (grep rc=${grep_rc}); cannot confirm anchoring in '${mw_bin}'"
elif [ -n "${unanchored}" ]; then
  fail "unanchored help check still present in: ${unanchored//$'\n'/ }"
else
  pass "no usr/bin script uses the unanchored '=~ (-h|--help)' help check"
fi

## ===========================================================================
printf '%s\n' "=== mw-file-to-web-archive: memento location detection ==="
## ===========================================================================
## Drives the REAL archive_save / archive_check (sourced via the script's sourced-guard) with a
## stubbed network layer -- no live wiki/archive.org. A snapshot is detected from a web.archive.org
## memento 'location:' header, checked BEFORE the HTTP status: curl --head --location replays the
## CAPTURED page, so the final status mirrors that page's own code (200, 403, 404, 500, ...) and a
## memento with a replayed non-200 status is still a real archive (verified live:
## web.archive.org/.../httpstat.us/500 returns a memento location and a final 500). The terminal
## status codes are the save/timegate endpoint's OWN control responses, which carry no memento.
## Verifies:
##  - 'location:' is matched case-insensitively (HTTP field names are case-insensitive, RFC 9110).
##  - the memento is honored even when the replayed status is a code the endpoint also uses as a
##    control response (403/404) -- the memento takes precedence over the status gate.
##  - a genuine control response (no memento): 429 is retryable (rc 1, nothing cached), 403 is
##    excluded, 404 is not-yet-archived -- preserved by the memento-first ordering.
##  - the memento match is ANCHORED: a location that merely CONTAINS the snapshot URL (open-redirect
##    style) or a look-alike host (web.archive.org.evil...) is not accepted.
##  - a bare non-memento redirect (final 302 without a snapshot location) is NOT recorded.
## archive_save reaches the net via curl_run; archive_check via the ${curl} command. Stub both;
## the driven function calls only one.
url='https://example.com/x'
snap='https://web.archive.org/web/20260101000000/https://example.com/x'
run_archive_case() {
  ## run_archive_case FUNC HEADER_LINE STATUS -> prints "<category> <rc>", category being which
  ## already-* file recorded the input URL, rc the function's exit status (controls the caller's
  ## save/retry loop). Categories: archived (URL line AND memento link in already-archived.txt),
  ## archived-nolink (URL recorded without the memento link -- a record not tied to the parsed
  ## header), down, excluded, unknown-error, unknown-case, none (URL in NO already-* file).
  local func="$1" header_line="$2" status="$3" outcome rc f arch tmp
  (
    tmp="$(mktemp -d)"
    export MEDIAWIKI_SHELL_COMMON="${mw_common}"
    export TMPFOLDER="${tmp}"
    mkdir -p -- "${TMPFOLDER}/webarchive"
    # shellcheck disable=SC1090,SC1091  # real subject resolved at runtime; sourced-guard skips main
    source "${mw_bin}/mw-file-to-web-archive"
    # shellcheck disable=SC2317  # called indirectly via curl_run / ${curl}, not statically visible
    stub_net() {
      printf '%s\n' "${header_line}" > "${TMPFOLDER}/webarchive/curl-output-temp"
      printf '%s' "${status}"
    }
    # shellcheck disable=SC2317  # invoked indirectly by archive_save, not statically visible
    curl_run() { stub_net; }
    # shellcheck disable=SC2317  # invoked indirectly by archive_check via ${curl}
    stub_curl_cmd() { stub_net; }
    # shellcheck disable=SC2034  # read by archive_check as ${curl} (nounset)
    curl=stub_curl_cmd
    # shellcheck disable=SC2034  # expanded by the sourced function's curl_run/${curl} call (nounset)
    curl_web_archive_opts=( "--head" )   # value irrelevant; the stub ignores them
    # shellcheck disable=SC2034  # read by archive_save's 429 branch (nounset); main sets it in production
    wait_if_too_many_requests=0
    rc=0
    "${func}" "${url}" >/dev/null 2>&1 || rc=$?
    ## Classify by which already-* file holds the input URL, so 'none' means truly nothing cached
    ## anywhere (not just absent from one or two files).
    outcome='none'
    arch="${TMPFOLDER}/webarchive/already-archived.txt"
    if [ -f "${arch}" ] && grep --fixed-strings --line-regexp --quiet -- "${url}" "${arch}"; then
      ## A real archive record carries the parsed memento link as its own line, not just the URL --
      ## so an impl that records the URL without reading the header is distinguishable.
      if grep --fixed-strings --line-regexp --quiet -- "${snap}" "${arch}"; then outcome='archived'; else outcome='archived-nolink'; fi
    else
      for f in "${TMPFOLDER}"/webarchive/already-*; do
        [ -f "${f}" ] || continue
        [ "${f}" = "${arch}" ] && continue
        if grep --fixed-strings --quiet -- "${url}" "${f}"; then
          case "${f##*/}" in
            already-known-down.txt)
              outcome='down'
              ;;
            already-known-excluded.txt)
              outcome='excluded'
              ;;
            already-known-unknown-error.txt)
              outcome='unknown-error'
              ;;
            already-unknown-case-error.txt)
              outcome='unknown-case'
              ;;
            *)
              outcome="other:${f##*/}"
              ;;
          esac
          break
        fi
      done
    fi
    safe-rm --recursive --force -- "${tmp}"
    printf '%s' "${outcome} ${rc}"
  )
}

## A location that merely CONTAINS the snapshot URL (open-redirect style), not anchored to it.
evil="https://evil.example/redir?u=${snap}"
## A look-alike host that contains the string 'web.archive.org' but is not the memento host.
lookalike='https://web.archive.org.evil.example/web/20260101000000/https://example.com/x'
## A look-alike host where a '.' position holds a different char -- catches a matcher that uses
## an unescaped regex dot (which would match 'webxarchive.org' as 'web.archive.org').
dotwild='https://webxarchive.org/web/20260101000000/https://example.com/x'
## A 'Link:' header carrying a DIFFERENT memento (real Wayback responses include one, with a
## trailing '>;'), ahead of the real 'location:' memento. The recorded link must come from the
## 'location:' header, not the first web.archive.org URL anywhere in the dump.
linkhdr=$'link: <https://web.archive.org/web/19990101000000/https://example.com/x>; rel="memento"\nlocation: '"${snap}"
## A non-memento redirect target (for the bare-302 case).
plain='https://example.com/elsewhere'
## A multi-hop redirect chain whose memento is a LATER hop (the first hop is a relative /
## normalization redirect), to guard against reading only the first 'location:' header.
multihop=$'location: /web/20201027215555/https://example.com/x\nlocation: '"${snap}"

assert_eq "archive_save: lowercase memento + 200 -> archived" \
  "archived 0" "$(run_archive_case archive_save "location: ${snap}" 200)"
assert_eq "archive_save: uppercase 'Location:' memento + 200 -> archived (case-insensitive)" \
  "archived 0" "$(run_archive_case archive_save "Location: ${snap}" 200)"
assert_eq "archive_save: memento + replayed 403 -> archived (memento precedes status gate)" \
  "archived 0" "$(run_archive_case archive_save "location: ${snap}" 403)"
assert_eq "archive_save: no memento + 429 -> retryable, nothing cached" \
  "none 1" "$(run_archive_case archive_save "location: ${plain}" 429)"
assert_eq "archive_save: no memento + 403 -> excluded" \
  "excluded 0" "$(run_archive_case archive_save "location: ${plain}" 403)"
assert_eq "archive_save: location only CONTAINS snapshot URL + 200 -> not archived (anchored)" \
  "unknown-case 0" "$(run_archive_case archive_save "location: ${evil}" 200)"
assert_eq "archive_save: web.archive.org look-alike host + 200 -> not archived (anchored)" \
  "unknown-case 0" "$(run_archive_case archive_save "location: ${lookalike}" 200)"
assert_eq "archive_save: unescaped-dot look-alike host (webxarchive.org) + 200 -> not archived" \
  "unknown-case 0" "$(run_archive_case archive_save "location: ${dotwild}" 200)"
assert_eq "archive_save: Link: header memento ignored; records the location: memento" \
  "archived 0" "$(run_archive_case archive_save "${linkhdr}" 200)"
assert_eq "archive_save: bare non-memento redirect (302) -> not archived" \
  "unknown-case 0" "$(run_archive_case archive_save "location: ${plain}" 302)"
assert_eq "archive_save: memento on a later redirect hop -> archived (scans all hops)" \
  "archived 0" "$(run_archive_case archive_save "${multihop}" 200)"
assert_eq "archive_check: uppercase 'Location:' memento + 200 -> archived (case-insensitive)" \
  "archived 0" "$(run_archive_case archive_check "Location: ${snap}" 200)"
assert_eq "archive_check: memento + replayed 404 -> archived (memento precedes status gate)" \
  "archived 0" "$(run_archive_case archive_check "location: ${snap}" 404)"
assert_eq "archive_check: no memento + 404 -> not archived, retryable" \
  "none 1" "$(run_archive_case archive_check "location: ${plain}" 404)"
assert_eq "archive_check: location only CONTAINS snapshot URL + 200 -> not archived (anchored)" \
  "none 1" "$(run_archive_case archive_check "location: ${evil}" 200)"
assert_eq "archive_check: unescaped-dot look-alike host (webxarchive.org) + 200 -> not archived" \
  "none 1" "$(run_archive_case archive_check "location: ${dotwild}" 200)"
assert_eq "archive_check: memento on a later redirect hop -> archived (scans all hops)" \
  "archived 0" "$(run_archive_case archive_check "${multihop}" 200)"

## ===========================================================================
printf '%s\n' "=== SUMMARY ==="
## ===========================================================================
printf '%s\n' "PASS=${PASS} FAIL=${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
  printf '%s\n' "FAILURES:" >&2
  printf '%s' "${ERRORS}" >&2
  exit 1
fi
printf '%s\n' "$0: all offline unit tests passed."
