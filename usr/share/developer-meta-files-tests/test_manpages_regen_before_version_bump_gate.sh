#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards dm-packaging-helper-script's drift-closure ordering:
## pkg_need_version_bump_and_pkg_build_and_reprepro_add must regenerate the
## generated artifacts (pkg_git_manpages, pkg_git_debinstfile) UNCONDITIONALLY,
## before pkg_need_version_bump_show and its "needs bump" early-return. Only
## then does a lone man/*.ronn edit get regenerated+committed every packaging
## pass regardless of release state; left behind the gate (the prior bug), a
## quiet package's committed auto-generated-man-pages/ silently drifts from
## its source.
##
## Structural check against the CURRENT script text (no drift): an unconditional
## (base-indentation) call that precedes the gate is a pure statement-placement
## invariant, so a text assertion is the faithful guard and needs no
## reprepro/dpkg fixture.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$(( test_failures + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

rel='usr/bin/dm-packaging-helper-script'
candidates=()
[ -z "${DM_PACKAGING_HELPER_SCRIPT:-}" ] || candidates+=( "${DM_PACKAGING_HELPER_SCRIPT}" )
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
candidates+=( "/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: dm-packaging-helper-script not found (set DM_PACKAGING_HELPER_SCRIPT)." >&2
   exit 1
fi

## Extract the orchestration function body. Its closing brace is the only '}'
## at column 0.
func_text="$(awk '
   /^pkg_need_version_bump_and_pkg_build_and_reprepro_add\(\) \{/ { f=1 }
   f                                                              { print }
   f && /^\}/                                                     { exit }
' "${subject}")"
if [ -z "${func_text}" ]; then
   printf '%s\n' "FATAL: could not extract pkg_need_version_bump_and_pkg_build_and_reprepro_add from '${subject}'." >&2
   exit 1
fi

## 1-based line index of the gate call, and its leading whitespace. The three
## calls sit at the function's top level, so that indentation is the "base": a
## regen call found as a bare line at exactly that indent is UNCONDITIONAL,
## while one wrapped in an if/loop is indented deeper and must not match. This
## is a simple whole-line match, not a bash-control-flow parser.
gate_raw="$(printf '%s\n' "${func_text}" \
   | grep --extended-regexp -- '^[[:space:]]*pkg_need_version_bump_show([[:space:]]|$)' \
   | head -1 \
   || true)"
if [ -z "${gate_raw}" ]; then
   fail "pkg_need_version_bump_show not called in the orchestration function"
   printf '%s\n' "${pass_count} pass, ${test_failures} fail, 0 skip"
   exit 1
fi
## The function's base (top-level) indentation, derived INDEPENDENTLY of the gate
## call: the leading whitespace of the first STATEMENT in the body (after the
## 'name() {' header), skipping blank and COMMENT lines. Deriving it from gate_raw
## instead let an all-three-in-one-conditional evade -- a gate nested in an if/loop
## would set the "base" to that deeper indent, so a regen nested alongside it would
## masquerade as unconditional. A comment may sit at column 0 (or any indent)
## regardless of the code's indent, so it does not mark the base. Assumes the first
## statement is a normal top-level line (these functions open with a plain call); a
## first line that opened a heredoc / line-continuation is out of scope.
base_indent=""
header_seen="false"
while IFS= read -r line; do
   if [ "${header_seen}" = "false" ]; then
      ## The 'name() {' header line itself.
      header_seen="true"
      continue
   fi
   trimmed="${line#"${line%%[![:space:]]*}"}"
   if [ -z "${trimmed}" ]; then
      continue
   fi
   case "${trimmed}" in
      '#'*)
         continue
         ;;
   esac
   base_indent="${line%%[![:space:]]*}"
   break
done <<< "${func_text}"
show_line="$(printf '%s\n' "${func_text}" \
   | grep --line-number --extended-regexp -- '^[[:space:]]*pkg_need_version_bump_show([[:space:]]|$)' \
   | head -1 \
   | cut -d: -f1 \
   || true)"

## 1-based line index of a bare, unconditional call to ${1} -- a whole line
## equal to base_indent + name (no args, no && / || / conditional) -- or empty.
base_call_line() {
   local needle="${1}"
   printf '%s\n' "${func_text}" \
      | grep --line-number --fixed-strings --line-regexp -- "${base_indent}${needle}" \
      | head -1 \
      | cut -d: -f1 \
      || true
}

manpages_line="$(base_call_line 'pkg_git_manpages')"
debinstfile_line="$(base_call_line 'pkg_git_debinstfile')"

if [ -z "${manpages_line}" ]; then
   fail "pkg_git_manpages not called unconditionally at function base indentation -- absent, or nested in a conditional/loop, so man pages can drift"
elif [ "${manpages_line}" -lt "${show_line}" ]; then
   pass "pkg_git_manpages (line ${manpages_line}) runs unconditionally before the version-bump gate (line ${show_line})"
else
   fail "pkg_git_manpages (line ${manpages_line}) runs at/after the version-bump gate (line ${show_line}) -- man pages drift on quiet packages"
fi

if [ -z "${debinstfile_line}" ]; then
   fail "pkg_git_debinstfile not called unconditionally at function base indentation -- absent, or nested in a conditional/loop, so the install file can drift"
elif [ "${debinstfile_line}" -lt "${show_line}" ]; then
   pass "pkg_git_debinstfile (line ${debinstfile_line}) runs unconditionally before the version-bump gate (line ${show_line})"
else
   fail "pkg_git_debinstfile (line ${debinstfile_line}) runs at/after the version-bump gate (line ${show_line}) -- install file drifts on quiet packages"
fi

## Pathspec-scoping of these regen commits (that pkg_git_manpages /
## pkg_git_debinstfile commit ONLY their generated paths, never a sibling's staged
## change) is covered BEHAVIOURALLY by test_pkg_git_manpages_pathspec_abort.sh: it
## drives the real git_commit_pathspecs against throwaway repos and asserts the
## single commit carries only the given pathspecs, plus that both callers wire
## through it. This test keeps the ORDERING invariant only (regen runs
## unconditionally before the version-bump gate); a text re-check of the commit
## scoping here would only duplicate that behavioural test more weakly.

printf '%s\n' "${pass_count} pass, ${test_failures} fail, 0 skip"
[ "${test_failures}" -eq 0 ]
