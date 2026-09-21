#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Consistency lint over the dist-ai-tests-all suite registry.
##
## WHY this exists: every inconsistency it checks for FAILS SILENTLY as a green
## run, which is the worst possible failure mode for a test runner. An audit
## found all five live at once:
##   - a registered suite whose entrypoint lost its executable bit is reported
##     MISSING and counted as a SKIP, so a PR-gating suite stopped running with
##     no signal (web-analyzer-tests);
##   - a suite with no debian/*.install is MISSING the same way once installed,
##     while still passing from a checkout (lockfile-tests);
##   - a suite with no wire() case hits wire()'s 'return 1' default under
##     errexit and ABORTS the whole run mid-way (lockfile, iso-boot,
##     dm-reprepro-tracking);
##   - a suite with no suite_component() mapping silently drops out of every
##     --component run, i.e. out of per-repo CI, while looking registered;
##   - an entrypoint in no *_suites array never runs at all, not even under
##     --all (dm-image-boot-tests, dm-reproducible-build-tests).
##
## This is a source-tree lint: it needs the repo, and exits 77 without one.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Entrypoints that are deliberately NOT suites. Keep this list short and
## justified: every addition is a suite that stops being checked.
##   dist-ai-tests-all  the runner itself
##   privleap-tests-coverage  a measurement wrapper, not a suite: it RUNS the
##     registered privleap suites and reports how much of privleap they reach,
##     so registering it would run them a second time and assert nothing new
##   dm-stripped-setx-audit  a review AID with no verdict: whether removing
##     'set -x' from a given script was right cannot be decided mechanically,
##     so it reports and exits 0 and a human decides. It also compares each
##     package's 'ai' branch against org-ai-assisted/master, which a CI runner
##     has no refs for. Same shape as comments-audit.
##   website-tests-sandbox  the sandbox DELEGATE that website-tests invokes to
##     run the browser lanes (check_mobile / check_width) confined in the review
##     qube; it is not a standalone suite. Registering it would run those lanes a
##     second time and assert nothing new (same shape as privleap-tests-coverage).
##   privleap-tests-session-fuzz-setup  a CI runtime PROVISIONER, not a suite: it
##     installs the privleap group / PAM policy / shim on a throwaway container so
##     the privleap-tests-session-fuzz workflow can run the daemon; it asserts
##     nothing itself, and needs root + a checkout arg no orchestrator lane passes.
##   privleap-tests-fuzz-ci  the CI ORCHESTRATOR wrapping the provisioner above:
##     installs container prerequisites, sets up the runtime, creates the
##     unprivileged caller, and runs the whole privleap --fuzz category (in-process
##     parser fuzz + live-daemon session fuzz) as it. Same reason as the setup
##     script: root + a checkout arg no orchestrator lane passes.
allowed_unregistered=(
   'dist-ai-tests-all'
   'privleap-tests-coverage'
   'dm-stripped-setx-audit'
   'website-tests-sandbox'
   'privleap-tests-session-fuzz-setup'
   'privleap-tests-fuzz-ci'
)

## Suite BASE names with no owning component repo, so no suite_component()
## mapping is possible. Each is deliberate and matches the reason recorded in
## the suite's own wire() case; anything not listed here that lacks a mapping is
## an oversight, not a design choice.
##   web-analyzer     analyzer.js lives in output-lies.github.io
##   website          the Pages sites live in their own repos
##   iso-boot         the QMP parser is dist-ai's own payload
##   dm-image-boot    self-contained; takes a built image as an argument
##   dm-gitlink-upstream-check  self-contained; offline --self-test of dist-ai's
##                    own tool, no component checkout under test
allowed_no_component=(
   'web-analyzer'
   'website'
   'iso-boot'
   'dm-image-boot'
   'dm-gitlink-upstream-check'
)

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## Resolve the dist-ai source tree: an explicit override, else the checkout this
## script lives in (usr/share/<suite>/ -> repo root).
repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dist-ai-tests-all" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/usr/bin/dist-ai-tests-all" ] || [ ! -d "${repo}/debian" ]; then
   ## No tree to lint is a missing TARGET, not an inconsistency -- SKIP, per the
   ## header contract and the project convention (dist-ai-tests-all maps exit 77
   ## to SKIP).
   printf '%s\n' 'SKIP: dist-ai-registry-tests: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 77  ## style-ok: allow-skip: no dist-ai source tree present to lint
fi

runner="${repo}/usr/bin/dist-ai-tests-all"

failures=0
checks=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## ---- parse the registry out of dist-ai-tests-all --------------------------
## Textual parsing on purpose: dist-ai-tests-all runs its work at top level, so
## it cannot be sourced to introspect it.

registered_suites=()
in_array=''
wire_labels=()
component_labels=()
wired_env_vars=()
in_func=''

while read -r line; do
   ## Suite arrays.
   case "${line}" in
      'core_suites=('|'fuzz_suites=('|'e2e_suites=('|'integration_suites=(')
         in_array='yes'
         continue
         ;;
      ')')
         in_array=''
         continue
         ;;
   esac
   if [ -n "${in_array}" ]; then
      case "${line}" in
         ''|'#'*)
            ;;
         *)
            registered_suites+=( "${line}" )
            ;;
      esac
      continue
   fi

   ## Function bodies.
   case "${line}" in
      'wire() {')
         in_func='wire'
         continue
         ;;
      'suite_component() {')
         in_func='component'
         continue
         ;;
      '}')
         in_func=''
         continue
         ;;
   esac
   [ -n "${in_func}" ] || continue

   ## Collect the env var names wire() actually SETS, from its
   ## wire_env=( "VAR=..." ) elements, so the *_BIN wiring check below matches a
   ## real assignment -- not an unrelated 'VAR=' mention (a comment, another
   ## string) anywhere in the file, which the old whole-file grep accepted.
   if [ "${in_func}" = 'wire' ]; then
      case "${line}" in
         '#'*)
            ## A comment -- incl. a commented-out wire_env=( "VAR=..." ) -- is not
            ## a real assignment; skip it so it cannot false-wire a *_BIN var.
            ;;
         *)
            ## Also drop a trailing comment so a "VAR=" inside it does not count.
            env_rest="${line%% #*}"
            while [[ "${env_rest}" =~ \"([A-Za-z_][A-Za-z0-9_]*)= ]]; do
               wired_env_vars+=( "${BASH_REMATCH[1]}" )
               env_rest="${env_rest#*"${BASH_REMATCH[0]}"}"
            done
            ;;
      esac
   fi

   ## A case label: ends in ')', with no '(' or '=' or whitespace, and is not
   ## the catch-all. Excludes 'wire_env=( ... )' and friends.
   case "${line}" in
      '*)'|*'('*|*'='*|*' '*|*$'\t'*)
         continue
         ;;
      *')')
         ;;
      *)
         continue
         ;;
   esac
   label="${line%)}"
   ## Split an alternation like 'a|b|c' on '|'.
   IFS='|' read -r -a parts <<< "${label}"
   for part in "${parts[@]}"; do
      [ -n "${part}" ] || continue
      if [ "${in_func}" = 'wire' ]; then
         wire_labels+=( "${part}" )
      else
         component_labels+=( "${part}" )
      fi
   done
done < "${runner}"

## Parser desync guard: every suite array and function body opened above must
## have closed. A close line the case did not match (e.g. a ')' carrying a
## trailing comment) would leave in_array/in_func set, and the parser would then
## collect whatever followed -- function bodies as "suite entries", say -- into
## the registry, silently. Turn that into a loud failure rather than a corrupt,
## still-green parse.
if [ -n "${in_array}" ] || [ -n "${in_func}" ]; then
   fail 'registry parse did not close cleanly (a suite array or wire()/suite_component() body) -- the format changed and this lint would parse the wrong lines; fix the parser'
   printf '%s\n' '' "FAILED: ${failures} registry check(s) failed" >&2
   exit 1
fi

if [ "${#registered_suites[@]}" -eq 0 ]; then
   fail 'parsed zero registered suites -- the registry format changed and this lint is now blind'
   printf '%s\n' '' "FAILED: ${failures} registry check(s) failed" >&2
   exit 1
fi

## True when some debian/*.install source pattern covers a repo-relative path.
## The patterns are GLOBS ('usr/*', 'usr/share/foo/*.sh'), so an exact string
## compare would miss every one of them.
installed_covers() {
   local candidate="$1"
   local install_src
   for install_src in "${installed_sources[@]}"; do
      # shellcheck disable=SC2254
      case "${candidate}" in
         ${install_src})
            return 0
            ;;
      esac
   done
   return 1
}

has_label() {
   local needle="$1"
   shift
   local candidate
   for candidate in "$@"; do
      if [ "${candidate}" = "${needle}" ]; then
         return 0
      fi
   done
   return 1
}

## Source patterns from every debian/*.install, one per element -- the FIRST
## field of each line (the second is the destination directory).
##
## Parsed into a list rather than substring-matched against one concatenated
## blob: command substitution strips trailing newlines, so a blob match needed
## the entry to be followed by a space or a newline, and the last line of the
## last file has neither. A one-column line (valid dh_install syntax) at the end
## of a file therefore read as "not shipped" -- a false failure.
## Collect the .install files by glob under nullglob, so a tree with none
## yields an EMPTY list (a clear, loud failure below) rather than the literal
## unexpanded 'debian/*.install' -- which cat would then try to open as a file
## (error) or, once a stray nullglob elsewhere is in effect, drop to reading
## stdin and hang. Restore the caller's glob setting immediately.
install_files=()
if shopt -q nullglob; then
   install_files=( "${repo}"/debian/*.install )
else
   shopt -s nullglob
   install_files=( "${repo}"/debian/*.install )
   shopt -u nullglob
fi
if [ "${#install_files[@]}" -eq 0 ]; then
   fail 'no debian/*.install under the tree -- cannot verify what an installed system ships; the registry format or layout changed and this lint is now blind'
   printf '%s\n' '' "FAILED: ${failures} registry check(s) failed" >&2
   exit 1
fi
installed_sources=()
while read -r install_src _install_dest; do
   case "${install_src}" in
      ''|'#'*)
         continue
         ;;
   esac
   installed_sources+=( "${install_src}" )
done < <( cat -- "${install_files[@]}" )

## ---- check each registered suite ------------------------------------------
for suite in "${registered_suites[@]}"; do
   entry="${repo}/usr/bin/${suite}"
   base="${suite%%-tests*}"

   checks=$(( checks + 1 ))
   if [ ! -f "${entry}" ]; then
      fail "${suite}: registered but usr/bin/${suite} does not exist"
      continue
   fi
   if [ ! -x "${entry}" ]; then
      fail "${suite}: usr/bin/${suite} is not executable -- the runner would report it MISSING and count a silent SKIP"
   fi

   if ! installed_covers "usr/bin/${suite}"; then
      fail "${suite}: no debian/*.install ships usr/bin/${suite} -- it would be MISSING on an installed system"
   fi

   if ! has_label "${base}" "${wire_labels[@]}"; then
      fail "${suite}: no wire() case for base '${base}' -- wire()'s default returns 1 and aborts the entire run under errexit"
   fi

   if ! has_label "${base}" "${component_labels[@]}" \
      && ! has_label "${base}" "${allowed_no_component[@]}"; then
      fail "${suite}: no suite_component() mapping for base '${base}' -- it silently drops out of every --component run, i.e. out of per-repo CI"
   fi
done

## ---- check that every payload FILE is shipped -----------------------------
## The entrypoint check says nothing about usr/share/. An .install that
## ENUMERATES payload files one per line instead of globbing silently drops a
## newly added one: the suite still runs, collects fewer test files than the
## checkout holds, and exits 0 -- green while covering less than it claims,
## which is the same class this lint exists to close.
## GIT-TRACKED files only. A working tree carries build artefacts a package
## never ships (.pytest_cache, .hypothesis, .coverage), and flagging those would
## be pure noise; what gets packaged is what is committed.
if ! git -C "${repo}" rev-parse --git-dir >/dev/null 2>&1; then
   printf '%s\n' "NOTE: ${repo} is not a git checkout; skipping the payload-shipping check."
   payload_files=()
else
   mapfile -d '' -t payload_files < <(
      git -C "${repo}" ls-files -z -- 'usr/share/*-tests*' )
fi

for rel in "${payload_files[@]}"; do
   checks=$(( checks + 1 ))
   if ! installed_covers "${rel}"; then
      fail "${rel}: in a test payload dir but matched by no debian/*.install pattern -- absent on an installed system, so the suite would silently cover less"
   fi
done

## ---- check every *_BIN override a payload reads is wired ------------------
## A PYTHON payload that resolves its subject from os.environ.get('X_BIN',
## '/home/user/...') falls back, when the var is unset, to a hardcoded
## developer-box path that never exists in CI -- so the affected cases degrade
## to SKIPs and the run still reports PASS, exactly the silent green this lint
## exists for. It cost the sanitize-string suite 3019 silently skipped
## sanitize-echo fuzz cases, because wire() set SANITIZE_STRING_BIN but not
## SANITIZE_ECHO_BIN.
##
## Python only. Shell suites read `${X_BIN:-<fallback>}` and then check the
## resolved subject explicitly: they either fall back to a checkout-relative
## path that DOES exist in CI, or `exit 1` FATAL when nothing resolves -- never
## the silent-skip shape above (and a silent shell skip is caught by R-220, not
## here). So scanning `.sh` for this Python idiom matched nothing and only
## misled; it is intentionally not scanned.
bin_vars=()
mapfile -t bin_vars < <(
   grep --recursive --no-filename --only-matching --extended-regexp \
      --include='*.py' \
      "os\.environ\.get\(['\"][A-Z0-9_]+_BIN['\"]" -- "${repo}/usr/share" \
   | grep --only-matching --extended-regexp '[A-Z0-9_]+_BIN' \
   | sort --unique )

checks=$(( checks + 1 ))
if [ "${#bin_vars[@]}" -eq 0 ]; then
   fail 'parsed zero *_BIN overrides out of the suite payloads -- the pattern changed and this check is now blind'
fi

for bin_var in "${bin_vars[@]}"; do
   checks=$(( checks + 1 ))
   ## Wired means SET by a wire_env element, not merely mentioned somewhere in
   ## the file (a comment or an unrelated string would false-PASS the old grep).
   if ! has_label "${bin_var}" "${wired_env_vars[@]}"; then
      fail "${bin_var}: read by a suite payload but wired by no wire() case -- the payload falls back to its hardcoded developer-box path, which never exists in CI, and silently skips every case that needs it"
   fi
done

## ---- check for entrypoints that are registered nowhere --------------------
shopt -s nullglob
for entry in "${repo}"/usr/bin/*-tests "${repo}"/usr/bin/*-tests-*; do
   name="$(basename -- "${entry}")"
   checks=$(( checks + 1 ))
   if has_label "${name}" "${allowed_unregistered[@]}"; then
      continue
   fi
   if ! has_label "${name}" "${registered_suites[@]}"; then
      fail "${name}: an entrypoint in no *_suites array -- it never runs, not even under --all (register it, or add it to allowed_unregistered with a reason)"
   fi
done

printf '%s\n' '' "===== summary: ${checks} checks, ${failures} failure(s) ====="
if [ "${failures}" -ne 0 ]; then
   printf '%s\n' 'FAILED: the suite registry is inconsistent' >&2
   exit 1
fi
printf '%s\n' 'OK: every registered suite has an executable entrypoint, a debian/*.install entry, a wire() case and a suite_component() mapping'
exit 0
