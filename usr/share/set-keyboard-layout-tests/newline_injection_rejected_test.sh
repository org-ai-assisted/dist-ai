#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## parse_cmd must REJECT a layout argument containing a control character
## (embedded newline) before dispatching to the keymap-writing function.
##
## The layout/variant/option args are written verbatim into config files
## ('/etc/default/keyboard', the 'labwc' environment file). The per-token
## validators split their check strings on newlines, so a SINGLE argument with an
## embedded newline whose every line is individually a valid layout (e.g.
## 'us\nde') passes validation on unfixed code and reaches the writer, which then
## emits 'XKBLAYOUT=us\nde' -- injecting a stray 'de' line into the config file
## (config corruption; untrusted CLI / D-Bus argument vector).
##
## BEHAVIORAL test: source the shipped library (source-able via its was_executed
## guard, so main()/parse_cmd do not auto-run), point 'function_name' at a
## recording sink, stub 'localectl-static' to report 'us' and 'de' as valid, then
## drive the REAL parse_cmd:
##   tainted 'us<newline>de': the dispatch sink is NOT reached and parse_cmd
##      returns nonzero -- the tainted value never reaches the config writer.
##   clean 'us': the dispatch sink IS reached -- proof the test drives the real
##      dispatch path, so the tainted assertion has teeth (no fabricated pass).
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v SET_KEYBOARD_LAYOUT_REPO ] || SET_KEYBOARD_LAYOUT_REPO=""
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""

lib_rel='usr/libexec/helper-scripts/set-keyboard-layout.sh'
lib=""
lib_repo=""

## Resolve the library under test, highest precedence first. An explicitly-set
## override (SET_KEYBOARD_LAYOUT_REPO > HELPER_SCRIPTS_REPO > HELPER_SCRIPTS_PATH)
## NAMES the subject: if it is set but its lib is not a readable regular file, fail
## closed -- do NOT fall through to a lower-precedence override or the installed copy.
## The installed copy is used ONLY when no override is set at all. lib_repo is the
## repo root of the resolved lib, exported as HELPER_SCRIPTS_PATH so the library's
## own sources resolve against the same checkout.
for repo_var in SET_KEYBOARD_LAYOUT_REPO HELPER_SCRIPTS_REPO HELPER_SCRIPTS_PATH; do
   repo_val="${!repo_var}"
   [ -n "${repo_val}" ] || continue
   if [ -f "${repo_val}/${lib_rel}" ] && [ -r "${repo_val}/${lib_rel}" ]; then
      lib="${repo_val}/${lib_rel}"
      lib_repo="${repo_val}"
   else
      printf '%s\n' "FATAL: ${repo_var}='${repo_val}' set but '${repo_val}/${lib_rel}' is not a readable file" >&2
      printf '%s\n' "an explicit override must point at a readable helper-scripts checkout; refusing to silently fall back" >&2
      exit 1
   fi
   break
done

if [ -z "${lib}" ] && [ -f "/${lib_rel}" ] && [ -r "/${lib_rel}" ]; then
   lib="/${lib_rel}"
   lib_repo=""
fi

if [ -z "${lib}" ]; then
   printf '%s\n' "FATAL: set-keyboard-layout.sh not found" >&2
   printf '%s\n' "set SET_KEYBOARD_LAYOUT_REPO or HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install the package" >&2
   exit 1
fi

pass_count=0
fail_count=0
ok() { pass_count=$(( pass_count + 1 )); printf '%s\n' "  ok: $1"; }
notok() { fail_count=$(( fail_count + 1 )); printf '%s\n' "  NOT OK: $1" >&2; }

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
harness="${tool_dir}/../dist-ai-tests-common/stub-path-harness.bash"
if [ ! -r "${harness}" ]; then
   printf '%s\n' "FATAL: stub-path harness not found at '${harness}'" >&2
   exit 1
fi
# shellcheck source=../dist-ai-tests-common/stub-path-harness.bash
source "${harness}"

## Source the sourceable library: was_executed is false here, so main()/parse_cmd
## do NOT auto-run -- only the function definitions load. HELPER_SCRIPTS_PATH points
## at the resolved checkout so the library's own sources resolve there.
export HELPER_SCRIPTS_PATH="${lib_repo}"
# shellcheck disable=SC1090
source "${lib}"

## A recording sink standing in for the real keymap-writing function. parse_cmd
## dispatches via "${function_name}"; pointing that at this sink isolates the guard
## under test -- if the tainted value reaches dispatch, the marker is written, which
## on unfixed code is exactly the value that would be written into the config file.
newline_dispatch_recorder() {
   printf 'CALLED\n' >> "${STUB_PATH_REC}/dispatch.marker"
}

## Drive the real parse_cmd with "$@" under a fresh stub PATH. localectl-static
## reports 'us' and 'de' as valid so a tainted 'us<newline>de' would otherwise pass
## validation. Echoes 'called'/'not-called' plus parse_cmd's exit code.
run_parse_case() {
   (
      stub_path_init
      ## Report every token the cases use as valid, for layouts AND variants AND
      ## options (the stub returns the same list for each localectl-static query).
      stub_cmd localectl-static 0 "$(printf 'us\nde\nnodeadkeys\ncompose:ralt')"

      # shellcheck disable=SC2034  # consumed by the sourced parse_cmd
      function_name='newline_dispatch_recorder'
      # shellcheck disable=SC2034  # populated by the sourced parse_cmd from "$@"
      args=()
      # shellcheck disable=SC2034  # consumed by the sourced parse_cmd
      skl_interactive='false'
      # shellcheck disable=SC2034  # consumed by the sourced parse_cmd
      do_build_all_grub_keymaps='false'
      # shellcheck disable=SC2034  # consumed by the sourced check_keyboard_layouts
      timeout_command=()
      # shellcheck disable=SC2034  # consumed by the sourced parse_cmd/callees
      scriptname='set-console-keymap'

      parse_rc=0
      parse_cmd "$@" >/dev/null 2>&1 || parse_rc=$?

      if [ -f "${STUB_PATH_REC}/dispatch.marker" ]; then
         printf '%s\n' "called rc=${parse_rc}"
      else
         printf '%s\n' "not-called rc=${parse_rc}"
      fi
      stub_path_cleanup
   )
}

## Positive control: a clean, valid layout must reach dispatch, proving the test
## drives the real parse_cmd path (so the tainted assertion below has teeth).
clean_result="$(run_parse_case 'us')"
if [ "${clean_result}" = 'called rc=0' ]; then
   ok "clean 'us' reaches dispatch (the behavioral assertion has teeth)"
else
   notok "clean 'us' did not reach dispatch as expected (result='${clean_result}')"
fi

## Teeth: an embedded newline whose lines are each individually valid layouts must
## be rejected before dispatch. On unfixed code it passes validation and reaches the
## writer (result would be 'called rc=0').
## The variant (args[1]) and option (args[2]) are ALSO written verbatim into the
## config, so an embedded newline in ANY of the three must be rejected -- not just
## the layout. Each injected value newline-joins two INDIVIDUALLY VALID tokens, so
## on unfixed code validation passes and the tainted value reaches the writer
## ('called rc=0'); only the control-char guard rejects it. (localectl-static is
## stubbed to report all of these tokens as valid.)
assert_arg_rejected() {
   local slot="$1"
   shift
   local res
   res="$(run_parse_case "$@")"
   case "${res}" in
      'not-called rc='[1-9]*)
         ok "embedded-newline ${slot} arg rejected before dispatch (no config injection)"
         ;;
      *)
         notok "embedded-newline ${slot} arg was NOT rejected before dispatch (result='${res}')"
         ;;
   esac
}

assert_arg_rejected 'layout' "$(printf 'us\nde')" '' ''
assert_arg_rejected 'variant' 'us' "$(printf 'nodeadkeys\nnodeadkeys')" ''
assert_arg_rejected 'option' 'us' '' "$(printf 'compose:ralt\ncompose:ralt')"

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
