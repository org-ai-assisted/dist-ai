#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## set_console_keymap must NOT restart keyboard-setup.service when not running as
## root. BEHAVIORAL test: it sources the shipped library (source-able via its
## was_executed guard, so main()/parse_cmd do not run), stubs the external commands
## on PATH, and calls set_console_keymap under two identities, asserting on the
## RECORDED invocations, not on the source text:
##   non-root (id --user -> nonzero): NO 'restart keyboard-setup.service' recorded
##      -- the root guard held.
##   root (id --user -> 0): the restart IS recorded -- proof the test drives the
##      real restart path, so the non-root assertion has teeth (no fabricated pass).
## Immune to comments, whitespace, wording and ordering; and it catches a guard
## neutered WITHIN the definition (guard text left only in an inert log line or a
## trailing comment, a conditional return) that a source-text check cannot see.
##
## A duplicate set_console_keymap definition still fails closed on the definition
## COUNT below (bash runs the LAST copy, so a single sourced body cannot tell which
## one runs), before any behavioral run.
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
## Falling through would silently test a different file than the one the caller pointed
## at, reporting green for a checkout whose library was renamed or deleted. Require a
## regular file (-f), not merely a readable path (-r): a directory, FIFO, or device at
## the lib path is -r-readable but would make sourcing below fail or block. The
## installed copy is used ONLY when no override is set at all. lib_repo is the repo
## root of the resolved lib, exported as HELPER_SCRIPTS_PATH so the library's own
## sources resolve against the same checkout.
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

## Call set_console_keymap once under a fresh stub PATH with 'id --user' -> $1.
## Echoes 'restart' if a keyboard-setup.service restart was recorded, else
## 'no-restart'. The externals set_console_keymap invokes are stubbed to force the
## path to the restart: id sets the identity, the systemctl status check succeeds
## (so the restart branch is entered), ischroot reports not-a-chroot, and the
## filesystem-writing helpers are neutralized. do_force='true' short-circuits the
## real LUKS prompt; the restart itself flows through the real log_run to the
## recording systemctl stub.
run_keymap_case() {
   local uid="$1"
   (
      stub_path_init
      stub_cmd id 0 "${uid}"
      stub_cmd systemctl 0
      stub_cmd ischroot 1
      stub_cmd mkdir 0
      stub_cmd overwrite 0
      stub_cmd stcat 0
      stub_cmd dpkg-reconfigure 0

      set_console_keymap >/dev/null 2>&1 || true

      if stub_called_with systemctl 'restart keyboard-setup.service'; then
         printf '%s\n' 'restart'
      else
         printf '%s\n' 'no-restart'
      fi
      stub_path_cleanup
   )
}

## Require EXACTLY ONE set_console_keymap definition before sourcing/running it.
## bash keeps the LAST definition of a repeated name, so a duplicate (a bad
## merge/rebase leaving a stale guarded copy above an unguarded live one) would let
## the dead copy be trusted while the live one runs unguarded -- fail closed on any
## count != 1. The count matches a definition HEADER ('function name', or the name
## followed by '(' -- so 'name(', 'name (', 'name( )' all count), erring toward
## OVER-counting, a fail-CLOSED direction. This is a cheap structural invariant, not
## a body parser: telling a live guard from inert text is what the behavioral run does.
def_count="$(grep --count --extended-regexp -- '^[[:space:]]*(function[[:space:]]+set_console_keymap([[:space:]]|\(|$)|set_console_keymap[[:space:]]*\()' "${lib}" || true)"
if [ "${def_count}" -eq 1 ]; then
   ok "exactly one set_console_keymap definition"

   ## Source the sourceable library: was_executed is false here, so main()/parse_cmd
   ## do NOT run -- only the function definitions load. HELPER_SCRIPTS_PATH points at
   ## the resolved checkout so the library's own sources resolve there.
   export HELPER_SCRIPTS_PATH="${lib_repo}"
   # shellcheck disable=SC1090
   source "${lib}"

   ## Globals main() would normally set; the test provides the ones set_console_keymap
   ## and its callees read. args empty -> no layout writes; timeout_command empty ->
   ## the stubbed commands run directly; do_force -> real LUKS prompt returns early.
   args=()
   skl_default_keyboard_var_names=( 'XKBLAYOUT' 'XKBVARIANT' 'XKBOPTIONS' )
   do_live_changes='true'
   timeout_command=()
   do_force='true'
   did_prompt_for_luks='false'
   scriptname='set-console-keymap'

   nonroot_result="$(run_keymap_case 1000)"
   if [ "${nonroot_result}" = 'no-restart' ]; then
      ok "non-root: root guard holds, keyboard-setup.service NOT restarted"
   else
      notok "non-root: keyboard-setup.service restarted despite the guard (result='${nonroot_result}')"
   fi

   root_result="$(run_keymap_case 0)"
   if [ "${root_result}" = 'restart' ]; then
      ok "root: keyboard-setup.service IS restarted (the behavioral assertion has teeth)"
   else
      notok "root: keyboard-setup.service NOT restarted -- the test never reaches the real restart path (result='${root_result}')"
   fi
else
   notok "expected exactly one set_console_keymap definition, found '${def_count}'"
fi

## The resolved TODO must be gone (an addressed marker is deleted).
if grep --quiet --fixed-strings -- 'TODO: Do not try this if not running as root' "${lib}"; then
   notok "resolved TODO still present"
else
   ok "resolved TODO removed"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
