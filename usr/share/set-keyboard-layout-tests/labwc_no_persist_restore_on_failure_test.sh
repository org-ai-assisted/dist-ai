#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## set_labwc_keymap in the '--no-persist' path must NOT lose the user's existing
## config when the overwrite of the new config fails.
##
## The '--no-persist' path moves the original config to a temporary backup BEFORE
## overwriting the config in place. On unfixed code a failed overwrite returns
## early, skipping the later restore step -- so the original config is orphaned in
## a temp file and LOST from its real location.
##
## BEHAVIORAL test: source the shipped library (source-able via its was_executed
## guard), pre-populate a config file, stub 'overwrite' to FAIL, and drive the REAL
## set_labwc_keymap with do_persist=false:
##   the overwrite stub IS invoked -- proof the failure branch is actually reached.
##   the original config file still exists with its original content -- the failed
##      overwrite was rolled back, not left orphaned.
## On unfixed code the config file is gone (moved to the backup and never restored).
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

## Source the sourceable library: was_executed is false here, so main() does NOT
## auto-run -- only the function definitions load. HELPER_SCRIPTS_PATH points at the
## resolved checkout so the library's own sources resolve there.
export HELPER_SCRIPTS_PATH="${lib_repo}"
# shellcheck disable=SC1090
source "${lib}"

## Run set_labwc_keymap once with do_persist=false against a pre-populated config,
## with 'overwrite' stubbed to FAIL. Echoes the outcome the assertions read:
## whether overwrite was invoked, whether the config file survives, and its content.
original_content="# original labwc env
XKB_DEFAULT_LAYOUT=fr"

run_no_persist_overwrite_failure_case() {
   (
      stub_path_init
      ## Force the overwrite failure branch under test.
      stub_cmd overwrite 1

      cfg="${STUB_PATH_ROOT}/labwc-environment"
      printf '%s\n' "${original_content}" > "${cfg}"

      # shellcheck disable=SC2034  # consumed by the sourced set_labwc_keymap
      labwc_config_path="${cfg}"
      # shellcheck disable=SC2034  # consumed by the sourced set_labwc_keymap
      do_persist='false'
      # shellcheck disable=SC2034  # one layout so replace_file_variables has a var pair
      args=( 'us' )
      # shellcheck disable=SC2034  # consumed by the sourced set_labwc_keymap
      skl_xkb_env_var_names=( 'XKB_DEFAULT_LAYOUT' 'XKB_DEFAULT_VARIANT' 'XKB_DEFAULT_OPTIONS' )
      # shellcheck disable=SC2034  # consumed by the sourced set_labwc_keymap
      no_reload='true'
      # shellcheck disable=SC2034  # consumed by the sourced set_labwc_keymap
      do_live_changes='true'
      # shellcheck disable=SC2034  # consumed by the sourced set_labwc_keymap
      timeout_command=()

      set_labwc_keymap >/dev/null 2>&1 || true

      ## Match on the config path (a real recorded arg): a bare 'stub_called_with
      ## overwrite' with no args would build an empty-but-quoted needle and never
      ## match. The path is the first argument the writer is invoked with.
      if stub_called_with overwrite "${cfg}"; then
         printf '%s\n' "overwrite-called"
      else
         printf '%s\n' "overwrite-not-called"
      fi
      if [ -f "${cfg}" ]; then
         printf '%s\n' "config-present"
         cat -- "${cfg}"
      else
         printf '%s\n' "config-missing"
      fi
      stub_path_cleanup
   )
}

result="$(run_no_persist_overwrite_failure_case)"

## Sanity: the failure branch under test is actually reached.
if grep --quiet --fixed-strings -- 'overwrite-called' <<< "${result}"; then
   ok "overwrite failure branch reached (the assertion has teeth)"
else
   notok "overwrite was not invoked -- the test never reached the failure branch"
fi

## Teeth: the original config survives the failed overwrite.
if grep --quiet --fixed-strings -- 'config-present' <<< "${result}" \
   && grep --quiet --fixed-strings -- 'XKB_DEFAULT_LAYOUT=fr' <<< "${result}"; then
   ok "original config restored after failed overwrite (not lost)"
else
   notok "original config lost after failed overwrite (result below)"
   printf '%s\n' "${result}" >&2
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
