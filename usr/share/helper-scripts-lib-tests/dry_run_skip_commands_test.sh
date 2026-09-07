#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## log_run (log_run_die.sh) and root_cmd (root_cmd.sh) share ONE dry-run
## contract: when the global 'dry_run_skip_commands' equals "1" the command is
## logged as "Skipping command (dry-run)" and NOT executed. This is the renamed
## successor of the old shared 'dry_run' variable; the old name must no longer
## have any effect (it collided with unrelated per-script dry_run flags -- the
## footgun the rename removes).
##
## Sources the REAL libraries and drives log_run / root_cmd with a sentinel
## command (touch a marker file). Marker present => the command ran; marker
## absent => it was skipped. root_cmd is exercised with sucmd=sudo and a stub
## 'sudo' recorder on PATH, so no real privilege escalation happens. Each case
## runs in a child bash for isolation. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
repo="${HELPER_SCRIPTS_REPO}"

log_run_die_sh="${repo:-}/usr/libexec/helper-scripts/log_run_die.sh"
[ -r "${log_run_die_sh}" ] || repo=""
log_run_die_sh="${repo:-}/usr/libexec/helper-scripts/log_run_die.sh"
[ -r "${log_run_die_sh}" ] || log_run_die_sh='/usr/libexec/helper-scripts/log_run_die.sh'

if [ ! -r "${log_run_die_sh}" ]; then
   printf '%s\n' "FATAL: log_run_die.sh not readable at '${log_run_die_sh}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a checkout, or install helper-scripts" >&2
   exit 1
fi

## HELPER_SCRIPTS_PATH lets the libraries resolve their siblings
## (get_colors.sh, strings.bsh, ...) and the stecho / sanitize-string binaries.
helper_scripts_path="${HELPER_SCRIPTS_PATH:-${repo}}"
if [ ! -x "${helper_scripts_path}/usr/bin/stecho" ]; then
   printf '%s\n' "FATAL: stecho not executable under '${helper_scripts_path}/usr/bin'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH / HELPER_SCRIPTS_REPO to a built checkout" >&2
   exit 1
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Stub 'sudo': record every invocation, then run the command after the first
## '--' so the sentinel still fires when NOT skipped. No real escalation.
stub_bin_dir="${work_dir}/bin"
mkdir --parents -- "${stub_bin_dir}"
cat > "${stub_bin_dir}/sudo" <<'STUB'
#!/bin/bash
printf '%s\n' "sudo-invoked" >> "${SUDO_STUB_RECORD}"
saw_sep=0
argv=()
for arg in "$@"; do
   if [ "${saw_sep}" = 0 ] && [ "${arg}" = "--" ]; then
      saw_sep=1
      continue
   fi
   [ "${saw_sep}" = 1 ] && argv+=( "${arg}" )
done
[ "${#argv[@]}" -gt 0 ] && exec "${argv[@]}"
STUB
chmod +x -- "${stub_bin_dir}/sudo"

pass_count=0
fail_count=0
ok() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "  ok: $1"
}
notok() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "  NOT OK: $1" >&2
}

## Source log_run_die.sh in a child bash with the given leading VAR=VALUE
## assignments in the environment, then run 'log_run notice touch -- MARKER'.
## Prints "ran" if MARKER now exists, "skipped" otherwise.
log_run_touch() {
   local marker
   marker="${work_dir}/marker.$$.${RANDOM}"
   safe-rm --force -- "${marker}"
   env "$@" \
      HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      MARKER="${marker}" \
      /usr/bin/bash -c '
         source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/log_run_die.sh"
         log_run notice touch -- "${MARKER}"
      ' >/dev/null 2>&1 || true
   if [ -e "${marker}" ]; then
      printf '%s\n' "ran"
   else
      printf '%s\n' "skipped"
   fi
}

## As above but drives root_cmd with sucmd=sudo and the stub sudo on PATH.
root_cmd_touch() {
   local marker record
   marker="${work_dir}/marker.$$.${RANDOM}"
   record="${work_dir}/record.$$.${RANDOM}"
   safe-rm --force -- "${marker}" "${record}"
   env "$@" \
      HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      PATH="${stub_bin_dir}:${PATH}" \
      MARKER="${marker}" \
      SUDO_STUB_RECORD="${record}" \
      sucmd=sudo ROOT_CMD_TARGET_USER='' ROOT_CMD_TARGET_DIR='' \
      /usr/bin/bash -c '
         source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/root_cmd.sh"
         root_cmd touch -- "${MARKER}"
      ' >/dev/null 2>&1 || true
   if [ -e "${marker}" ]; then
      printf '%s\n' "ran"
   else
      printf '%s\n' "skipped"
   fi
}

## --- log_run ---

if [ "$(log_run_touch dry_run_skip_commands=1)" = "skipped" ]; then
   ok "log_run: dry_run_skip_commands=1 skips the command"
else
   notok "log_run: dry_run_skip_commands=1 did NOT skip"
fi

if [ "$(log_run_touch)" = "ran" ]; then
   ok "log_run: no flag runs the command"
else
   notok "log_run: command was skipped with no dry-run flag set"
fi

if [ "$(log_run_touch dry_run_skip_commands=0)" = "ran" ]; then
   ok "log_run: dry_run_skip_commands=0 runs the command"
else
   notok "log_run: dry_run_skip_commands=0 wrongly skipped"
fi

## De-collision: the OLD shared name must be inert. Fails on pre-rename code
## (which reads 'dry_run' and would skip).
if [ "$(log_run_touch dry_run=1)" = "ran" ]; then
   ok "log_run: legacy dry_run=1 is inert (old shared name no longer skips)"
else
   notok "log_run: legacy dry_run=1 still skipped -- the shared variable was not renamed"
fi

## Inline override forces execution even under an ambient skip (the
## dist-installer-cli 'dry_run_skip_commands=0 log_run/root_cmd ...' pattern).
inline_marker="${work_dir}/marker.inline.${RANDOM}"
env dry_run_skip_commands=1 HELPER_SCRIPTS_PATH="${helper_scripts_path}" MARKER="${inline_marker}" \
   /usr/bin/bash -c '
      source "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/log_run_die.sh"
      dry_run_skip_commands=0 log_run notice touch -- "${MARKER}"
   ' >/dev/null 2>&1 || true
if [ -e "${inline_marker}" ]; then
   ok "log_run: inline dry_run_skip_commands=0 overrides an ambient skip"
else
   notok "log_run: inline dry_run_skip_commands=0 did not force execution"
fi

## --- root_cmd (inherits the skip via log_run) ---

if [ "$(root_cmd_touch dry_run_skip_commands=1)" = "skipped" ]; then
   ok "root_cmd: dry_run_skip_commands=1 skips the privileged command"
else
   notok "root_cmd: dry_run_skip_commands=1 did NOT skip"
fi

if [ "$(root_cmd_touch)" = "ran" ]; then
   ok "root_cmd: no flag runs the privileged command"
else
   notok "root_cmd: command was skipped with no dry-run flag set"
fi

if [ "$(root_cmd_touch dry_run=1)" = "ran" ]; then
   ok "root_cmd: legacy dry_run=1 is inert (old shared name no longer skips)"
else
   notok "root_cmd: legacy dry_run=1 still skipped -- the shared variable was not renamed"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
