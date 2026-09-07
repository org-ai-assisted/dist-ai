#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Safety-critical wiring: dist-installer-cli is an INSTALLER, and its '--dry-run'
## mode must guarantee that no mutating command runs. It relies on the shared
## log_run/root_cmd contract: those skip a command iff the global
## 'dry_run_skip_commands' equals "1". This test proves the installer's OWN code
## honors that end to end -- the '--dry-run' option sets the flag, and the
## installer's inlined log_run then SKIPS a command.
##
## Drives the shipped self-contained 'dist-installer-cli-standalone' (which
## inlines the real parse_opt and log_run): the standalone guards its auto-run
## with 'was_executed', so sourcing it defines the functions without launching
## the installer. Each case runs in a child bash and uses a sentinel 'touch' as
## the command; marker present => it ran, absent => it was skipped. No root, no
## network.
##
## Exit: 0 pass | 1 fail. A missing subject or helper-scripts is FATAL (exit 1),
## never a silent skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

repo="${USABILITY_MISC_REPO:-}"
if [ -z "${repo}" ]; then
   repo="${HOME}/derivative-maker/packages/kicksecure/usability-misc"
fi
standalone="${repo}/usr/share/usability-misc/dist-installer-cli-standalone"

if [ ! -r "${standalone}" ]; then
   printf '%s\n' "FATAL: standalone not readable at '${standalone}'" >&2
   printf '%s\n' "set USABILITY_MISC_REPO to a checkout." >&2
   exit 1
fi

## The standalone is self-contained EXCEPT for the stecho / sanitize-string
## binaries its inlined log_run requires. Resolve them via HELPER_SCRIPTS_PATH
## (wired by dist-ai-tests-all), else a sibling helper-scripts checkout, else the
## installed /usr copy.
helper_scripts_path="${HELPER_SCRIPTS_PATH:-}"
if [ -z "${helper_scripts_path}" ] && [ -x "${repo}/../helper-scripts/usr/bin/stecho" ]; then
   helper_scripts_path="${repo}/../helper-scripts"
fi
stecho_bin="${helper_scripts_path:-}/usr/bin/stecho"
if [ ! -x "${stecho_bin}" ]; then
   stecho_bin='/usr/bin/stecho'
   helper_scripts_path=''
fi
if [ ! -x "${stecho_bin}" ]; then
   printf '%s\n' "FATAL: stecho not found; the standalone's inlined log_run needs it." >&2
   printf '%s\n' "set HELPER_SCRIPTS_PATH to a helper-scripts checkout, or install helper-scripts." >&2
   exit 1
fi

tests_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
probe="${tests_dir}/dry_run_skip_commands_wiring_probe.sh"
if [ ! -r "${probe}" ]; then
   printf '%s\n' "FATAL: probe helper not found at '${probe}'" >&2
   exit 1
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

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

## Run the probe in 'flag' mode: it sources the standalone (sourced =>
## was_executed false => installer not run), parses the given options with the
## REAL parse_opt, and prints the resulting dry_run_skip_commands value.
flag_after_parse() {
   env HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      STANDALONE="${standalone}" \
      MODE=flag \
      /usr/bin/bash -- "${probe}" "$@"
}

## Run the probe in 'logrun' mode: after parsing the given options it runs the
## installer's inlined log_run with a sentinel command. Prints "ran" / "skipped".
log_run_after_parse() {
   local marker
   marker="${work_dir}/marker.$$.${RANDOM}"
   safe-rm --force -- "${marker}"
   env HELPER_SCRIPTS_PATH="${helper_scripts_path}" \
      STANDALONE="${standalone}" \
      MODE=logrun \
      MARKER="${marker}" \
      /usr/bin/bash -- "${probe}" "$@" >/dev/null 2>&1 || true
   if [ -e "${marker}" ]; then
      printf '%s\n' "ran"
   else
      printf '%s\n' "skipped"
   fi
}

## --- parse_opt sets the shared flag ---

if [ "$(flag_after_parse --dry-run)" = "1" ]; then
   ok "parse_opt --dry-run sets dry_run_skip_commands=1"
else
   notok "parse_opt --dry-run did NOT set dry_run_skip_commands=1"
fi

if [ "$(flag_after_parse -d)" = "1" ]; then
   ok "parse_opt -d sets dry_run_skip_commands=1"
else
   notok "parse_opt -d did NOT set dry_run_skip_commands=1"
fi

if [ "$(flag_after_parse --non-interactive)" != "1" ]; then
   ok "parse_opt without --dry-run leaves dry_run_skip_commands unset"
else
   notok "parse_opt without --dry-run wrongly set dry_run_skip_commands=1"
fi

## --- the safety consequence: installer's own log_run skips in dry-run ---

if [ "$(log_run_after_parse --dry-run)" = "skipped" ]; then
   ok "installer log_run SKIPS the command after --dry-run (no mutation in dry-run)"
else
   notok "installer log_run RAN the command in dry-run mode -- SAFETY REGRESSION"
fi

if [ "$(log_run_after_parse --non-interactive)" = "ran" ]; then
   ok "installer log_run runs the command when not in dry-run"
else
   notok "installer log_run was skipped outside dry-run mode"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} passed, ${fail_count} failed"
[ "${fail_count}" -eq 0 ]
