#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- deliberately NOT strict at top level: this probe
## sources SUBJECT (the real self-contained dist-installer-cli-standalone) and
## must observe its behaviour, so it must not let the subject's own strict-mode
## or a benign non-zero abort the probe. Driven by
## dry_run_skip_commands_wiring_test.sh, which asserts on this probe's effect.
##
## Env: STANDALONE (standalone path), HELPER_SCRIPTS_PATH (for the inlined
## log_run's stecho / sanitize-string), MODE ('flag' | 'logrun'), MARKER
## (logrun sentinel path). Args: the option words to pass to the real parse_opt.
##
## MODE=flag   -> print the resulting dry_run_skip_commands value (or UNSET).
## MODE=logrun -> run the installer's inlined log_run with a sentinel 'touch';
##                the caller checks whether MARKER was created.
##
## errexit stays OFF (never enabled): sourcing the standalone must not abort the
## probe on a benign non-zero, and the standalone's own strict preamble is inert
## when sourced (guarded by was_executed).

# shellcheck disable=SC1090,SC2154  # STANDALONE: injected by the wiring harness
source "${STANDALONE}" >/dev/null 2>&1

## set_default initialises the option globals (user_home_dir, directory_prefix,
## dry_run_skip_commands, ...); parse_opt then applies the given options through
## the REAL getopt parser.
set_default >/dev/null 2>&1

## parse_opt computes the download-dir default and runs its mkdir / per-run
## log-dir block (real sudo + filesystem writes). This probe exercises ONLY the
## --dry-run flag and log_run wiring, not directory creation, so neutralize that
## privileged boundary: no elevation, no stray dirs, no abort on a non-tty sudo.
run_as_target_user() { return 0; }
test_file() { return 0; }
copy_thru_barrier() { return 0; }

parse_opt "$@" >/dev/null 2>&1

# shellcheck disable=SC2154  # MODE: injected by the wiring harness
case "${MODE}" in
   flag)
      printf '%s' "${dry_run_skip_commands:-UNSET}"
      ;;
   logrun)
      log_run notice touch -- "${MARKER}" >/dev/null 2>&1
      ;;
   *)
      printf '%s\n' "probe: unknown MODE '${MODE}'" >&2
      exit 2
      ;;
esac
