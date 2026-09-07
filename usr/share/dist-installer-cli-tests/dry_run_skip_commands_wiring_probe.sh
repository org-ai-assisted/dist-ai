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

# shellcheck disable=SC1090
source "${STANDALONE}" >/dev/null 2>&1

## reset_variables initialises the option globals; parse_opt then applies the
## given options through the REAL getopt parser.
reset_variables >/dev/null 2>&1
parse_opt "$@" >/dev/null 2>&1

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
