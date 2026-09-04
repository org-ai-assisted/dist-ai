#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## generic_gui_message.py must not SIGABRT when there is no display.
##
## THE BUG: with neither DISPLAY nor WAYLAND_DISPLAY set, Qt's platform plugin
## cannot initialize and Qt calls abort() -- SIGABRT, exit 134. A caller that
## captures a yes/no answer under errexit (e.g. open-link-confirmation) then
## treats the crash as a script bug and tries to report it through the SAME
## crashing tool. The tool must instead detect the headless case, print nothing
## to stdout (so a 'yesno' caller reads no affirmative answer and declines) and
## exit cleanly.
##
## The guard must sit AFTER argparse (invalid arguments still rejected) and must
## honour an explicit QT_QPA_PLATFORM (the offscreen test harness still renders)
## -- both asserted below so the fix cannot regress in either direction.
##
## No root, no network, no display.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v MSGCOLLECTOR_REPO ] || MSGCOLLECTOR_REPO=""
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${MSGCOLLECTOR_REPO}" ]; then
   subject="${MSGCOLLECTOR_REPO}/usr/libexec/msgcollector/generic_gui_message.py"
else
   subject='/usr/libexec/msgcollector/generic_gui_message.py'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: generic_gui_message.py not found at '${subject}'" >&2
   printf '%s\n' "set MSGCOLLECTOR_REPO to a msgcollector checkout, or install the package" >&2
   exit 1
fi

## The no-display guard lives in helper-scripts' guimessages.display, which the
## script imports. In checkout mode put that repo's modules on PYTHONPATH; the
## installed package is on the default path.
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   PYTHONPATH="${HELPER_SCRIPTS_REPO%/}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
   export PYTHONPATH
fi

## The script imports PyQt5 and guimessages.display at module load, before the
## guard runs; without either there is nothing to exercise.
if ! python3 -c 'import PyQt5' >/dev/null 2>&1; then
   printf '%s\n' "FATAL: PyQt5 not importable (install python3-pyqt5)" >&2
   exit 1
fi
if ! python3 -c 'import guimessages.display' >/dev/null 2>&1; then
   printf '%s\n' "FATAL: guimessages.display not importable (set HELPER_SCRIPTS_REPO or install helper-scripts)" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

work_dir="$(mktemp --directory)"
cleanup() {
   ## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Run the subject headless (no display, no explicit platform) and capture
## exit code, stdout and stderr separately.
run_headless() {
   local out_file err_file rc
   out_file="${work_dir}/out"
   err_file="${work_dir}/err"
   rc=0
   env --unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=QT_QPA_PLATFORM \
      python3 "${subject}" "$@" </dev/null >"${out_file}" 2>"${err_file}" || rc=$?
   printf '%s' "${rc}"
}

## A 'yesno' dialog with no display: must exit 0, print nothing (no fabricated
## "16384"), and say why on stderr. On the pre-fix tool this run exits 134.
rc="$(run_headless warning "Title" "<p>msg</p>" "" yesno)"
if [ "${rc}" -ge 128 ]; then
   fail "headless yesno: killed by signal (exit ${rc}) -- this is the SIGABRT bug"
elif [ "${rc}" -ne 0 ]; then
   fail "headless yesno: expected clean exit 0, got ${rc}"
elif [ -s "${work_dir}/out" ]; then
   fail "headless yesno: stdout must be empty (fabricated answer): [$(cat -- "${work_dir}/out")]"
elif [ ! -s "${work_dir}/err" ]; then
   fail "headless yesno: expected a diagnostic on stderr"
else
   pass "headless yesno: clean exit 0, empty stdout, stderr diagnostic"
fi

## An 'ok' dialog with no display: same clean exit, never a signal.
rc="$(run_headless error "Title" "<p>msg</p>" "" ok)"
if [ "${rc}" -ge 128 ]; then
   fail "headless ok: killed by signal (exit ${rc}) -- this is the SIGABRT bug"
elif [ "${rc}" -ne 0 ]; then
   fail "headless ok: expected clean exit 0, got ${rc}"
else
   pass "headless ok: clean exit 0"
fi

## The guard must not swallow argument validation: invalid message_type headless
## must still be rejected (argparse exits 2), proving the guard sits after
## parse_args() rather than short-circuiting every headless invocation.
rc="$(run_headless invalid_type "Title" "msg" "" ok)"
if [ "${rc}" -eq 0 ]; then
   fail "headless invalid type: accepted (guard placed before argparse)"
else
   pass "headless invalid type: still rejected (exit ${rc})"
fi

## An explicit platform override must NOT be short-circuited: with
## QT_QPA_PLATFORM=offscreen the dialog renders headless, so the guard must let
## it proceed. 'ok' shows briefly then needs a click; drive it under a short
## timeout and accept only a real GUI-loop outcome, never the guard's exit 0
## with a "no GUI available" diagnostic.
off_err="${work_dir}/off_err"
off_rc=0
timeout --kill-after=6 6 env --unset=DISPLAY --unset=WAYLAND_DISPLAY QT_QPA_PLATFORM=offscreen \
   python3 "${subject}" info "Title" "<p>msg</p>" "" ok </dev/null \
   >/dev/null 2>"${off_err}" || off_rc=$?
if grep --quiet --fixed-strings -- 'no GUI available' "${off_err}"; then
   fail "offscreen: guard short-circuited an explicit QT_QPA_PLATFORM override"
elif [ "${off_rc}" -eq 124 ] || [ "${off_rc}" -eq 0 ]; then
   pass "offscreen: dialog runs (guard honours QT_QPA_PLATFORM, exit ${off_rc})"
else
   fail "offscreen: unexpected exit ${off_rc} (stderr: $(head -1 -- "${off_err}"))"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
