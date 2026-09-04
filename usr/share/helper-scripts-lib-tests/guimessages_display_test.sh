#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## guimessages.display: the shared "is a GUI available" guard used by the PyQt
## helpers (generic_gui_message.py and the other msgcollector dialog entry
## points) to avoid Qt's SIGABRT-on-no-display (exit 134). One place to test the
## logic instead of duplicating it per GUI app.
##
## Asserts:
##  - gui_available() truth table matches msgcollector's msgfallbacks: true when
##    DISPLAY or WAYLAND_DISPLAY is set; and additionally when QT_QPA_PLATFORM is
##    set (deliberate headless render, e.g. 'offscreen' -- must NOT be
##    suppressed); false when none is set or all are empty.
##  - exit_if_no_gui() with no display exits 0 (default) after printing a stderr
##    diagnostic and BEFORE constructing anything -- so a 'yesno' caller reads no
##    affirmative answer and declines; with a display it returns (caller
##    proceeds); its exit_code argument is honoured.
##
## Pure os/sys logic: PyQt5 is NOT required. No root, no network, no display.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

## Checkout mode: put the repo's modules on PYTHONPATH. Installed mode uses the
## system module on the default path.
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   PYTHONPATH="${HELPER_SCRIPTS_REPO%/}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
   export PYTHONPATH
fi

if ! python3 -c 'import guimessages.display' >/dev/null 2>&1; then
   printf '%s\n' "FATAL: guimessages.display not importable" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install it" >&2
   exit 1
fi

work_dir="$(mktemp --directory)"
cleanup() {
   ## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

## gui_available() prints TRUE/FALSE and exits 0. Printing the result (rather
## than encoding it in the exit code) keeps a crash distinguishable: an uncaught
## exception exits non-zero with no TRUE/FALSE line, so a broken implementation
## cannot masquerade as a correct 'false' (which shares exit code 1).
avail_probe='from guimessages.display import gui_available; print("TRUE" if gui_available() else "FALSE")'

check_available() {
   local description want rc out
   description="$1"; want="$2"; shift 2
   rc=0
   out="$(env "$@" python3 -c "${avail_probe}" 2>/dev/null)" || rc=$?
   if [ "${rc}" -ne 0 ]; then
      fail "gui_available ${description}: probe crashed (rc=${rc}, out='${out}')"
   elif [ "${want}" = "true" ] && [ "${out}" = "TRUE" ]; then
      pass "gui_available ${description} -> true"
   elif [ "${want}" = "false" ] && [ "${out}" = "FALSE" ]; then
      pass "gui_available ${description} -> false"
   else
      fail "gui_available ${description}: want ${want}, got '${out}'"
   fi
}

check_available "DISPLAY set"          true  --unset=WAYLAND_DISPLAY --unset=QT_QPA_PLATFORM DISPLAY=:0
check_available "WAYLAND_DISPLAY set"  true  --unset=DISPLAY --unset=QT_QPA_PLATFORM WAYLAND_DISPLAY=wayland-0
check_available "QT_QPA_PLATFORM set"  true  --unset=DISPLAY --unset=WAYLAND_DISPLAY QT_QPA_PLATFORM=offscreen
check_available "none set"             false --unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=QT_QPA_PLATFORM
check_available "all empty"            false DISPLAY= WAYLAND_DISPLAY= QT_QPA_PLATFORM=

## exit_if_no_gui(): BEFORE prints, then the call either exits (no GUI) or
## returns (GUI) so AFTER prints. Default exit code is 0.
guard_probe='from guimessages.display import exit_if_no_gui; import sys; print("BEFORE"); exit_if_no_gui(); print("AFTER")'
guard_probe_code='from guimessages.display import exit_if_no_gui; import sys; print("BEFORE"); exit_if_no_gui(1); print("AFTER")'

## no GUI: exits 0, stdout has BEFORE but not AFTER, stderr carries a diagnostic.
out="${work_dir}/o"; err="${work_dir}/e"; rc=0
env --unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=QT_QPA_PLATFORM \
   python3 -c "${guard_probe}" >"${out}" 2>"${err}" || rc=$?
if [ "${rc}" -ne 0 ]; then
   fail "exit_if_no_gui no-GUI: expected exit 0, got ${rc}"
elif grep --quiet --fixed-strings -- 'AFTER' "${out}"; then
   fail "exit_if_no_gui no-GUI: returned instead of exiting (AFTER printed)"
elif ! grep --quiet --fixed-strings -- 'BEFORE' "${out}"; then
   fail "exit_if_no_gui no-GUI: BEFORE missing (exited too early / crashed)"
elif [ ! -s "${err}" ]; then
   fail "exit_if_no_gui no-GUI: expected a stderr diagnostic"
else
   pass "exit_if_no_gui no-GUI: exits 0, prints diagnostic, does not return"
fi

## with a display: returns, so AFTER prints and exit is 0.
rc=0
env --unset=WAYLAND_DISPLAY --unset=QT_QPA_PLATFORM DISPLAY=:0 \
   python3 -c "${guard_probe}" >"${out}" 2>"${err}" || rc=$?
if [ "${rc}" -eq 0 ] && grep --quiet --fixed-strings -- 'AFTER' "${out}"; then
   pass "exit_if_no_gui with-display: returns (AFTER printed), exit 0"
else
   fail "exit_if_no_gui with-display: expected return+exit 0, got rc=${rc} out=[$(cat -- "${out}")]"
fi

## QT_QPA_PLATFORM override alone must NOT be treated as no-GUI (offscreen render).
rc=0
env --unset=DISPLAY --unset=WAYLAND_DISPLAY QT_QPA_PLATFORM=offscreen \
   python3 -c "${guard_probe}" >"${out}" 2>"${err}" || rc=$?
if [ "${rc}" -eq 0 ] && grep --quiet --fixed-strings -- 'AFTER' "${out}"; then
   pass "exit_if_no_gui QT_QPA override: returns (not suppressed)"
else
   fail "exit_if_no_gui QT_QPA override: expected return, got rc=${rc} out=[$(cat -- "${out}")]"
fi

## exit_code argument honoured: no GUI with exit_if_no_gui(1) exits 1.
rc=0
env --unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=QT_QPA_PLATFORM \
   python3 -c "${guard_probe_code}" >"${out}" 2>"${err}" || rc=$?
if [ "${rc}" -eq 1 ]; then
   pass "exit_if_no_gui(1) no-GUI: honours exit_code (exit 1)"
else
   fail "exit_if_no_gui(1) no-GUI: expected exit 1, got ${rc}"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
