#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## open-link-confirmation's ERR-trap error_handler must survive its own dialog
## failing.
##
## THE BUG: error_handler reports a caught error by calling
## generic_gui_message.py. The conditions that reach the handler -- a headless
## or display-unreachable caller, a transiently crashing GUI tool -- are exactly
## the ones under which that report ALSO fails. With the script under errexit +
## errtrace, an unguarded failure there re-enters the ERR trap and aborts the
## handler mid-way, so the process exits with the raw crash status (a SIGABRT
## 134 plus core dumps) instead of the handler's defined 'exit 1'. The fix makes
## the dialog call failure-tolerant ('|| true'), mirroring the sanitize-string
## call just above it.
##
## Drives the REAL error_handler() extracted from the shipped script, with its
## absolute helper paths redirected to stubs, so the exact shipped logic runs
## without root or a display. The generic_gui_message.py stub SIGABRTs (exit
## 134) like the real tool does headless; the test asserts the handler still
## finishes at 'exit 1' rather than propagating 134.
##
## No root, no network, no display.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

resolve_script() {
   if [ -n "${OPEN_LINK_CONFIRMATION_BIN:-}" ]; then
      printf '%s\n' "${OPEN_LINK_CONFIRMATION_BIN}"
      return 0
   fi
   local installed
   installed='/usr/libexec/open-link-confirmation/open-link-confirmation'
   if [ -f "${installed}" ]; then
      printf '%s\n' "${installed}"
      return 0
   fi
   printf '%s\n' "${HOME}/derivative-maker/packages/kicksecure/open-link-confirmation/usr/libexec/open-link-confirmation/open-link-confirmation"
}

script_path="$(resolve_script)"
if [ ! -f "${script_path}" ]; then
   printf '%s\n' "FATAL: open-link-confirmation not found at '${script_path}'; set OPEN_LINK_CONFIRMATION_BIN" >&2
   exit 1
fi

work_dir="$(mktemp --directory)"
cleanup() {
   # shellcheck disable=SC2317
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Extract error_handler() (definition line to the first bare closing brace).
handler_file="${work_dir}/handler.bash"
sed -n '/^error_handler()/,/^}/p' -- "${script_path}" > "${handler_file}"
if [ ! -s "${handler_file}" ]; then
   printf '%s\n' "FAIL: could not extract error_handler() from ${script_path}" >&2
   exit 1
fi
if ! bash -n "${handler_file}" 2>/dev/null; then
   printf '%s\n' "FAIL: extracted error_handler() does not parse (incomplete extraction)" >&2
   exit 1
fi

## Stub the helpers the handler shells out to by absolute path, and redirect
## those absolute paths in the extracted function to the stubs.
stub_dir="${work_dir}/msgcollector"
mkdir --parents -- "${stub_dir}"

## generic_gui_message.py: reproduce the real headless failure -- SIGABRT (134).
## Touch a marker first, so the assertion can prove the handler actually REACHED
## the dialog call: a crash BEFORE it (e.g. an unbound variable under nounset)
## would also exit 1 and otherwise read as a false pass.
printf '%s\n' '#!/bin/bash' "touch -- '${work_dir}/dialog_reached'" 'kill -ABRT $$' \
   > "${stub_dir}/generic_gui_message.py"
## br_add.py: reflect argv[1], like the real one (which reflows <br>). It must
## NOT read stdin -- a bare 'cat' blocks the driver forever whenever stdin is not
## already at EOF (an interactive run, or the suite runner, which does not
## redirect it).
printf '%s\n' '#!/bin/bash' 'printf "%s" "$1"' > "${stub_dir}/br_add.py"
chmod 0755 -- "${stub_dir}/generic_gui_message.py" "${stub_dir}/br_add.py"

handler_stubbed="${work_dir}/handler_stubbed.bash"
sed -e "s#/usr/libexec/msgcollector/generic_gui_message.py#${stub_dir}/generic_gui_message.py#g" \
    -e "s#/usr/libexec/msgcollector/br_add.py#${stub_dir}/br_add.py#g" \
    -- "${handler_file}" > "${handler_stubbed}"

## sanitize-string is called as a bare command (already '|| true' guarded in the
## handler); stub it on PATH so the test does not depend on helper-scripts.
printf '%s\n' '#!/bin/bash' 'printf "%s" "sanitized"' > "${work_dir}/sanitize-string"
chmod 0755 -- "${work_dir}/sanitize-string"

## Drive the handler exactly as the script does: registered as the ERR trap
## under errexit + errtrace, then triggered by a failing command. The stubbed
## dialog SIGABRTs inside the handler; the fix ('|| true') must let the handler
## reach its own 'exit 1'.
driver="${work_dir}/driver"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
      'set -o errtrace' 'shopt -s inherit_errexit'
   printf '%s\n' "export PATH=\"${work_dir}:\${PATH}\""
   printf '%s\n' "source \"${handler_stubbed}\""
   printf '%s\n' 'trap error_handler ERR'
   ## Trigger the trap with a genuine command failure.
   printf '%s\n' 'false'
} > "${driver}"

rc=0
bash "${driver}" >/dev/null 2>&1 </dev/null || rc=$?

pass_count=0
fail_count=0
if [ "${rc}" -ge 128 ]; then
   fail_count=1
   printf '%s\n' "FAIL: handler propagated a signal exit (${rc}); the dialog failure re-entered the trap and aborted it -- this is the bug" >&2
elif [ ! -e "${work_dir}/dialog_reached" ]; then
   ## rc==1 alone is ambiguous (a crash before the dialog also exits 1); require
   ## proof the handler reached and tolerated the (SIGABRTing) dialog call.
   fail_count=1
   printf '%s\n' "FAIL: handler exited ${rc} without reaching the dialog call; it did not exercise the tolerance under test" >&2
elif [ "${rc}" -ne 1 ]; then
   fail_count=1
   printf '%s\n' "FAIL: handler exited ${rc}; expected its defined 'exit 1' after tolerating the dialog failure" >&2
else
   pass_count=1
   printf '%s\n' "PASS: handler tolerates a SIGABRTing dialog and still exits 1"
fi

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
