#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reusable command-stub / mock-PATH harness for dist-ai bash tests. A test that
## must assert "did the shipped script invoke external command X, with args Y?"
## sources this, registers recording stubs for the externals, prepends them to
## PATH, runs the subject, then queries the recording -- instead of parsing the
## script's source text. Records argv only; stub genuinely-external commands (a
## root/network action, a sink that records, or to force a branch of the REAL
## function), never a real dependency you could simply require.
##
## Pure sourced-only fragment: functions only, no strict-mode preamble and no
## was_executed guard -- the consuming test owns strict-mode and the EXIT trap.
## style-ok: no-strict -- sourced-only fragment

## Create a fresh stub tree and prepend it to PATH. Sets STUB_PATH_ROOT,
## STUB_PATH_BIN (the dir on PATH) and STUB_PATH_REC (per-command records), and
## exports STUB_PATH_REC + PATH so a stub sees them at runtime. Returns nonzero if
## the tree cannot be made. Pair with stub_path_cleanup from the caller's EXIT trap.
stub_path_init() {
   STUB_PATH_ROOT="$(mktemp --directory)" || return 1
   STUB_PATH_BIN="${STUB_PATH_ROOT}/bin"
   STUB_PATH_REC="${STUB_PATH_ROOT}/rec"
   mkdir --parents -- "${STUB_PATH_BIN}" "${STUB_PATH_REC}" || return 1
   export STUB_PATH_REC

   ## One recording body serves every stubbed command: invoked through a
   ## per-command symlink, it derives its name from "$0", appends its argv to that
   ## command's record, emits the command's fixed stdout (if any), and exits the
   ## command's fixed code. Off PATH; kept literal so no write-time value leaks in.
   cat > "${STUB_PATH_ROOT}/recording-stub" <<'STUB'
#!/bin/bash
stub_self="$(basename -- "${0}")"
printf '%s\n' "${*}" >> "${STUB_PATH_REC}/${stub_self}.argv"
if [ -f "${STUB_PATH_REC}/${stub_self}.out" ]; then
   cat -- "${STUB_PATH_REC}/${stub_self}.out"
fi
exit "$(cat -- "${STUB_PATH_REC}/${stub_self}.rc")"
STUB
   chmod 0755 -- "${STUB_PATH_ROOT}/recording-stub"

   PATH="${STUB_PATH_BIN}:${PATH}"
   export PATH
}

## Register (or re-point) a recording stub named $1 on the stub PATH: exit code $2
## (default 0), optional fixed stdout line $3. Re-registering changes behaviour for
## the next case. Each call's argv is recorded to "$1.argv" under STUB_PATH_REC.
stub_cmd() {
   local name exit_code stdout_line
   name="$1"
   exit_code="${2:-0}"
   stdout_line="${3:-}"
   printf '%s\n' "${exit_code}" > "${STUB_PATH_REC}/${name}.rc"
   if [ -n "${stdout_line}" ]; then
      printf '%s\n' "${stdout_line}" > "${STUB_PATH_REC}/${name}.out"
   else
      safe-rm --force -- "${STUB_PATH_REC}/${name}.out"
   fi
   ln --symbolic --force -- "${STUB_PATH_ROOT}/recording-stub" "${STUB_PATH_BIN}/${name}"
}

## True if stub $1 recorded any invocation whose argv (space-joined) contains the
## fixed string $2.
stub_called_with() {
   local rec="${STUB_PATH_REC}/$1.argv"
   [ -f "${rec}" ] || return 1
   grep --quiet --fixed-strings -- "$2" "${rec}"
}

## True if stub $1 recorded NO invocation containing the fixed string $2 (also true
## when the stub was never called at all).
stub_not_called_with() {
   ! stub_called_with "$1" "$2"
}

## Remove the stub tree. Safe from an EXIT trap: a failed cleanup ('|| true')
## never overrides the caller's real pass/fail exit status.
stub_path_cleanup() {
   [ -n "${STUB_PATH_ROOT:-}" ] || return 0
   safe-rm --recursive --force -- "${STUB_PATH_ROOT}" || true
}
