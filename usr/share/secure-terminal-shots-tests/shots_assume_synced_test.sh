#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: `--assume-synced` skips the fresh tree sync and instead VERIFIES the sandbox
## already holds a matching checkout (`sandbox assert-synced`), so a repeat reshoot starts
## capturing at once. Without the flag the trees are freshly synced (the safe default).
## Drives the REAL driver with a stub `sandbox` that records the subcommands it is handed.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
driver="${script_dir}/../../bin/secure-terminal-shots-sandbox"
if [ ! -x "${driver}" ]; then
   printf '%s\n' "FATAL: secure-terminal-shots-sandbox not found at ${driver}" >&2
   exit 1
fi

st_repo="${SECURE_TERMINAL_REPO:-${HOME}/private-sources/secure-terminal}"
corpus="${CORPUS_REPO:-${HOME}/private-sources/terminal-poc-corpus}"
if [ ! -d "${st_repo}/usr/lib/python3/dist-packages/secure_terminal" ] || [ ! -d "${corpus}" ]; then
   ## Both real source trees are needed to get past the driver's tree checks and reach the
   ## sync block under test; without them the case cannot be verified, so FAIL loud rather
   ## than report a partial run as green (an unauthorized skip is a failure, not a pass).
   printf '%s\n' 'FATAL: secure-terminal / terminal-poc-corpus checkout absent; cannot verify --assume-synced' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}" 2>/dev/null || true
}
trap cleanup EXIT
mkdir --parents -- "${work}/site/comparison/shots" "${work}/bin"
log="${work}/sandbox.log"

## Stub `sandbox`: record the subcommand + args, succeed for everything. The driver's later
## steps (lane exec, pull, webp copy) are irrelevant here -- the sync/assert-synced calls are
## already logged by then, and the driver's eventual failure is swallowed below.
cat > "${work}/bin/sandbox" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> "${log}"
exit 0
STUB
chmod +x -- "${work}/bin/sandbox"

pass=0
fail=0

## Run the driver and assert the sandbox call log CONTAINS ${2} and does NOT contain ${3}.
check() {  ## $1=label $2=want $3=forbid [driver args...]
   local label want forbid
   label="$1"
   want="$2"
   forbid="$3"
   shift 3
   printf '' > "${log}"
   env PATH="${work}/bin:${PATH}" \
      SECURE_TERMINAL_REPO="${st_repo}" CORPUS_REPO="${corpus}" \
      SECURE_TERMINAL_SITE="${work}/site" \
      "${driver}" "$@" >/dev/null 2>&1 || true
   if grep --quiet --fixed-strings -- "${want}" "${log}" \
      && ! grep --quiet --fixed-strings -- "${forbid}" "${log}"; then
      printf '%s\n' "PASS: ${label}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${label} -- want '${want}', forbid '${forbid}'; log:" >&2
      sed 's/^/    /' "${log}" >&2
      fail=$(( fail + 1 ))
   fi
}

## --assume-synced: the trees are VERIFIED (assert-synced), never re-synced.
check '--assume-synced verifies instead of syncing' 'assert-synced' 'sync --delete' \
   comparison --assume-synced
## default: the trees are freshly synced, assert-synced is not used.
check 'default freshly syncs the trees' 'sync --delete' 'assert-synced' \
   comparison

## A stale/dirty tree under --assume-synced must REFUSE (die), not shoot it. Point the stub's
## assert-synced at failure for the secure-terminal tree.
cat > "${work}/bin/sandbox" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> "${log}"
case "\$*" in *assert-synced*secure-terminal*) exit 1 ;; esac
exit 0
STUB
chmod +x -- "${work}/bin/sandbox"
printf '' > "${log}"
rc=0
env PATH="${work}/bin:${PATH}" \
   SECURE_TERMINAL_REPO="${st_repo}" CORPUS_REPO="${corpus}" \
   SECURE_TERMINAL_SITE="${work}/site" \
   "${driver}" comparison --assume-synced >/dev/null 2>"${work}/err" || rc=$?
if [ "${rc}" -ne 0 ] \
   && grep --quiet --fixed-strings -- 'not verifiably in sync' "${work}/err"; then
   printf '%s\n' 'PASS: --assume-synced refuses a stale tree (dies, not a stale shoot)'
   pass=$(( pass + 1 ))
else
   printf '%s\n' "FAIL: --assume-synced should die on a stale tree (rc=${rc}); err:" >&2
   sed 's/^/    /' "${work}/err" >&2
   fail=$(( fail + 1 ))
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
printf '%s\n' 'OK: --assume-synced gates the tree sync on sandbox assert-synced'
