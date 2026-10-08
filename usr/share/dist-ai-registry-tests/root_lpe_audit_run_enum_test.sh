#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary for dm-root-lpe-audit's run_enum fail-closed contract. run_enum shells
## out to the sibling dm-root-scripts-enum and parses its JSON; a broken enum run
## (no output, non-JSON/undecodable bytes, or a non-object document) must STOP the
## audit cleanly, never look clean -- a silent-green on a security-inventory tool is
## the worst failure. A NONZERO enum exit is NOT a failure: the enum prints a
## complete report then exits nonzero as a "wrong root?" advisory, and the audit's
## own root-guarded scan must still run on it, so run_enum must RETURN that report
## (keying fail-close on the exit code drops real LPE findings). The enum is resolved
## as a sibling of the tool (no env override), so this drives run_enum as a targeted
## unit: the checker imports the REAL tool and calls run_enum with a tool_dir holding
## a STUB enum (a controlled INPUT, not a copy of the subject). No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v DIST_AI_REPO ] || DIST_AI_REPO=""

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dist-ai-tests-all" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -x "${repo}/usr/bin/dm-root-lpe-audit" ]; then
   printf '%s\n' 'FATAL: dist-ai-registry-tests: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

subject="${repo}/usr/bin/dm-root-lpe-audit"
checker="${script_dir}/root_lpe_audit_run_enum_check.py"

if [ ! -f "${checker}" ]; then
   printf '%s\n' "FATAL: missing assertion checker '${checker}'." >&2
   exit 1
fi

"${checker}" "${subject}"
