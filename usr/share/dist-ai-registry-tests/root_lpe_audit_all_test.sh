#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary for dm-root-lpe-audit-all: the multi-tree wrapper around dm-root-lpe-audit.
## It must aggregate per-tree JSON into one verdict with a correct exit contract --
## 0 clean, 1 an open candidate, 2 a scan error (missing tree / no JSON / degraded),
## scan error OUTRANKING a finding -- so a broken scan is never read as clean. The
## checker drives the REAL wrapper with its auditor overridden (DM_ROOT_LPE_AUDIT)
## to a STUB emitting canned per-tree JSON (a controlled INPUT, not a copy of the
## subject), plus a real-auditor smoke. No root, no network.

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

if [ -z "${repo}" ] || [ ! -x "${repo}/usr/bin/dm-root-lpe-audit-all" ]; then
  printf '%s\n' 'FATAL: dist-ai-registry-tests: no dist-ai source tree (set DIST_AI_REPO).' >&2
  exit 1
fi

subject="${repo}/usr/bin/dm-root-lpe-audit-all"
checker="${script_dir}/root_lpe_audit_all_check.py"

if [ ! -f "${checker}" ]; then
  printf '%s\n' "FATAL: missing assertion checker '${checker}'." >&2
  exit 1
fi

"${checker}" "${subject}"
