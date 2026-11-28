#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary for dm-root-lpe-audit's target RESOLUTION (build_index + resolve_targets).
## A BARE root command resolves via PATH, so among several shippers of one basename
## the PATH-dir shipper wins -- otherwise a real '/usr/bin/foo' is dropped as
## "ambiguous" because a bash-completion file or an off-PATH libexec helper shares
## the name, silently cutting a root-reachable script from the audited surface (a
## false negative). The checker imports the REAL tool and drives resolution over a
## synthetic tree (a controlled INPUT, not a copy of the subject). No root, no network.

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
checker="${script_dir}/root_lpe_audit_resolve_check.py"

if [ ! -f "${checker}" ]; then
  printf '%s\n' "FATAL: missing assertion checker '${checker}'." >&2
  exit 1
fi

"${checker}" "${subject}"
