#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Shell-coverage lane: runs the core lane under kcov and gates the tools that
## the corpus is supposed to exercise against a per-tool floor.
##
## WHY a per-tool allow-list rather than one repo-wide percentage: the corpus
## targets four argument parsers out of ~50 shipped tools, so a repo-wide number
## is dominated by untested tools and would ratchet on noise. The gated list
## names exactly what the tests claim to cover, and each floor is a measured
## value -- raise them as coverage improves, never lower them to make a red run
## green.
##
## MEASUREMENT CAVEATS, all of which silently UNDERCOUNT (see the kcov probe):
##   - python harnesses that exec a shell tool lose it: subprocess.run defaults
##     to close_fds=True, which shuts kcov's trace fd, so the child's xtrace is
##     orphaned. The python tests in the core lane therefore contribute no
##     shell coverage. They are still run (for their own assertions), just not
##     counted.
##   - a script that sets its own PS4 or 'set +x' clobbers kcov's tracer and
##     loses coverage from that point.
##   - kcov runs a '#!/bin/sh' script under bash, so coverage of a dash script
##     is NOT evidence it works under dash.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## Gated tools: 'basename:minimum-percent'. Measured floors, set below the
## observed value only by the rounding margin.
## Measured 2026-07-31 in the sandbox against the core lane (deterministic
## across repeat runs):
##   container-guard 78.26 / sandbox-run 43.68 / qube-ctl 22.78 / sandbox-view 20.19
## Floors sit just under those so normal churn does not flap the gate.
gated=(
   'sandbox-run:40'
   'qube-ctl:20'
   'container-guard:75'
   'sandbox-view:18'
)

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${PRIVATE_AI_CONFIG_PATH:-}"
if [ -z "${repo}" ] || [ ! -d "${repo}/tests" ]; then
   printf 'private-ai-config-tests-coverage: PRIVATE_AI_CONFIG_PATH unset or has no tests/ dir; skipping.\n' >&2
   exit 77
fi

## Sourced after the checkout guard above, so a missing PRIVATE_AI_CONFIG_PATH
## still SKIPs rather than dying here.
# shellcheck source=./has.sh
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.sh

## A missing DEPENDENCY is a hard FAIL, not a SKIP. Only an absent SUBJECT (the
## checkout guarded above) earns 77. kcov and jq are this lane's tooling: if they
## are gone the lane measured nothing, and reporting that as SKIP would let a
## coverage gate silently stop gating -- the exact failure mode this suite set
## exists to close.
missing_deps=()
for dep in kcov jq; do
   has "${dep}" || missing_deps+=( "${dep}" )
done
if [ "${#missing_deps[@]}" -gt 0 ]; then
   printf 'FAIL: private-ai-config-tests-coverage: missing dependency: %s\n' "${missing_deps[*]}" >&2
   printf 'Hint: add it to .github/dm-consumer.yml dist-ai-tests.apt-packages.\n' >&2
   exit 1
fi

[ -v TMP ] || TMP=/tmp
outdir="$(mktemp --directory -- "${TMP}/private-ai-config-coverage.XXXXXX")"

# shellcheck disable=SC2317  # invoked indirectly via 'trap ... EXIT'
cleanup() {
   if [ -n "${outdir}" ]; then
      safe-rm --recursive --force -- "${outdir}"
   fi
   return 0
}
trap cleanup EXIT

## kcov must be handed a shell SCRIPT, never a binary: its ELF engine needs
## ptrace, which is denied under kernel.yama.ptrace_scope >= 2 (the Qubes
## sandbox runs at 3). The bash engine works because it drives BASH_ENV + PS4
## instead.
rc=0
kcov --include-path="${repo}/usr/bin,${repo}/usr/libexec" \
   "${outdir}" "${script_dir}/run-tests.sh" --lane core || rc=$?

## A failing core lane is a test failure, not a coverage failure; report it as
## such rather than reading coverage off a run that did not complete.
if [ "${rc}" -eq 77 ]; then
   printf 'private-ai-config-tests-coverage: core lane skipped; nothing to measure.\n' >&2
   exit 77
fi
if [ "${rc}" -ne 0 ]; then
   printf 'private-ai-config-tests-coverage: core lane FAILED (%s); coverage not evaluated.\n' "${rc}" >&2
   exit "${rc}"
fi

report="$(find "${outdir}" -name 'coverage.json' -print -quit)"
if [ -z "${report}" ] || [ ! -f "${report}" ]; then
   printf 'private-ai-config-tests-coverage: kcov produced no coverage.json -- the tracer did not attach.\n' >&2
   exit 1
fi

printf '\n===== shell coverage (gated tools) =====\n'

failures=0
for spec in "${gated[@]}"; do
   tool="${spec%%:*}"
   floor="${spec##*:}"
   line="$(jq --raw-output --arg tool "${tool}" \
      '.files[] | select((.file | split("/") | last) == $tool)
       | "\(.percent_covered) \(.covered_lines) \(.total_lines)"' \
      -- "${report}")"
   if [ -z "${line}" ]; then
      ## The same drift guard secure-terminal-tests-coverage uses: a gated name
      ## matching no measured file leaves the gate inert, which would otherwise
      ## pass silently.
      printf 'FAIL: gated tool %s names no measured file -- renamed or removed; update the gate\n' "${tool}" >&2
      failures=$(( failures + 1 ))
      continue
   fi
   read -r percent covered total <<< "${line}"
   ## Integer compare: kcov reports one decimal place, and a floor is a floor.
   whole="${percent%%.*}"
   if [ "${whole}" -lt "${floor}" ]; then
      printf 'FAIL: %-18s %6s%% (%s/%s) below floor %s%%\n' \
         "${tool}" "${percent}" "${covered}" "${total}" "${floor}" >&2
      failures=$(( failures + 1 ))
   else
      printf 'ok:   %-18s %6s%% (%s/%s) floor %s%%\n' \
         "${tool}" "${percent}" "${covered}" "${total}" "${floor}"
   fi
done

printf '\n===== shell coverage (ungated, report only) =====\n'
jq --raw-output \
   '.files[] | "\(.percent_covered)\t\(.covered_lines)/\(.total_lines)\t\(.file | split("/") | last)"' \
   -- "${report}" | sort --numeric-sort --reverse | head -40

printf '\n===== overall: %s%% =====\n' "$(jq --raw-output '.percent_covered' -- "${report}")"

if [ "${failures}" -ne 0 ]; then
   printf '\nFAILED: %s gated tool(s) below floor\n' "${failures}" >&2
   exit 1
fi
printf '\nOK: every gated tool meets its coverage floor\n'
exit 0
