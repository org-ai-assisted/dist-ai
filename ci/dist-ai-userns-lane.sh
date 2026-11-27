#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: allow-apt-get -- bare GHA runner; dist-ai's apt-get-noninteractive
## wrapper is not on PATH here, and these installs are already non-interactive.

## Dedicated bare-runner lane for userns-marked dist-ai tests. The hardened
## dist-ai test container runs the suite unprivileged (uid != 0) and the GHA
## host's apparmor_restrict_unprivileged_userns LSM blocks unprivileged user
## namespaces -- a host sysctl the container CANNOT clear (read-only from
## inside, even with CAP_SYS_ADMIN). This runs on the BARE ubuntu-24.04 runner,
## relaxes that sysctl, and runs only the userns-marked tests (pytest -m userns)
## for the calling component, unprivileged -- faithfully modelling the
## pam_namespace login session the invariant is about.
##
## Thin by design: the reusable workflow (developer-meta-files) only checks out
## dist-ai and calls this, so future lane changes land HERE, not in the workflow.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Relax the apparmor LSM so an unprivileged unshare works on this bare runner.
sudo sysctl --write kernel.apparmor_restrict_unprivileged_userns=0
## Prove it took AND an unprivileged unshare now works -- never a false green
## from a silently-ignored sysctl or a kernel that still refuses.
knob="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)"
if [ "${knob}" != "0" ]; then
  printf '%s\n' "FATAL: apparmor_restrict_unprivileged_userns is '${knob}', not 0." >&2
  exit 1
fi
unshare --map-root-user -- true

## The component under test is the calling repo; its dist-ai suites live in
## usr/share/<component>-tests next to this script's checkout (the standard
## dist-ai layout). Absent -> this component ships no dist-ai suite.
## Component = the calling repo. DIST_AI_USERNS_COMPONENT overrides it for local
## runs and the pre-merge probe: GITHUB_REPOSITORY is a reserved CI variable a
## 'env:' block cannot set, so without this hook the lane is untestable off-CI.
component="${DIST_AI_USERNS_COMPONENT:-}"
if [ -z "${component}" ]; then
  : "${GITHUB_REPOSITORY:?set DIST_AI_USERNS_COMPONENT, or run under CI}"
  component="${GITHUB_REPOSITORY##*/}"
fi
script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
tests_dir="${script_dir}/../usr/share/${component}-tests"
if [ ! -d "${tests_dir}" ]; then
  printf '%s\n' "no dist-ai test dir for '${component}'; userns lane is a no-op."
  exit 0
fi

## Collect ONLY the files that declare the userns marker. 'pytest -m userns'
## over the whole suite dir still IMPORTS every test module (collection runs
## before marker filtering), and a component's unrelated tests import helper
## libs the bare runner does not provide -> collection errors (exit 2) for a
## component that has no userns test at all. Selecting the marked files keeps a
## no-userns component a clean no-op.
mapfile -t userns_files < <(grep -rlF --include='*.py' 'pytest.mark.userns' -- "${tests_dir}" 2>/dev/null || true)
if [ "${#userns_files[@]}" -eq 0 ]; then
  printf '%s\n' "no userns-marked tests for '${component}'; userns lane is a no-op."
  exit 0
fi

sudo apt-get update --quiet
## safe-rm: dist-ai suites clean up with it (R-120); it ships as a Debian package,
## matching the container lane's apt_packages_base, not the host private-ai-config.
sudo apt-get install --yes --no-install-recommends python3-pytest util-linux safe-rm

## DIST_AI_USERNS_LANE=1: the userns tests FAIL (never skip) if userns is still
## unavailable -- this lane promised it, so a regressed sysctl step is loud.
## pytest rc 5 = nothing collected -> belt-and-suspenders no-op (the marked files
## were pre-selected above, so this only trips if a marker was stripped mid-file).
rc=0
DIST_AI_USERNS_LANE=1 python3 -m pytest -m userns --import-mode=importlib -q \
  "${userns_files[@]}" || rc="$?"
if [ "${rc}" = "5" ]; then
  printf '%s\n' "no userns-marked tests collected for '${component}'; userns lane is a no-op."
  exit 0
fi
exit "${rc}"
