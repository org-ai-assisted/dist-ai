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
##
## Source-able: the guard at the foot runs main only when executed, so the unit
## test can source this for discover_userns_test_files without the privileged
## body. The strict-mode block stays file-level (it is re-set, harmlessly, in the
## test's own strict shell).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Discover the test files that carry a userns-marked test, one file at a time so
## pytest resolves the marker itself (alias-safe -- a grep for 'pytest.mark.userns'
## misses an aliased `um = pytest.mark.userns; @um`) AND each file's imports stay
## isolated: a component's unrelated test importing a helper lib absent on the bare
## runner errors only its own probe, not the whole lane (running 'pytest -m userns'
## over the whole dir would import every module at collection time and exit 2). A
## userns test imports only stdlib+pytest, so a real one is never hidden here.
discover_userns_test_files() {
  local tests_dir="$1" test_file collected rc
  local -a found=()
  while IFS= read -r -d '' test_file; do
    rc=0
    collected="$(DIST_AI_USERNS_LANE=1 python3 -m pytest -m userns --collect-only -q \
      --import-mode=importlib "${test_file}" 2>/dev/null)" || rc="$?"
    case "${collected}" in
      *'::'*)
        ## A collected node id '<file>::<test>' -- an importable file that carries
        ## a userns test (pytest resolved the marker, alias and all).
        found+=( "${test_file}" )
        ;;
      *)
        ## No userns node. pytest rc 5 = a clean "no userns test here" -> omit. But
        ## a collection ERROR (import raised) tells us nothing about the marker, so
        ## we must NOT treat it as "no userns test": a file that TEXTUALLY carries
        ## the marker yet could not be collected is a BROKEN userns test -- include
        ## it so the real run fails LOUD, never a silent passing no-op (the inverse
        ## false-green of the alias case). Residual: a marker reached only via
        ## getattr / an imported alias in a file that ALSO fails to import is not
        ## textually detectable and stays omitted.
        if [ "${rc}" -ne 0 ] && [ "${rc}" -ne 5 ] \
          && grep --quiet --fixed-strings 'mark.userns' -- "${test_file}"; then
          found+=( "${test_file}" )
        fi
        ;;
    esac
  done < <(find "${tests_dir}" -type f -name '*.py' -print0 | sort --zero-terminated)
  (( ${#found[@]} )) || return 0
  printf '%s\n' "${found[@]}"
}

main() {
  ## Relax the apparmor LSM so an unprivileged unshare works on this bare runner.
  sudo sysctl --write kernel.apparmor_restrict_unprivileged_userns=0
  ## Prove it took AND an unprivileged unshare now works -- never a false green
  ## from a silently-ignored sysctl or a kernel that still refuses.
  local knob
  knob="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)"
  if [ "${knob}" != "0" ]; then
    printf '%s\n' "FATAL: apparmor_restrict_unprivileged_userns is '${knob}', not 0." >&2
    return 1
  fi
  unshare --map-root-user -- true

  ## The component under test is the calling repo; its dist-ai suites live in
  ## usr/share/<component>-tests next to this script's checkout (the standard
  ## dist-ai layout). Absent -> this component ships no dist-ai suite.
  ## Component = the calling repo. DIST_AI_USERNS_COMPONENT overrides it for local
  ## runs and the pre-merge probe: GITHUB_REPOSITORY is a reserved CI variable a
  ## 'env:' block cannot set, so without this hook the lane is untestable off-CI.
  local component
  component="${DIST_AI_USERNS_COMPONENT:-}"
  if [ -z "${component}" ]; then
    : "${GITHUB_REPOSITORY:?set DIST_AI_USERNS_COMPONENT, or run under CI}"
    component="${GITHUB_REPOSITORY##*/}"
  fi
  local script_dir tests_dir
  script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
  tests_dir="${script_dir}/../usr/share/${component}-tests"
  if [ ! -d "${tests_dir}" ]; then
    printf '%s\n' "no dist-ai test dir for '${component}'; userns lane is a no-op."
    return 0
  fi

  sudo apt-get update --quiet
  ## safe-rm: dist-ai suites clean up with it (R-120); it ships as a Debian package,
  ## matching the container lane's apt_packages_base, not the host private-ai-config.
  sudo apt-get install --yes --no-install-recommends python3-pytest util-linux safe-rm

  local -a userns_files
  mapfile -t userns_files < <(discover_userns_test_files "${tests_dir}")
  if [ "${#userns_files[@]}" -eq 0 ]; then
    printf '%s\n' "no userns-marked tests for '${component}'; userns lane is a no-op."
    return 0
  fi

  ## DIST_AI_USERNS_LANE=1: the userns tests FAIL (never skip) if userns is still
  ## unavailable -- this lane promised it, so a regressed sysctl step is loud.
  local rc=0
  DIST_AI_USERNS_LANE=1 python3 -m pytest -m userns --import-mode=importlib -q \
    "${userns_files[@]}" || rc="$?"
  return "${rc}"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  main "$@"
fi
