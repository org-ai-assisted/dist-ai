#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI helper for reusable-dist-ai-tests.yml: read the caller repo's per-repo
## dist-ai test config from .github/dm-consumer.yml and emit the resolved
## values to $GITHUB_OUTPUT for later workflow steps. All control-flow logic
## lives here, not embedded in the workflow yaml (no embedded shell scripts in
## CI files). Requires the apt 'yq' (kislyuk python-yq) already installed.
##
## Usage: dist-ai-tests-ci-config.sh <path-to-dm-consumer.yml>
##
## Emits to $GITHUB_OUTPUT:
##   apt_packages    packages to apt-install for the suites: dist-ai's own
##                   baseline, plus whatever the caller repo adds
##   allow_skip_args '--allow-skip <name>' arguments for suites authorized to skip
##   helper_scripts  'true' if a helper-scripts checkout is also needed
##   hs_arg          the matching '--helper-scripts-root <dir>' argument for
##                   dist-ai-tests-all, or empty
##   terminal_poc_corpus  'true' if a terminal-poc-corpus checkout is also needed
##                   (the adversarial PoC corpus lives in its own repo, so a suite
##                   that drives it cannot resolve one in CI otherwise, and would
##                   exit 77 -> reported SKIP -> counted green)

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

cfg="${1:-}"
if [ -z "${cfg}" ]; then
   printf '%s\n' 'dist-ai-tests-ci-config: missing dm-consumer.yml path argument' >&2
   exit 2
fi

## Packages dist-ai's OWN runner and suites need, whatever the component is.
## The caller repo's apt-packages list ADDS to this baseline, it cannot subtract
## from it: a consumer that forgot one got a suite failing on a dependency it
## never declared (git-meld-tests probes 'safe-rm' to drive the review tools, and
## dist-ai-tests-all's own EXIT-trap cleanup calls it), reported as a code
## failure in the component under test. A requirement every consumer repo has to
## remember to mirror is a requirement that eventually goes unmet, so dist-ai
## declares its own here, in the one place that cannot be forgotten per repo.
apt_packages_base='python3 python3-pytest python3-hypothesis safe-rm'
apt_packages="${apt_packages_base}"
helper_scripts='false'
terminal_poc_corpus='false'
skip_args=''
allow_skip_args=''

if [ -f "${cfg}" ]; then
   value="$(yq -r '.["dist-ai-tests"]["apt-packages"] // ""' "${cfg}")"
   if [ -n "${value}" ] && [ "${value}" != 'null' ]; then
      ## Union, de-duplicated: consumer lists normally restate the baseline
      ## names, and a doubled package list is pure noise in the CI log.
      apt_packages=''
      # shellcheck disable=SC2086
      ## Both are intentional word lists, so the split is the point.
      for package in ${apt_packages_base} ${value}; do
         case " ${apt_packages} " in
            *" ${package} "*)
               continue
               ;;
         esac
         apt_packages="${apt_packages}${apt_packages:+ }${package}"
      done
   fi
   if [ "$(yq -r '.["dist-ai-tests"]["helper-scripts"] // ""' "${cfg}")" = 'true' ]; then
      helper_scripts='true'
   fi
   ## Opt-in rather than unconditional: cloning the corpus for every consumer
   ## costs a checkout none of them need, and only a component with a suite that
   ## drives it can use one.
   if [ "$(yq -r '.["dist-ai-tests"]["terminal-poc-corpus"] // ""' "${cfg}")" = 'true' ]; then
      terminal_poc_corpus='true'
   fi
   ## Optional list of suite entrypoints to skip (a suite temporarily broken /
   ## pending a merge). Each becomes a '--skip <name>' argument.
   while IFS= read -r skip_name; do
      [ -n "${skip_name}" ] || continue
      case "${skip_name}" in
         *[![:alnum:]-]*)
            printf '%s\n' "dist-ai-tests-ci-config: invalid skip suite name: ${skip_name}" >&2
            exit 1
            ;;
      esac
      skip_args="${skip_args} --skip ${skip_name}"
   done < <(yq -r '.["dist-ai-tests"].skip[]? // empty' "${cfg}")
   ## Optional list of suites AUTHORIZED to exit 77 without failing the run. An
   ## unauthorized skip is a failure (dist-ai-tests-all skip_is_fatal): a suite that
   ## could not resolve its target must not report the same green exit 0 as one that
   ## ran. Authorize only where a human decided the suite may legitimately be absent
   ## for this repo -- never to turn a red run green.
   while IFS= read -r allow_name; do
      [ -n "${allow_name}" ] || continue
      case "${allow_name}" in
         *[![:alnum:]-]*)
            printf '%s\n' "dist-ai-tests-ci-config: invalid allow-skip suite name: ${allow_name}" >&2
            exit 1
            ;;
      esac
      allow_skip_args="${allow_skip_args} --allow-skip ${allow_name}"
   done < <(yq -r '.["dist-ai-tests"]["allow-skip"][]? // empty' "${cfg}")
fi

## Reject newline injection into $GITHUB_OUTPUT.
case "${apt_packages}" in
   *$'\n'*|*$'\r'*)
      printf '%s\n' 'dist-ai-tests-ci-config: dist-ai-tests.apt-packages contains a newline' >&2
      exit 1
      ;;
esac

{
   printf 'apt_packages=%s\n' "${apt_packages}"
   printf 'helper_scripts=%s\n' "${helper_scripts}"
   printf 'terminal_poc_corpus=%s\n' "${terminal_poc_corpus}"
   printf 'skip_args=%s\n' "${skip_args# }"
   printf 'allow_skip_args=%s\n' "${allow_skip_args# }"
   if [ "${helper_scripts}" = 'true' ]; then
      printf 'hs_arg=--helper-scripts-root %s/helper-scripts\n' "${GITHUB_WORKSPACE}"
   else
      printf 'hs_arg=\n'
   fi
} >> "${GITHUB_OUTPUT}"
