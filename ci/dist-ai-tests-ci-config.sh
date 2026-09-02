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
##   submodules      'true' if the component's submodules must be checked out
##                   (the adversarial PoC corpus lives in its own repo, so a suite
##                   that drives it cannot resolve one in CI otherwise, and would
##                   exit 77 -> reported SKIP -> counted green)
##
## It also PERFORMS that checkout when the component asks for it and the
## consuming workflow did not. The reusable workflow gained its own init step,
## but consumers pin the reusable at '@master' by org policy (same-org refs are
## branch-pinned, not SHA-pinned), so a component cannot benefit from it until
## that lands on master. dist-ai is checked out FRESH at job runtime, so doing it
## here takes effect immediately, for every consumer, with no branch name written
## down anywhere. Idempotent: a workflow that already initialized them makes this
## a no-op.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

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
submodules='false'
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
   ## Opt-in submodule checkout for the component. Some suites assert on files
   ## that live in a SUBMODULE (derivative-maker's dm-grub-smbios-tests compares
   ## the disk-side SMBIOS reader in vm-config-dist against the ISO-side copy in
   ## the main tree). Without them the suite cannot resolve its subject and exits
   ## 77, which -- correctly -- fails the run as an unauthorized skip. Checking
   ## them out is what makes the test actually RUN; it is not free, so it stays
   ## per-repo rather than unconditional.
   ## 'true' (direct submodules), not 'recursive': the suites need the component's
   ## own submodules, and recursive multiplies the checkout for no added coverage.
   if [ "$(yq -r '.["dist-ai-tests"].submodules // ""' "${cfg}")" = 'true' ]; then
      submodules='true'
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

## Do the checkout the flag asks for, rather than only reporting that it is
## wanted. A suite whose subject lives in a submodule exits 77 without it, which
## dist-ai-tests-all counts as an unauthorized skip -- correctly a failure, and
## one no consumer can fix from its own repo.
if [ "${submodules}" = 'true' ]; then
   component_dir="$( cd -- "$( dirname -- "${cfg}" )/.." && pwd )"
   if [ -e "${component_dir}/.gitmodules" ]; then
      ## A component may pin submodule commits that exist only in this org's
      ## forks while .gitmodules still points upstream, so a plain init cannot
      ## find them. Run the component's own mapping helper when it ships one,
      ## exactly as its build lane does.
      if [ -x "${component_dir}/ci/configure-fork-mirror" ]; then
         ( cd -- "${component_dir}" \
           && ./ci/configure-fork-mirror "${GITHUB_REPOSITORY_OWNER:-org-ai-assisted}" "${GITHUB_REPOSITORY_OWNER:-org-ai-assisted}" ) \
            || printf '%s\n' 'dist-ai-tests-ci-config: fork-mirror mapping failed; submodule init may not resolve' >&2
      fi
      ## NOT --recursive: the suites assert on the component's OWN submodules,
      ## and recursing multiplies the checkout for no coverage.
      if ( cd -- "${component_dir}" && git submodule update --init --quiet ); then
         printf '%s\n' "dist-ai-tests-ci-config: initialized ${component_dir} submodules" >&2
      else
         ## Not fatal here: the suite that needs one will exit 77 and be counted
         ## as an unauthorized skip, which is the correct loud failure. Silently
         ## swallowing this would turn that into a green run.
         printf '%s\n' 'dist-ai-tests-ci-config: submodule init FAILED; suites needing one will report an unauthorized skip' >&2
      fi
   fi
fi

{
   printf '%s\n' "apt_packages=${apt_packages}"
   printf '%s\n' "helper_scripts=${helper_scripts}"
   printf '%s\n' "terminal_poc_corpus=${terminal_poc_corpus}"
   printf '%s\n' "submodules=${submodules}"
   printf '%s\n' "skip_args=${skip_args# }"
   printf '%s\n' "allow_skip_args=${allow_skip_args# }"
   if [ "${helper_scripts}" = 'true' ]; then
      printf '%s\n' "hs_arg=--helper-scripts-root ${GITHUB_WORKSPACE}/helper-scripts"
   else
      printf '%s\n' "hs_arg="
   fi
} >> "${GITHUB_OUTPUT}"
