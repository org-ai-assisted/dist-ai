#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: usability-misc ci/vbox-back-to-default-repo.sh must exit with the
## INSTALLER's own exit code when the installer fails for a reason OTHER than the
## expected Debian 108 (Oracle-repo-not-selected). A prior version ran
## `exit "$?"` where `$?` was the status of the `if` that had just tested the
## code, collapsing every distinct installer failure into a meaningless 1 - so
## the CI log no longer said WHICH failure occurred.
##
## Hermetic: `sudo` is stubbed on PATH to "fail" with a distinctive, non-108
## code; grep stays real (it reads /etc/os-release), apt-get is never reached.
## The else (propagation) branch is the one under test. No root, no network.
##
## Exit: 0 pass | 1 fail | 77 skip when the usability-misc checkout is absent.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

## Subject: the shipped step script in a usability-misc checkout. USABILITY_MISC_REPO
## (wired by dist-ai-tests-all), else a derivative-maker checkout under ${HOME}.
repo="${USABILITY_MISC_REPO:-}"
if [ -z "${repo}" ]; then
   repo="${HOME}/derivative-maker/packages/kicksecure/usability-misc"
fi
step_script="${repo}/ci/vbox-back-to-default-repo.sh"

if [ ! -x "${step_script}" ]; then
   printf '%s\n' "FATAL: ${step_script} not found; set USABILITY_MISC_REPO to a checkout." >&2
   exit 1
fi

stub_exit=42
work_dir="$( mktemp --directory -- "${TMP}/dist-installer-cli-tests.XXXXXX" )"
## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Stub the installer at its only external reach (sudo) so it "fails" with a
## distinctive code that is NOT 108, forcing the propagation (else) branch.
mkdir --parents -- "${work_dir}/bin"
printf '%s\n' '#!/bin/bash' "exit ${stub_exit}" > "${work_dir}/bin/sudo"
chmod +x -- "${work_dir}/bin/sudo"

exit_code=0
( cd -- "${repo}" && PATH="${work_dir}/bin:${PATH}" ./ci/vbox-back-to-default-repo.sh ) \
   || exit_code="$?"

if [ "${exit_code}" = "${stub_exit}" ]; then
   printf '%s\n' "PASS: step propagated the installer exit code (${exit_code})"
   exit 0
fi

printf '%s\n' \
   "FAIL: step exited ${exit_code}, expected the installer's ${stub_exit}" \
   "      a wrong code hides which installer failure occurred" >&2
exit 1
