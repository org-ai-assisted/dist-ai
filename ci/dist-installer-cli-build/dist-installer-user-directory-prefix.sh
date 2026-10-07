#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression (real environment): a non-sysmaint invoker ('user') installing the
## guest under a DIFFERENT account ('--user=user2') with NO '--directory-prefix'
## must resolve the download dir to the TARGET's home, which the target can
## write. The download and import run AS the target (sudo -u user2), so a prefix
## under the invoker's /home/user is not writable by user2 and the installer
## aborted with "mkdir: cannot create directory '/home/user/...'".
##
## '--getopt' prints the parsed options and exits 0 right AFTER parse_opt's real
## directory-creation block (sudo -u user2 -- mkdir ...), so this exercises the
## genuine cross-user permission boundary with no download/import, across every
## distro image in the matrix.
##
## Canary: on the OLD code directory_prefix is the invoker's /home/user, so the
## real 'sudo -u user2 -- mkdir /home/user/...' is permission-denied, the
## installer dies, and this step is RED (resolved value wrong AND target dir
## absent).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## The reusable build workflow checks the consumer out under 'component/' and
## sets DIST_INSTALLER_CLI_STANDALONE to its standalone path; the default keeps
## a direct in-repo run (from the usability-misc checkout root) working.
standalone="${DIST_INSTALLER_CLI_STANDALONE:-usr/share/usability-misc/dist-installer-cli-standalone}"
want="/home/user2/dist-installer-cli-download"

rc=0
getopt_out="$(timeout --kill-after=10 120 sudo -u user -- \
   "${standalone}" --user=user2 --getopt --ci 2>&1)" || rc="$?"

got="$(printf '%s\n' "${getopt_out}" \
   | grep --max-count=1 -- '^directory_prefix=' | cut -d= -f2- || true)"

if [ "${got}" != "${want}" ]; then
   printf '%s\n' \
      "FAIL: '--user=user2' (no --directory-prefix) resolved directory_prefix='${got}', expected '${want}' (installer rc=${rc})" \
      "      pre-fix this defaults to the invoker's /home/user, which the target cannot write" >&2
   printf '%s\n' "----- installer output (tail) -----" >&2
   printf '%s\n' "${getopt_out}" | tail -n 15 >&2
   exit 1
fi

## The installer must also have SUCCEEDED: --getopt exits 0 right after the
## directory-creation block, so a nonzero code means it errored before/at that
## point even though the expected prefix was already printed.
if [ "${rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: installer exited ${rc} (expected 0 from --getopt)" >&2
   printf '%s\n' "----- installer output (tail) -----" >&2
   printf '%s\n' "${getopt_out}" | tail -n 15 >&2
   exit 1
fi

## The real 'sudo -u user2 -- mkdir' must have created the dir in the target home
## AND it must be WRITABLE by user2 -- the whole point of staging under the target
## home. A root:root 0755 dir would exist yet be unusable by the download, which
## runs as user2, so check writability, not mere existence.
if ! sudo -u user2 -- test -d "${want}"; then
   printf '%s\n' "FAIL: the target-home download dir was not created: '${want}'" >&2
   exit 1
fi
if ! sudo -u user2 -- test -w "${want}"; then
   printf '%s\n' "FAIL: the target-home download dir '${want}' is not writable by user2" >&2
   exit 1
fi

printf '%s\n' "PASS: '--user=user2' without --directory-prefix uses the target's home '${want}'"
