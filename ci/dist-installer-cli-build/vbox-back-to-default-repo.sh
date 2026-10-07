#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI step: install VirtualBox from the DEFAULT (non-Oracle) repository. On
## Debian-family that aborts with exit code 108 (Oracle repo not selected) -
## expected; drop the packages and retry. Any OTHER failure is real, so
## propagate the installer's OWN exit code - not the status of the `if` that
## just tested it, which would collapse every distinct failure into a
## meaningless 1 and hide which installer failure occurred.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## The reusable build workflow checks the consumer out under 'component/' and
## sets DIST_INSTALLER_CLI_STANDALONE to its standalone path; the default keeps a
## direct in-repo run (from the usability-misc checkout root) working.
standalone="${DIST_INSTALLER_CLI_STANDALONE:-usr/share/usability-misc/dist-installer-cli-standalone}"

run_installer() {
   sudo -u user -- "${standalone}" \
      --non-interactive --log-level=debug --no-boot --dev --ci --virtualbox-only
}

ec=0
run_installer || ec="$?"
if [ "${ec}" != '0' ]; then
   if grep --ignore-case --regexp "debian" --regexp "buntu" --regexp "mint" /etc/os-release >/dev/null 2>&1 && [ "${ec}" = "108" ]; then
      printf '%s\n' "Expected error as --oracle-repo is not specified"
      apt-get remove -y 'virtualbox*'
      run_installer
   else
      exit "${ec}"
   fi
fi
