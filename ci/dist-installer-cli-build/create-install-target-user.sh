#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CI setup: create a SECOND unprivileged account 'user2' (no sudo) with its own
## home, so dist-installer-cli can be driven with '--user=user2' from the primary
## 'user' invoker -- exercising "install the guest under a DIFFERENT account".
## That is the environment that regressed: the download dir defaulted to the
## invoker's home (not writable by the target) instead of the target's own home.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if test -f /etc/debian_version; then
   adduser --comment "" --disabled-password user2
elif test -f /etc/fedora-release; then
   adduser user2
else
   exit 1
fi
