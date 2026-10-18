#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Print a free localhost TCP port (kernel-picked via bind to port 0), for the
## dm-upload-images-tests-e2e throwaway sshd. A standalone file (not an inline
## `python3 -c`) so the style gate / shellcheck / coverage still see it.

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
finally:
    s.close()
