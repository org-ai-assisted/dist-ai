#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Deterministic tqdm progress bar emitted to STDOUT (so a byte-capture and the terminal both see
## it). NO time/rate fields in the format (byte-stable), forced to refresh every iteration
## (mininterval=0, miniters=1) so an append-only render stacks a fixed 20 frames; ncols pins the
## width independent of the terminal. Single source of the terminal-safe-corpus
## demos/progress-tqdm-safe-to-cat.txt bytes (see that repo's check-drift).
import sys

from tqdm import tqdm

for _ in tqdm(range(20), file=sys.stdout, ncols=56, mininterval=0, miniters=1,
              bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt}',
              desc='Indexing'):
    pass
