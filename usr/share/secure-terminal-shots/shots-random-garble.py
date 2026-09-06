#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## DETERMINISTIC pseudo-random garble field for the random.payload shot
## (shots_random_seed / _bytes). A live /dev/random churned the shot every run;
## a fixed-seed generator gives byte-identical output so regeneration is a no-op
## when nothing changed. Drawn from python3's seeded Mersenne-Twister (stable
## across versions/platforms); 2x bytes are drawn and ESC (0x1b) filtered out so
## a stray escape sequence in the garble can never hijack the terminal
## (alt-screen / clear / OSC title), then sliced to the exact size. Not a corpus
## detection payload (no canary token) -- an inline page-facing demo like notify
## / zerowidth. argv[1]=byte count, argv[2]=seed; writes raw bytes to stdout.
import random,sys
n=int(sys.argv[1]); r=random.Random(int(sys.argv[2]))
buf=bytes(x for x in (r.getrandbits(8) for _ in range(n*2)) if x!=0x1b)[:n]
sys.stdout.buffer.write(buf)
