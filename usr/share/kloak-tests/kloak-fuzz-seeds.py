#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Materialize libFuzzer SEED corpora for the kloak fuzz harnesses into a target
directory (<out>/<harness-name>/<seed>), one subdir per harness binary.

The seeds exist because several harnesses are structurally gated and random
bytes essentially never satisfy the gate, so an unseeded run barely reaches the
real logic (see the audit): parse_inotify_events only acts on an inotify record
whose name matches ^event[0-9]+$, parse_esc_key_str / lookup_keycode only accept
table key names, and the kloakwl event machine needs a valid packet-type
selector byte followed by a correctly-sized payload. A single valid seed per
harness gives libFuzzer a foothold to mutate from.

Kept as a generator (not committed binary blobs) so every seed is reviewable as
code. The runner writes these into a THROWAWAY dir and passes it as libFuzzer's
writable corpus, so discovered inputs never pollute the source tree.

Binary layouts mirror what the REAL code parses:
  * inotify: struct inotify_event { int wd; uint32 mask; uint32 cookie;
    uint32 len; char name[len]; } in native byte order (what the kernel writes
    and parse_inotify_events walks).
  * kloakwl wire frames: [enum ptc_packet_type (int)] then either
    [uint32 code][uint8 pressed] (button/key) or [double x][double y] (cursor/
    scroll) -- matching send_msg_to_peer / the harnesses' own writers.
"""

import os
import struct
import sys

## PTC packet-type enum order in src/kloakwl.h (0-based). Only the selector the
## harness reads from the FIRST byte matters for reaching a branch; the payload
## sizes below are what process_parent_message then consumes.
PTC_CURSOR_REL = 0
PTC_CURSOR_ABS = 1
PTC_SCROLL = 2
PTC_CLICK = 3
PTC_KB = 4

IN_CREATE = 0x00000100


def _write(root, harness, name, data):
    sub = os.path.join(root, harness)
    os.makedirs(sub, exist_ok=True)
    path = os.path.join(sub, name)
    mode = 'wb' if isinstance(data, (bytes, bytearray)) else 'w'
    with open(path, mode) as handle:
        handle.write(data)


def _inotify_record(mask, node):
    ## wd=1; cookie=0; len = padded name field length; name NUL-padded to len.
    raw = node.encode('ascii') + b'\x00'
    length = (len(raw) + 7) & ~7          ## kernel 8-byte-aligns the name field
    name = raw.ljust(length, b'\x00')
    header = struct.pack('=iIII', 1, mask, 0, length)
    return header + name


def _input_sequence_seed():
    ## selector 0x04 -> KB; uint32 keycode + 1 pressed byte.
    seed = bytes([PTC_KB]) + struct.pack('<I', 30) + bytes([1])
    ## selector 0x00 -> relative motion; two int16 deltas.
    seed += bytes([PTC_CURSOR_REL]) + struct.pack('<hh', 5, 0)
    ## selector 0x02 -> scroll; two int16 (one vertical tick).
    seed += bytes([PTC_SCROLL]) + struct.pack('<hh', 0, 120)
    return seed


def _geometry_seed():
    ## first byte -> output count (harness does byte % MAX_SCREEN_COUNT + 1);
    ## then 4 uint32 (x, y, width, height) per output. Two adjacent 1920x1080.
    seed = bytes([2])
    seed += struct.pack('<IIII', 0, 0, 1920, 1080)
    seed += struct.pack('<IIII', 1920, 0, 1920, 1080)
    ## a trailing query point (two int32) the geometry harness reads if present.
    seed += struct.pack('<ii', 500, 500)
    return seed


def _geometry_many_seed():
    ## MAX_SCREEN_COUNT (128) contiguous 100x100 screens tiled along x, so
    ## recalc_global_space ACCEPTS the layout and its O(n^2) connectivity scan +
    ## the global-space transform run at the full count -- the high-screen-count
    ## path the default max_len truncates away. Values are the pre-image through
    ## the harness's bounded_coord (raw % 200001 - 100000) and bounded_extent
    ## (raw % 100001), giving x=i*100, y=0, width=height=100.
    count = 128
    ## harness: count = data[0] % MAX_SCREEN_COUNT + 1, so data[0] = count - 1.
    seed = bytes([count - 1])
    for i in range(count):
        seed += struct.pack('<IIII', i * 100 + 100000, 100000, 100, 100)
    seed += struct.pack('<ii', 150, 50)
    return seed


def main():
    if len(sys.argv) != 2:
        sys.stderr.write('usage: kloak-fuzz-seeds.py <out-dir>\n')
        return 1
    root = sys.argv[1]

    ## Text parsers.
    for name, text in (
            ('single', 'KEY_A'),
            ('default_combo', 'KEY_RIGHTSHIFT,KEY_ESC'),
            ('chord', 'KEY_LEFTCTRL|KEY_A')):
        _write(root, 'fuzz_parse_esc_key_str', name, text)
    for name, text in (
            ('dec', '2147483647'),
            ('hex', 'ff'),
            ('keyname', 'KEY_A'),
            ('max', '4294967295')):
        _write(root, 'fuzz_parse_args', name, text)
    for name, text in (('key', 'KEY_A'), ('esc', 'KEY_ESC')):
        _write(root, 'fuzz_lookup_keycode', name, text)
    _write(root, 'fuzz_parse_uint31', 'max', '2147483647')
    _write(root, 'fuzz_parse_uint31', 'zero', '0')
    _write(root, 'fuzz_parse_uint32', 'max', '4294967295')
    _write(root, 'fuzz_parse_uint32', 'zero', '0')

    ## Binary machines.
    _write(root, 'fuzz_parse_inotify_events', 'create_event12',
           _inotify_record(IN_CREATE, 'event12'))
    _write(root, 'fuzz_kloakwl_input_sequence', 'kb_move_scroll',
           _input_sequence_seed())
    ## selector 34: type %5==4 (KB), batch bit (>>5)&1 set -> two frames written
    ## back-to-back then popped one at a time (multi-frame-per-read reassembly).
    _write(root, 'fuzz_kloakwl_input_sequence', 'batched_kb',
           bytes([34]) + struct.pack('<I', 30) + bytes([1]))
    _write(root, 'fuzz_kloakwl_geometry', 'two_screens', _geometry_seed())
    _write(root, 'fuzz_kloakwl_geometry', 'many_screens', _geometry_many_seed())
    ## Parent-side CTP decode: selector 2 -> POINTER_SPACE_DATA (selector % 3),
    ## then two non-negative int32 coordinates (the harness masks them >= 0).
    _write(root, 'fuzz_kloak_child_msg', 'pointer_space',
           bytes([2]) + struct.pack('<ii', 1920, 1080))
    return 0


if __name__ == '__main__':
    sys.exit(main())
