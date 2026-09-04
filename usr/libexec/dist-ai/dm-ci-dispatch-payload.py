#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Build the JSON body for a workflow_dispatch call.
##
## A real program rather than string concatenation in the caller: an input value
## carrying a quote or a backslash would otherwise produce malformed JSON, and
## the API then rejects the REQUEST with a message that never names the value.
##
## Usage: dm-ci-dispatch-payload.py REF OUTPUT_FILE [key=value]...

import json
import sys


def main():
    if len(sys.argv) < 3:
        print('usage: dm-ci-dispatch-payload.py REF OUTPUT_FILE [key=value]...',
              file=sys.stderr)
        return 2
    ref = sys.argv[1]
    out = sys.argv[2]
    inputs = {}
    for item in sys.argv[3:]:
        key, separator, value = item.partition('=')
        if not separator or not key:
            print("dm-ci-dispatch-payload.py: not a key=value pair: '%s'" % item,
                  file=sys.stderr)
            return 2
        inputs[key] = value
    payload: dict[str, object] = {'ref': ref}
    if inputs:
        payload['inputs'] = inputs
    with open(out, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle)
    return 0


if __name__ == '__main__':
    sys.exit(main())
