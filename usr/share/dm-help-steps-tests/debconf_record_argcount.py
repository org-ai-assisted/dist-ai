#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Count the arguments each 'printf ... | debconf-set-selections' line passes.
##
## A debconf record is 'package question type value' on ONE line, and
## 'printf %s\n' emits one line PER ARGUMENT -- so anything other than a single
## argument silently splits one record into several malformed fragments.
##
## Parsed with shlex rather than a shell word-split: the records contain literal
## TABs and quoting that a naive split mangles, which is how the defect was
## missed in review.
##
## Usage: debconf_record_argcount.py FILE
## Prints: line 1 = number of feeds examined
##         line 2 = space-separated '<line>:<argcount>' for every offending feed

import shlex
import sys


def main():
    if len(sys.argv) != 2:
        print('usage: debconf_record_argcount.py FILE', file=sys.stderr)
        return 2
    total = 0
    bad = []
    with open(sys.argv[1], encoding='utf-8') as handle:
        for number, line in enumerate(handle, 1):
            if 'debconf-set-selections' not in line or 'printf' not in line:
                continue
            total += 1
            try:
                arguments = shlex.split(line.split('|')[0].strip())[2:]
            except ValueError:
                ## Unbalanced quoting: report it rather than skipping, so a
                ## malformed line cannot pass as compliant.
                bad.append('%d:unparseable' % number)
                continue
            if len(arguments) != 1:
                bad.append('%d:%d' % (number, len(arguments)))
    print(total)
    print(' '.join(bad))
    return 0


if __name__ == '__main__':
    sys.exit(main())
