#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Check that every '... | debconf-set-selections' feed emits exactly ONE line.
##
## A debconf record is 'package question type value' on ONE line. A feed that
## emits more than one line silently splits one record into several malformed
## fragments, and debconf discards them without a word.
##
## BOTH producer forms are examined, because a checker that knows only one
## reports "nothing to check" on a file written in the other -- which is
## indistinguishable from "all clear" unless the caller demands a non-zero count:
##   printf FORMAT ARG...   -- '%s\n' emits one line PER ARGUMENT, so anything
##                             other than a single argument is a split record.
##   echo ARG...            -- joins its arguments with spaces and emits ONE
##                             line, so it is safe by construction UNLESS '-e'
##                             turns a literal '\n' in the value into a newline.
##
## Parsed with shlex rather than a shell word-split: the records contain literal
## TABs and quoting that a naive split mangles, which is how the defect was
## missed in review.
##
## Usage: debconf_record_argcount.py FILE
## Prints: line 1 = number of feeds examined
##         line 2 = space-separated '<line>:<reason>' for every offending feed

import shlex
import sys


def inspect_feed(words):
    """Return None when the feed emits exactly one line, else a reason string."""
    if not words:
        return 'empty'
    command = words[0]
    if command == 'printf':
        ## words[1] is the format; every remaining word becomes its own line
        ## under the '%s\n' format these records use.
        arguments = words[2:]
        if len(arguments) != 1:
            return str(len(arguments))
        return None
    if command == 'echo':
        ## echo parses options only BEFORE the first non-option word; everything
        ## after is literal text to print. Scanning every '-'-prefixed word would
        ## flag 'echo pkg question type -example' as escape-enabled, which prints
        ## '-example' verbatim and splits nothing.
        for word in words[1:]:
            if not word.startswith('-') or word == '-':
                break
            if set(word[1:]) <= set('neE') and 'e' in word[1:]:
                return 'echo-e'
            if not set(word[1:]) <= set('neE'):
                ## Not an option after all; echo prints it and stops parsing.
                break
        ## Without '-e' a backslash-n stays literal, so it cannot split the
        ## record. A REAL newline inside the quoted value still can.
        if any('\n' in value for value in words[1:]):
            return 'embedded-newline'
        return None
    return 'unrecognised-producer:' + command


def main():
    if len(sys.argv) != 2:
        print('usage: debconf_record_argcount.py FILE', file=sys.stderr)
        return 2
    total = 0
    bad = []
    with open(sys.argv[1], encoding='utf-8') as handle:
        for number, line in enumerate(handle, 1):
            if 'debconf-set-selections' not in line:
                continue
            if line.lstrip().startswith('#'):
                continue
            ## Split on the pipe as a TOKEN, not as a character: a quoted '|'
            ## inside a record value ("a | b") is data, and splitting the raw
            ## string on it truncates the producer so shlex then chokes on the
            ## unbalanced quote -- reported as unparseable, which is a false
            ## alarm rather than the defect this looks for.
            try:
                tokens = shlex.split(line, posix=True, comments=False)
            except ValueError:
                ## Unbalanced quoting: report it rather than skipping, so a
                ## malformed line cannot pass as compliant.
                bad.append('%d:unparseable' % number)
                total += 1
                continue
            if '|' not in tokens:
                continue
            words = tokens[:tokens.index('|')]
            if not words:
                continue
            total += 1
            reason = inspect_feed(words)
            if reason is not None:
                bad.append('%d:%s' % (number, reason))
    print(total)
    print(' '.join(bad))
    return 0


if __name__ == '__main__':
    sys.exit(main())
