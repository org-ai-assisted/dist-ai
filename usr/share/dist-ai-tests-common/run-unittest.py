#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Discover and run a unittest suite, mapping the outcome to dist-ai's canonical
result codes so an all-skipped or nothing-collected run cannot read as a green
PASS. A bare `python3 -m unittest discover` exits 0 when every test is skipped
at import (missing PyQt5, an absent subject module), hiding that nothing ran.

Codes (match dist-ai-tests-common/suite-exit.bash):
  0  pass -- at least one test ran and none failed
  1  a test failed or errored (an import error is an error, never a skip)
  77 SKIP:target-absent -- no tests were collected (the suite is empty/unwired)
  78 SKIP:env-unmet -- tests WERE collected but EVERY one skipped (a runtime
     capability the suite needs is absent here)

A partial mix of passes and skips is a PASS: individual opt-in / live-service
cases skip legitimately and must not red an otherwise-passing suite.
"""

import argparse
import sys
import unittest


def run(start_directory, pattern, verbosity):
   suite = unittest.TestLoader().discover(
      start_dir=start_directory, pattern=pattern)
   result = unittest.TextTestRunner(verbosity=verbosity).run(suite)

   if result.failures or result.errors:
      return 1
   if result.testsRun == 0:
      print('SKIP (target absent): no tests collected', file=sys.stderr)
      return 77
   if len(result.skipped) == result.testsRun:
      print('SKIP (environment unmet): every collected test skipped',
            file=sys.stderr)
      return 78
   return 0


def main(argv):
   parser = argparse.ArgumentParser(description=__doc__)
   parser.add_argument('--start-directory', required=True)
   parser.add_argument('--pattern', default='test_*.py')
   parser.add_argument('-v', '--verbose', dest='verbosity',
                       action='store_const', const=2, default=1)
   args = parser.parse_args(argv)
   return run(args.start_directory, args.pattern, args.verbosity)


if __name__ == '__main__':
   sys.exit(main(sys.argv[1:]))
