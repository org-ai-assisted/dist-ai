#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Discover and run a unittest suite, mapping the outcome to dist-ai's canonical
result codes so an all-skipped or nothing-collected run cannot read as a green
PASS. A bare `python3 -m unittest discover` exits 0 when every test is skipped
at import (missing PyQt5, an absent subject module), hiding that nothing ran.

Codes (match dist-ai-tests-common/suite-exit.bash):
  0  pass -- at least one test ran to a real conclusion (passed, or failed AS
     EXPECTED under @expectedFailure) and nothing went wrong
  1  a test failed, errored, OR unexpectedly passed (an @expectedFailure that
     passed is a failure in unittest -- wasSuccessful() is False -- so it is
     here too)
  77 SKIP:target-absent -- no tests were collected (the suite is empty/unwired)
  78 SKIP:env-unmet -- tests were collected but EVERY one skipped (a runtime
     capability the suite needs is absent here), INCLUDING a whole class or
     module skipped from setUpClass/setUpModule (such a skip lands in
     result.skipped WITHOUT incrementing testsRun)

A partial mix of passes and skips is a PASS: individual opt-in / live-service
cases skip legitimately and must not red an otherwise-passing suite.

--strict-skips is for a suite with NO legitimately-optional case: ANY skip
(method, class or module) is exit 1, listing the skipped tests, unless the
orchestrator authorized the skip (DIST_AI_SKIP_AUTHORIZED=1, set for an
--allow-skip'd suite), then 78. A partial mix is otherwise a silent PASS that
hides every case which tested nothing.
"""

import argparse
import os
import sys
import unittest


class _CountingResult(unittest.TextTestResult):
   ## unittest exposes failures/errors/skipped/expectedFailures/unexpectedSuccesses
   ## but NOT a passed count, and a class/module-level skip lands in `skipped`
   ## WITHOUT incrementing testsRun -- so deriving the passed count from testsRun
   ## is unreliable (it goes negative on a setUpClass skip). Count addSuccess.
   def __init__(self, *args, **kwargs):
      super().__init__(*args, **kwargs)
      self.passed = 0

   def addSuccess(self, test):
      super().addSuccess(test)
      self.passed += 1


def run(start_directory, pattern, verbosity, strict_skips):
   suite = unittest.TestLoader().discover(
      start_dir=start_directory, pattern=pattern)
   result = unittest.TextTestRunner(
      verbosity=verbosity, resultclass=_CountingResult).run(suite)

   ## wasSuccessful() is False on a failure, an error, OR an unexpected success.
   if not result.wasSuccessful():
      return 1
   if strict_skips and result.skipped:
      for test, reason in result.skipped:
         print(f'skipped: {test.id()}: {reason}', file=sys.stderr)
      if os.environ.get('DIST_AI_SKIP_AUTHORIZED') == '1':
         print(f'SKIP (environment unmet): {len(result.skipped)} test(s) '
               'skipped (authorized)', file=sys.stderr)
         return 78
      print(f'FATAL: {len(result.skipped)} test(s) skipped under --strict-skips '
            'and the skip is not authorized (DIST_AI_SKIP_AUTHORIZED=1)',
            file=sys.stderr)
      return 1
   ## A real pass (or an expected failure that behaved) means the suite actually
   ## exercised something -> PASS, even alongside some skips.
   if result.passed > 0 or result.expectedFailures:
      return 0
   ## Nothing ran to a real conclusion. A collected-but-skipped test (method,
   ## class, or module level) is an env-unmet SKIP; nothing at all is a
   ## target-absent SKIP.
   if result.skipped:
      print('SKIP (environment unmet): every collected test skipped',
            file=sys.stderr)
      return 78
   print('SKIP (target absent): no tests collected', file=sys.stderr)
   return 77


def main(argv):
   parser = argparse.ArgumentParser(description=__doc__)
   parser.add_argument('--start-directory', required=True)
   parser.add_argument('--pattern', default='test_*.py')
   parser.add_argument('-v', '--verbose', dest='verbosity',
                       action='store_const', const=2, default=1)
   parser.add_argument('--strict-skips', action='store_true')
   ## Unknown args (a forwarded -k/-f) are REJECTED loudly by argparse (exit 2),
   ## never silently ignored -- a runner forwards "$@" here so --help and -v work
   ## and anything unsupported fails visibly instead of pretending it applied.
   args = parser.parse_args(argv)
   return run(args.start_directory, args.pattern, args.verbosity,
              args.strict_skips)


if __name__ == '__main__':
   sys.exit(main(sys.argv[1:]))
