#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized in-process fuzzer for sdwdate's untrusted-input parsers.

sdwdate fetches the time from remote (onion) servers and parses whatever they
return, then parses its own on-disk pool configuration. Those parsers face
attacker-influenceable input -- a hostile time server controls the HTTP Date
header, and a tampered pool file controls the sort_pool text. They must never
crash on adversarial input; a crash is the time daemon dying on a hostile
server response.

sdwdate's parsers reject bad input by calling sys.exit(N) (SystemExit), NOT by
returning a sentinel. So the oracle is: for any input a target must either
return cleanly OR raise SystemExit -- any OTHER exception is a finding.

Targets:
  * url_to_unixtime.data_to_http_time           -- HTTP Date header length gate
  * url_to_unixtime.http_time_to_parsed_unixtime -- dateutil parse -> unixtime
  * url_to_unixtime.unixtime_sanity_check        -- numeric/length bounds
  * sdwdate.config.sort_pool                     -- pool-config text parser

Network is kept OUT of the hot loop: only the pure parsers are driven, never
requests.get / the Tor control connection.

Run: fuzz_sdwdate.py [--iterations N] [--seed N]. On a failure it prints the
seed and the offending input so the case replays deterministically.
"""

import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import random
import sys

import sdwdate_testlib as T


## ---- target resolution ------------------------------------------------------

def _load_url_to_unixtime():
    """
    Import the real url_to_unixtime script as a module.

    It lives in usr/bin (not on the Python path) and is guarded by
    ``if __name__ == "__main__"``, so importing it defines its functions
    without running main() (no network). It imports requests + dateutil at load
    time; a missing dep is the runner's SKIP (exit 77), matching
    sdwdate_testlib.import_sdwdate.
    """
    repo = os.environ.get('SDWDATE_REPO', '').strip()
    base = repo if repo else '/'
    path = os.path.join(base, 'usr', 'bin', 'url_to_unixtime')
    if not os.path.exists(path):
        print(
            'SKIP: %s not found -- install sdwdate or set SDWDATE_REPO' % path,
            file=sys.stderr,
        )
        sys.exit(77)
    ## url_to_unixtime has no .py extension, so spec_from_file_location cannot
    ## infer a loader from the path; supply one explicitly.
    loader = importlib.machinery.SourceFileLoader('url_to_unixtime', path)
    spec = importlib.util.spec_from_loader('url_to_unixtime', loader)
    module = importlib.util.module_from_spec(spec)
    try:
        loader.exec_module(module)
    except ImportError as exc:
        print(
            'SKIP: cannot import url_to_unixtime (%s) -- needs python3-requests '
            'and python3-dateutil' % exc,
            file=sys.stderr,
        )
        sys.exit(77)
    return module


def _load_config():
    """Import sdwdate.config (stdlib-only imports) via the testlib resolver."""
    dist_packages = T.sdwdate_dist_packages()
    module_path = os.path.join(dist_packages, 'sdwdate', 'config.py')
    if not os.path.exists(module_path):
        print(
            'SKIP: %s not found -- install sdwdate or set SDWDATE_REPO'
            % module_path,
            file=sys.stderr,
        )
        sys.exit(77)
    if dist_packages not in sys.path:
        sys.path.insert(0, dist_packages)
    try:
        from sdwdate import config
    except ImportError as exc:
        print(
            'SKIP: cannot import sdwdate.config (%s)' % exc, file=sys.stderr)
        sys.exit(77)
    return config


class _FakeResponse:
    """
    Stand-in for the requests.Response the real parsers read.

    data_to_http_time reads ``data.headers["Date"]`` and, on rejection, prints
    ``data``; mirror only those two surfaces. The Date header is always present
    (requests guarantees the mapping shape) -- the untrusted part is its VALUE,
    which is what gets fuzzed.
    """

    def __init__(self, date_value):
        self.headers = {'Date': date_value}

    def __str__(self):
        return '<FakeResponse Date=%r>' % self.headers.get('Date')


def _clean_or_exit(call):
    """
    Run a target. A clean return or a controlled SystemExit (the parser
    rejecting bad input) is expected; return None so the caller stops the
    chain. Any other exception propagates -- that is the finding.

    The parsers print rejection diagnostics to stderr on their sys.exit paths;
    silence that noise in the hot loop (a real finding surfaces through the
    propagated exception's traceback, not these prints). stderr is restored
    before any propagated exception reaches main().
    """
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return call()
    except SystemExit:
        return None


## ---- input generators -------------------------------------------------------

_DAYS = 'Mon Tue Wed Thu Fri Sat Sun'.split()
_MONTHS = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
_HTTP_CHARS = "0123456789 :,-+/.GMTUTCabcdefghijklmnopqrstuvwxyz"


def _rand_httpdate(rnd):
    """
    Bias toward strings that pass data_to_http_time's 29..100 length gate and
    reach dateutil, with adversarial numeric fields (giant years, out-of-range
    components) that probe the ValueError-only except in
    http_time_to_parsed_unixtime.
    """
    kind = rnd.random()
    if kind < 0.5:
        day = rnd.choice(_DAYS)
        dd = rnd.choice(
            ['01', '31', '00', '99', str(rnd.randint(0, 99)), '999999999'])
        mon = rnd.choice(_MONTHS + ['Zzz', ''])
        yyyy = rnd.choice(
            ['2024', '1970', '0001', '9999', '99999999999999', '-1',
             str(rnd.randint(0, 10 ** 9))])
        hh = rnd.choice(['00', '23', '99', str(rnd.randint(0, 99))])
        mm = rnd.choice(['00', '59', '99'])
        ss = rnd.choice(['00', '59', '61', '99'])
        tz = rnd.choice(['GMT', 'UTC', '+0000', '', 'ZZZ'])
        return '%s, %s %s %s %s:%s:%s %s' % (
            day, dd, mon, yyyy, hh, mm, ss, tz)
    if kind < 0.8:
        return ''.join(
            rnd.choice(_HTTP_CHARS) for _ in range(rnd.randint(0, 120)))
    return rnd.choice(_HTTP_CHARS) * rnd.randint(0, 200)


def _rand_unixtime_str(rnd):
    """Adversarial candidate unixtime strings for unixtime_sanity_check."""
    kind = rnd.random()
    if kind < 0.4:
        return str(rnd.randint(-10, 10 ** 12))
    if kind < 0.6:
        return '-' + str(rnd.randint(0, 10 ** 12))
    if kind < 0.8:
        return ''.join(rnd.choice('0123456789') for _ in range(rnd.randint(0, 15)))
    return ''.join(rnd.choice('0123456789abcxyz +-.') for _ in range(rnd.randint(0, 15)))


def _rand_pool_lines(rnd):
    """
    Pool-config line lists as read_pools would hand sort_pool: quoted
    ``"url#comment"`` entries, multi-line ``[`` .. ``]`` blocks (which may be
    empty or unbalanced), and stray tokens.
    """
    lines = []
    for _ in range(rnd.randint(0, 12)):
        r = rnd.random()
        if r < 0.45:
            url = ''.join(
                rnd.choice('abcdef0123456789.onin') for _ in range(rnd.randint(0, 24)))
            comment = ''.join(
                rnd.choice('abc DEF-') for _ in range(rnd.randint(0, 10)))
            lines.append('"%s#%s"' % (url, comment))
        elif r < 0.6:
            lines.append('[')
        elif r < 0.75:
            lines.append(']')
        elif r < 0.9:
            lines.append(''.join(
                rnd.choice('"#[] .:abc0') for _ in range(rnd.randint(0, 30))))
        else:
            lines.append('')
    return lines


## ---- fuzz phases ------------------------------------------------------------

def phase_http_date(rnd, iterations, u2u):
    for _ in range(iterations):
        value = _rand_httpdate(rnd)
        data = _FakeResponse(value)
        http_time = _clean_or_exit(lambda: u2u.data_to_http_time(data))
        if http_time is None:
            continue
        parsed = _clean_or_exit(
            lambda: u2u.http_time_to_parsed_unixtime(data, http_time))
        if parsed is None:
            continue
        _clean_or_exit(
            lambda: u2u.unixtime_sanity_check(data, http_time, parsed))

    ## Drive unixtime_sanity_check directly too: in production its input is
    ## strftime('%s') output, but a wrong-typed/overlong value must still be
    ## rejected cleanly, never crash.
    data = _FakeResponse('probe')
    for _ in range(iterations):
        parsed = _rand_unixtime_str(rnd)
        _clean_or_exit(
            lambda: u2u.unixtime_sanity_check(data, 'probe', parsed))


def phase_sort_pool(rnd, iterations, config):
    for _ in range(iterations):
        lines = _rand_pool_lines(rnd)
        mode = rnd.choice(['production', 'test'])
        result = _clean_or_exit(lambda: config.sort_pool(lines, mode))
        if result is None:
            continue
        if (not isinstance(result, tuple) or len(result) != 2
                or not all(isinstance(item, list) for item in result)):
            raise AssertionError(
                'sort_pool returned {0!r} for mode {1!r} lines {2!r}'.format(
                    result, mode, lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=20000)
    parser.add_argument('--seed', type=int, default=None)
    opts = parser.parse_args()

    u2u = _load_url_to_unixtime()
    config = _load_config()

    seed = opts.seed if opts.seed is not None else random.randrange(2 ** 32)
    rnd = random.Random(seed)
    phases = (
        ('http_date', lambda r, n: phase_http_date(r, n, u2u)),
        ('sort_pool', lambda r, n: phase_sort_pool(r, n, config)),
    )
    per_phase = max(1, opts.iterations // len(phases))
    print('fuzz_sdwdate: seed={0} iterations={1}'.format(seed, opts.iterations))
    for name, func in phases:
        try:
            func(rnd, per_phase)
        except Exception:
            sys.stderr.write(
                "fuzz_sdwdate: FAILURE in phase '{0}' -- replay with "
                '--seed {1}\n'.format(name, seed))
            raise
        print("fuzz_sdwdate: phase '{0}' ok ({1} iterations)".format(
            name, per_phase))

    print('fuzz_sdwdate: PASS')


if __name__ == '__main__':
    main()
