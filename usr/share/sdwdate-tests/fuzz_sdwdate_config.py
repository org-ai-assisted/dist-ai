#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris coverage-guided harness for sdwdate.config.sort_pool, the pool-config
text parser.

Pool config lives in root-owned /etc/sdwdate.d, so this is not an unprivileged
surface, but a malformed pool file must not crash the time daemon on load.
sort_pool must return its declared (urls, comments) pair of lists for any input,
never raise. This harness feeds adversarial pool-line lists (quoted entries,
multi-line "[" .. "]" blocks, stray tokens) in both modes.

The subject module is imported under atheris.instrument_imports() so the parser
is coverage-instrumented. Runs in-process (sdwdate-tests-fuzz-atheris,
SDWDATE_REPO) and as a ClusterFuzzLite build.
"""

import os
import sys
from typing import Any

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import sdwdate_testlib as T  # noqa: E402

try:
    import atheris  # type: ignore

    _HAVE_ATHERIS: bool = True
except ImportError:
    _HAVE_ATHERIS = False


def _load_config() -> Any:
    dist_packages = T.sdwdate_dist_packages()
    module_path = os.path.join(dist_packages, 'sdwdate', 'config.py')
    if not os.path.exists(module_path):
        return None
    if dist_packages not in sys.path:
        sys.path.insert(0, dist_packages)
    try:
        if _HAVE_ATHERIS:
            with atheris.instrument_imports():
                from sdwdate import config as _config
        else:
            from sdwdate import config as _config
    except ImportError:
        return None
    return _config


config: Any = _load_config()


def _rand_pool_lines(fdp):
    lines = []
    for _ in range(fdp.ConsumeIntInRange(0, 12)):
        kind = fdp.ConsumeIntInRange(0, 4)
        if kind == 0:
            lines.append('[')
        elif kind == 1:
            lines.append(']')
        elif kind == 2:
            lines.append('"' + fdp.ConsumeUnicodeNoSurrogates(40) + '"')
        else:
            lines.append(fdp.ConsumeUnicodeNoSurrogates(40))
    return lines


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    fdp = atheris.FuzzedDataProvider(data)
    lines = _rand_pool_lines(fdp)
    mode = 'production' if fdp.ConsumeBool() else 'test'
    result = config.sort_pool(lines, mode)
    if (not isinstance(result, tuple) or len(result) != 2
            or not all(isinstance(item, list) for item in result)):
        raise RuntimeError('sort_pool returned %r' % (result,))


def main() -> None:
    if config is None:
        print(
            'SKIP: sdwdate.config not found -- install sdwdate or set '
            'SDWDATE_REPO',
            file=sys.stderr,
        )
        ## style-ok: allow-skip: sdwdate subject not available
        raise SystemExit(77)
    if not _HAVE_ATHERIS:
        print('SKIP: atheris is not installed (pip install atheris).')
        ## style-ok: allow-skip: atheris optional fuzzing dep not installed
        raise SystemExit(77)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
