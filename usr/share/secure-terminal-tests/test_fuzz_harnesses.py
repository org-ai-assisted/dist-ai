#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""EXECUTE every atheris fuzz harness in secure-terminal/fuzz/ against the shared
seed corpus, without atheris installed.

The harnesses are compiled and run only by ClusterFuzzLite, so anything that
breaks them (a renamed import, a harness whose own invariant check is wrong, a
seed that trips a real bug) surfaces in a nightly that nothing blocks on. This
suite runs their TestOneInput on every push instead.

atheris is stubbed, not required: the harnesses use exactly four entry points
(instrument_imports, FuzzedDataProvider, Setup, Fuzz), and only the first two run
at import/drive time. The provider is deterministic, so a failure here replays.

A harness raising is a FAILURE, not an error to swallow -- its RuntimeErrors are
the security invariants (no ESC smuggled into a cell, no unsafe run, cursor in
bounds). Exit 0 on full pass, 1 on any failure.

Source here is pure ASCII: seeds live as hex in fuzz/corpus/seeds.txt.
"""

import contextlib
import importlib.util
import os
import sys
import types

try:
    from secure_terminal import sanitize as _S
except Exception as exc:  # pylint: disable=broad-except
    # Fail closed: a missing package means the harnesses cannot be driven, and a
    # silent skip here would read as "the fuzz harnesses are fine".
    sys.stderr.write('secure-terminal-tests(fuzz-harnesses): FAIL cannot import '
                     'secure_terminal.sanitize: %s\n' % exc)
    sys.exit(1)

PASS = 0
FAIL = 0


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        sys.stderr.write('FAIL: ' + msg + '\n')


class _FuzzedDataProvider:
    """Deterministic stand-in for atheris.FuzzedDataProvider.

    Byte-for-byte fidelity with atheris is neither possible nor needed: the point
    is that each harness receives structured-but-hostile input derived from the
    seed, and that its own assertions run. Consumption is front-to-back so a seed
    maps to the same values on every run.
    """

    def __init__(self, data):
        self._data = bytes(data)
        self._pos = 0

    def _take(self, count):
        chunk = self._data[self._pos:self._pos + max(0, count)]
        self._pos += len(chunk)
        return chunk

    def ConsumeBytes(self, count):                    # noqa: N802 (atheris API)
        return self._take(count)

    def ConsumeIntInRange(self, low, high):           # noqa: N802 (atheris API)
        if high <= low:
            return low
        raw = self._take(4)
        if not raw:
            return low
        return low + (int.from_bytes(raw, 'little') % (high - low + 1))

    def ConsumeUnicodeNoSurrogates(self, count):      # noqa: N802 (atheris API)
        raw = self._data[self._pos:]
        self._pos = len(self._data)
        text = raw.decode('utf-8', 'replace')
        text = ''.join(ch for ch in text if not 0xD800 <= ord(ch) <= 0xDFFF)
        return text[:max(0, count)]


def _install_atheris_stub():
    """Put a stub 'atheris' in sys.modules so the harnesses import unmodified."""
    stub = types.ModuleType('atheris')

    @contextlib.contextmanager
    def instrument_imports(*_args, **_kwargs):
        yield

    stub.instrument_imports = instrument_imports
    stub.FuzzedDataProvider = _FuzzedDataProvider
    stub.Setup = lambda *_args, **_kwargs: None       # only called from main()
    stub.Fuzz = lambda *_args, **_kwargs: None
    sys.modules['atheris'] = stub


def _repo_root():
    pkg_dir = os.path.dirname(os.path.abspath(_S.__file__))
    root = pkg_dir
    for _level in range(5):    # .../usr/lib/python3/dist-packages/secure_terminal
        root = os.path.dirname(root)
    return root


def _load_seeds(path):
    """Parse NAME<space>HEX lines into (name, bytes)."""
    seeds = []
    with open(path, encoding='ascii') as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('##'):
                continue
            name, _, hexed = line.partition(' ')
            if not hexed:
                continue
            seeds.append((name, bytes.fromhex(hexed)))
    return seeds


def _load_harness(path):
    name = 'stfuzz_' + os.path.basename(path)[:-3]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    _install_atheris_stub()
    root = _repo_root()
    fuzz_dir = os.path.join(root, 'fuzz')
    seeds_path = os.path.join(fuzz_dir, 'corpus', 'seeds.txt')

    ok(os.path.isdir(fuzz_dir), 'fuzz harness dir present (%s)' % fuzz_dir)
    ok(os.path.isfile(seeds_path), 'seed corpus present (%s)' % seeds_path)
    if not (os.path.isdir(fuzz_dir) and os.path.isfile(seeds_path)):
        return 1

    seeds = _load_seeds(seeds_path)
    ok(len(seeds) >= 20, 'seed corpus has a useful number of seeds (%d)' % len(seeds))

    harnesses = sorted(n for n in os.listdir(fuzz_dir)
                       if n.startswith('fuzz_') and n.endswith('.py'))
    ok(len(harnesses) > 0, 'at least one fuzz harness present')

    for harness_name in harnesses:
        path = os.path.join(fuzz_dir, harness_name)
        try:
            module = _load_harness(path)
        except Exception as exc:  # pylint: disable=broad-except
            ok(False, 'fuzz/%s imports: %r' % (harness_name, exc))
            continue
        ok(callable(getattr(module, 'TestOneInput', None)),
           'fuzz/%s defines TestOneInput' % harness_name)
        if not callable(getattr(module, 'TestOneInput', None)):
            continue
        drove = 0
        for seed_name, blob in seeds:
            try:
                module.TestOneInput(blob)
                drove += 1
            except Exception as exc:  # pylint: disable=broad-except
                ok(False, 'fuzz/%s raised on seed %r: %r'
                   % (harness_name, seed_name, exc))
        ok(drove == len(seeds),
           'fuzz/%s survives the whole seed corpus (%d/%d)'
           % (harness_name, drove, len(seeds)))
        # An empty input must be handled too: libFuzzer always tries it first.
        try:
            module.TestOneInput(b'')
            ok(True, 'fuzz/%s handles an empty input' % harness_name)
        except Exception as exc:  # pylint: disable=broad-except
            ok(False, 'fuzz/%s raised on an empty input: %r' % (harness_name, exc))

    print('secure-terminal-tests(fuzz-harnesses): %d passed, %d failed'
          % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
