#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Assert the genmkfile SBOM's reproducibility invariants for sbom_reproducible_test.sh.
## Standalone (not an inline 'python3 -c') per the R-193 style rule.
##
## Usage: sbom_reproducible_assert.py <run1.json> <run2.json> <source_date_epoch>

import json
import sys
from datetime import datetime, timezone


def main():
    run1_path, run2_path, source_date_epoch = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(run1_path, "rb") as run1_file:
        run1_bytes = run1_file.read()
    with open(run2_path, "rb") as run2_file:
        run2_bytes = run2_file.read()
    document = json.loads(run1_bytes)

    passes = 0
    fails = []

    def check(condition, ok_message, fail_message):
        nonlocal passes
        if condition:
            print(f"PASS: {ok_message}")
            passes += 1
        else:
            fails.append(fail_message)

    ## 1. Byte-for-byte reproducible across runs.
    check(
        run1_bytes == run2_bytes,
        "SBOM byte-identical across two runs",
        "SBOM differs between runs (non-reproducible)",
    )

    ## 2. Timestamp equals the changelog release date (SOURCE_DATE_EPOCH), not wall-clock.
    expected_ts = datetime.fromtimestamp(
        int(source_date_epoch), tz=timezone.utc
    ).isoformat()
    got_ts = document["metadata"].get("timestamp", "")
    check(
        got_ts == expected_ts,
        f"timestamp from changelog date ({got_ts})",
        f"timestamp '{got_ts}' != changelog-derived '{expected_ts}' (wall-clock or absent?)",
    )

    ## 3. Every component -- root and deps -- typed 'library'.
    types = [document["metadata"]["component"]["type"]] + [
        component["type"] for component in document.get("components", [])
    ]
    non_library = [one_type for one_type in types if one_type != "library"]
    check(
        not non_library,
        "all components typed library (uniform)",
        f"component(s) not typed library: {non_library}",
    )

    ## 4. No random serialNumber.
    check(
        "serialNumber" not in document,
        "no serialNumber (reproducible)",
        "serialNumber present (non-reproducible)",
    )

    for fail_message in fails:
        print(f"FAIL: {fail_message}", file=sys.stderr)
    print(f"RESULT: {passes} pass, {len(fails)} fail, 0 skip")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
