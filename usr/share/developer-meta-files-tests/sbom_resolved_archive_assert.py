#!/usr/bin/python3 -Bsu

## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@kicksecure.com>
## SPDX-License-Identifier: AGPL-3.0-or-later

## AI-Assisted

## Assert the resolved-SBOM invariants for sbom_resolved_archive_test.sh. Standalone
## (not an inline 'python3 -c') per the R-193 style rule.
##
## Usage: sbom_resolved_archive_assert.py \
##          <run1.json> <run2.json> <expected_serial> <source_date_epoch> \
##          <name> <version> <arch>

import json
import sys
from datetime import datetime, timezone


def main():
    (
        run1_path,
        run2_path,
        expected_serial,
        source_date_epoch,
        name,
        version,
        arch,
    ) = sys.argv[1:8]

    with open(run1_path, "rb") as run1_file:
        run1_bytes = run1_file.read()
    with open(run2_path, "rb") as run2_file:
        run2_bytes = run2_file.read()
    document = json.loads(run1_bytes)
    components = document.get("components", [])

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

    ## 2. RESOLVED: the binary component carries the index's content hashes.
    binary = next(
        (
            component
            for component in components
            if f"arch={arch}" in (component.get("purl") or "")
        ),
        None,
    )
    check(
        binary is not None and len(binary.get("hashes", [])) > 0,
        "binary component carries content hashes (resolved)",
        "binary component missing or has no hashes (unresolved)",
    )
    if binary is not None:
        check(
            binary.get("name") == name and binary.get("version") == version,
            f"binary component is {name}@{version}",
            f"binary component is not {name}@{version}: "
            f"{binary.get('name')}@{binary.get('version')}",
        )

    ## 3. The binary->source edge: a source component is emitted (no closure expansion).
    source = next(
        (
            component
            for component in components
            if "arch=source" in (component.get("purl") or "")
        ),
        None,
    )
    check(
        source is not None,
        "source component emitted (binary->source edge)",
        "no source component (missing binary->source edge)",
    )

    ## 4. Deterministic serial = UUID5 of the package identity.
    expected_urn = f"urn:uuid:{expected_serial}"
    got_serial = document.get("serialNumber", "")
    check(
        got_serial == expected_urn,
        f"serialNumber is the deterministic UUID5 ({got_serial})",
        f"serialNumber '{got_serial}' != expected '{expected_urn}'",
    )

    ## 5. Timestamp = the passed SOURCE_DATE_EPOCH, not wall-clock.
    expected_ts = datetime.fromtimestamp(
        int(source_date_epoch), tz=timezone.utc
    ).isoformat()
    got_ts = document.get("metadata", {}).get("timestamp", "")
    check(
        got_ts == expected_ts,
        f"timestamp from SOURCE_DATE_EPOCH ({got_ts})",
        f"timestamp '{got_ts}' != expected '{expected_ts}' (wall-clock?)",
    )

    for fail_message in fails:
        print(f"FAIL: {fail_message}", file=sys.stderr)
    print(f"RESULT: {passes} pass, {len(fails)} fail, 0 skip")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
