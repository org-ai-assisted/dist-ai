#!/usr/bin/python3 -Bsu

## SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@kicksecure.com>
## SPDX-License-Identifier: AGPL-3.0-or-later

## AI-Assisted

## Assert the resolved-SBOM invariants for sbom_resolved_archive_test.sh. Standalone
## (not an inline 'python3 -c') per the R-193 style rule.
##
## Usage: sbom_resolved_archive_assert.py \
##          <run1.json> <run2.json> <expected_serial> <source_date_epoch> \
##          <name> <version> <arch> <expected_sha256>

import json
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit


def purl_arch(purl):
    ## The purl's 'arch' qualifier, parsed exactly (not a substring match, so 'amd64'
    ## does not spuriously match 'amd64evil').
    if not purl:
        return None
    qualifiers = parse_qs(urlsplit(purl).query)
    values = qualifiers.get("arch")
    return values[0] if values else None


def sha256_of(component):
    for one_hash in component.get("hashes", []):
        if one_hash.get("alg") == "SHA-256":
            return one_hash.get("content")
    return None


def main():
    (
        run1_path,
        run2_path,
        expected_serial,
        source_date_epoch,
        name,
        version,
        arch,
        expected_sha256,
    ) = sys.argv[1:9]

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

    ## 2. RESOLVED: the binary component is exactly this (name, version, arch) and carries
    ## the fixture index's SHA-256 -- not merely 'some hash', so a wrong-arch or wrong-hash
    ## component cannot pass.
    binary = next(
        (
            component
            for component in components
            if component.get("name") == name
            and component.get("version") == version
            and purl_arch(component.get("purl")) == arch
        ),
        None,
    )
    check(
        binary is not None,
        f"binary component is exactly {name}@{version} arch={arch}",
        f"no binary component matching {name}@{version} arch={arch}",
    )
    check(
        binary is not None and sha256_of(binary) == expected_sha256,
        "binary component carries the index's SHA-256 (resolved)",
        f"binary SHA-256 {binary and sha256_of(binary)} != index {expected_sha256}",
    )

    ## 3. The binary->source EDGE. The source component is the fixture's OWN source, matched
    ## by NAME (sbomfixture has no Source: field, so source name == binary name) -- not merely
    ## 'some source-arch component', so an edge to an unrelated source cannot pass. The edge
    ## must run binary-ref -> source-ref with DISTINCT refs, so a degenerate self-reference
    ## ({"ref": X, "dependsOn": [X]}) cannot satisfy it.
    source = next(
        (
            component
            for component in components
            if purl_arch(component.get("purl")) == "source"
            and component.get("name") == name
        ),
        None,
    )
    check(
        source is not None,
        f"source component is exactly {name} (arch=source)",
        f"no source component named {name}",
    )
    edges = {
        dependency.get("ref"): dependency.get("dependsOn", [])
        for dependency in document.get("dependencies", [])
    }
    binary_ref = binary.get("bom-ref") if binary else None
    source_ref = source.get("bom-ref") if source else None
    check(
        binary_ref is not None
        and source_ref is not None
        and binary_ref != source_ref
        and source_ref in edges.get(binary_ref, []),
        "binary->source dependency edge present (distinct refs)",
        "no binary->source edge, or binary and source share a bom-ref",
    )

    ## 4. No closure expansion: exactly the binary and its source, nothing else -- so a
    ## stray transitive dependency component would fail.
    check(
        len(components) == 2,
        "exactly two components (binary + source, no closure)",
        f"expected 2 components (binary + source), got {len(components)}",
    )

    ## 5. Deterministic serial = the EXPECTED UUID5 (a literal the caller passes, computed
    ## independently of the function under test, so the check is not circular).
    expected_urn = f"urn:uuid:{expected_serial}"
    got_serial = document.get("serialNumber", "")
    check(
        got_serial == expected_urn,
        f"serialNumber is the expected UUID5 ({got_serial})",
        f"serialNumber '{got_serial}' != expected '{expected_urn}'",
    )

    ## 6. Timestamp = the passed SOURCE_DATE_EPOCH, not wall-clock.
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
