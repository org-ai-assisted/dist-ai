#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
End-to-end randomized fuzz of the REAL curl-prgrs.

Unlike the pure-function fuzzes (curl_prgrs_fuzz.sh, fuzz_curl_prgrs.py), this
drives the ACTUAL curl-prgrs script through its whole run -- header probe,
backgrounded body worker, the poll loop, the endless-data ceilings, truncation
detection, the trap/shutdown exit path -- using the deterministic fake curl stub
(curl_prgrs_fake_curl.sh). Each iteration builds a random scenario, predicts the
process exit code from a model of the documented behavior, runs curl-prgrs, and
asserts the real exit code matches. A mismatch is a finding, printed with the
seed and scenario so it reproduces (--seed N).

No external dependencies -- stdlib plus the real curl-prgrs and its runtime
tools (curl, tput, stecho, stcat, safe-rm). SKIPs (exit 77) if the subject or a
tool is absent.

Behavior model (matches curl-prgrs, verified against its unit tests):
  - CURL_OUT_FILE empty                 -> 57  (check_variables, before traps)
  - CURL_PRGRS_MAX_FILE_SIZE_BYTES empty-> 57
  - max not a whole number              -> 1   (is_whole_number fails, no trap yet)
  - advertised Content-Length not whole
    OR > 16 digits                      -> 116
  - else, on final body size vs the ceilings:
      body > max            -> 81   (hard cap)
      body > content-length -> 114
      body < content-length -> 115  (truncated)
      body == content-length-> the fake curl's body exit code (0 or non-zero)
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

_TOOL_DEPS = ("curl", "tput", "stecho", "stcat", "safe-rm", "mktemp", "truncate", "stat")


def _paths():
    """Resolve the curl-prgrs subject, the fake curl stub, and the env wiring the
    checkout needs (PATH for stecho/stcat, PYTHONPATH for their stdisplay import)."""
    here = os.path.dirname(os.path.realpath(__file__))
    fake_curl = os.path.join(here, "curl_prgrs_fake_curl.sh")
    repo = os.environ.get("HELPER_SCRIPTS_REPO", "").rstrip("/")
    base = repo if repo else ""
    subject = os.path.join(base or "/", "usr/libexec/helper-scripts/curl-prgrs")
    env = dict(os.environ)
    if base:
        env["HELPER_SCRIPTS_PATH"] = base
        env["PATH"] = os.path.join(base, "usr/bin") + os.pathsep + env.get("PATH", "")
        pp = os.path.join(base, "usr/lib/python3/dist-packages")
        env["PYTHONPATH"] = pp + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    else:
        env.setdefault("HELPER_SCRIPTS_PATH", "")
    env["CURL"] = fake_curl
    env["curl_prgrs_poll_interval"] = "0.02"
    return subject, fake_curl, env


def _is_whole(value: str) -> bool:
    return value == "0" or (value.isdigit() and not value.startswith("0"))


def _expected(scn: dict) -> int:
    if scn["out_empty"]:
        return 57
    if scn["max"] == "":
        return 57
    if not _is_whole(scn["max"]):
        return 1
    cl = scn["header_cl"]
    if not _is_whole(cl) or len(cl) > 16:
        return 116
    cl_int = int(cl)
    body = scn["body_bytes"]
    if body > int(scn["max"]):
        return 81
    if body > cl_int:
        return 114
    if body < cl_int:
        return 115
    return scn["body_exit"]


def _random_scenario(rng: random.Random) -> dict:
    roll = rng.random()
    out_empty = roll < 0.05
    max_val = "" if 0.05 <= roll < 0.10 else (
        rng.choice(["x", "-1", "07", "1a"]) if 0.10 <= roll < 0.16
        else str(rng.choice([1, 100, 1000, 100000, 10_000_000, 10 ** 15]))
    )
    header_cl = rng.choice([
        "0", "1", "100", "500", "1000", str(rng.randint(0, 3000)),
        "9999999999999999",          # 16 digits (allowed)
        "99999999999999999",         # 17 digits -> 116
        "x", "-5", "08",             # non-whole -> 116
    ])
    ## Note: an EMPTY header is not representable via the fake curl -- its
    ## '${FAKE_CURL_HEADER_CL:-0}' turns "" into "0" -- so it is not generated.
    body_bytes = rng.choice([0, 1, rng.randint(0, 3000), 500, 1000, 3000])
    body_exit = 0 if rng.random() < 0.85 else rng.choice([1, 22, 47])
    return {
        "out_empty": out_empty,
        "max": max_val,
        "header_cl": header_cl,
        "body_bytes": body_bytes,
        "body_exit": body_exit,
    }


def _run(subject: str, env: dict, scn: dict, out_dir: str, idx: int) -> int:
    out_file = "" if scn["out_empty"] else os.path.join(out_dir, f"o{idx}.bin")
    run_env = dict(env)
    run_env["CURL_OUT_FILE"] = out_file
    run_env["CURL_PRGRS_MAX_FILE_SIZE_BYTES"] = scn["max"]
    run_env["FAKE_CURL_HEADER_CL"] = scn["header_cl"]
    run_env["FAKE_CURL_BODY_BYTES"] = str(scn["body_bytes"])
    run_env["FAKE_CURL_BODY_EXIT"] = str(scn["body_exit"])
    argv = [subject]
    if out_file:
        argv += ["-o", out_file]
    argv.append("https://example.com/fuzz")
    try:
        proc = subprocess.run(
            argv, env=run_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return proc.returncode
    except subprocess.TimeoutExpired:
        return -1


def main() -> None:
    parser = argparse.ArgumentParser(description="curl-prgrs end-to-end fuzz.")
    parser.add_argument("--iterations", type=int, default=150)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    subject, fake_curl, env = _paths()
    if not os.path.isfile(subject) or not os.access(subject, os.X_OK):
        print(f"SKIP: curl-prgrs not found/executable at {subject!r}.")
        print("      set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install it.")
        raise SystemExit(77)
    if not os.access(fake_curl, os.X_OK):
        print(f"FATAL: fake curl stub missing: {fake_curl!r}")
        raise SystemExit(1)
    missing = [t for t in _TOOL_DEPS if shutil.which(t, path=env.get("PATH")) is None]
    if missing:
        print(f"SKIP: runtime tools not on PATH: {' '.join(missing)}")
        raise SystemExit(77)

    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(2 ** 32)
    rng = random.Random(seed)
    print(f"curl-prgrs e2e fuzz: seed={seed} iterations={args.iterations}")

    fails = 0
    with tempfile.TemporaryDirectory(prefix="curl-prgrs-e2e.") as out_dir:
        for i in range(args.iterations):
            scn = _random_scenario(rng)
            want = _expected(scn)
            got = _run(subject, env, scn, out_dir, i)
            if got != want:
                fails += 1
                print(f"FUZZ MISMATCH: scenario={scn} expected={want} got={got}")
                if fails >= 10:
                    break

    if fails:
        print(f"FAILED: {fails} mismatch(es); reproduce with --seed {seed}")
        raise SystemExit(1)
    print(f"OK: {args.iterations} scenarios, 0 mismatches (seed {seed})")


if __name__ == "__main__":
    main()
