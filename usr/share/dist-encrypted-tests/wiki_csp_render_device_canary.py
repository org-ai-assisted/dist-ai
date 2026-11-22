#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Behavioral canary for wiki-csp-render/check.py --device (the mobile CSP leg).
# Driven by wiki_csp_render_device_test.sh Phase 2 under the Playwright venv
# python; a standalone file (not an embedded -c program) so the shell harness
# carries no interpreter blob.
#
# Serves a local page that injects a CSP-blocked <img> ONLY on a narrow (mobile)
# viewport, then drives the REAL check.py (argv[1], else the sibling copy):
#   - desktop (no --device)       -> page stays clean           -> check.py exit 0
#   - --device "Pixel 5" (393px)  -> injected img is blocked     -> check.py exit 1
#   - --device "NoSuchDevice99"   -> unknown device, clean fail  -> check.py exit 2
#
# CANARY: a check.py without --device rejects the mobile run (argparse, exit 2),
# so a mobile-only violation would ship unseen. Exit 0 only if all three match;
# prints a PASS/FAIL line per case.
import subprocess
import sys
import threading
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

# The width=device-width viewport meta is REQUIRED: without it mobile Chromium
# lays out against a ~980px default viewport, so window.innerWidth reads 980 and
# the mobile branch never fires -- the canary would false-pass.
PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="img-src 'none'">
<title>csp device canary</title></head>
<body>
<script>
if (window.innerWidth < 500) {
  var i = document.createElement('img');
  i.src = '/mobile-only.png';
  document.body.appendChild(i);
}
</script>
</body></html>
"""


def run_check(check_py, serve_dir, base_url, extra):
    cmd = [sys.executable, check_py,
           "--base-url", base_url, "--path-prefix", "/", "--pages", "page.html",
           "--timeout-ms", "15000", "--settle-ms", "1500"] + extra
    proc = subprocess.run(cmd, cwd=serve_dir, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stderr.strip()


def main():
    here = Path(__file__).resolve().parent
    check_arg = sys.argv[1] if len(sys.argv) > 1 else str(here / "check.py")
    # Absolute: check.py is invoked from the server's temp CWD, not this dir.
    check_py = str(Path(check_arg).resolve())
    if not Path(check_py).is_file():
        print("FAIL: check.py not found at %r" % check_arg, file=sys.stderr)
        return 1

    import tempfile
    serve_dir = tempfile.mkdtemp()
    try:
        (Path(serve_dir) / "page.html").write_text(PAGE, encoding="utf-8")
        handler = partial(SimpleHTTPRequestHandler, directory=serve_dir)
        # Bind port 0 directly (no pick-then-rebind TOCTOU): the OS assigns a free port on the
        # live server socket and we read it back -- it is never closed and re-bound.
        httpd = HTTPServer(("127.0.0.1", 0), handler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % port

        cases = [
            ("desktop CLEAN -> exit 0", [], 0),
            ("mobile Pixel 5 CATCHES violation -> exit 1", ["--device", "Pixel 5"], 1),
            ("unknown device fails cleanly -> exit 2", ["--device", "NoSuchDevice99"], 2),
        ]
        ok = True
        for label, extra, want in cases:
            got, err = run_check(check_py, serve_dir, base, extra)
            passed = (got == want)
            ok = ok and passed
            tag = "PASS" if passed else "FAIL"
            print("%s: %s (got %d, want %d)" % (tag, label, got, want))
            if not passed and err:
                print("  stderr: %s" % err[-600:], file=sys.stderr)

        httpd.shutdown()
    finally:
        import shutil
        shutil.rmtree(serve_dir, ignore_errors=True)

    print("OK -- mobile-only CSP violation caught only with --device" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
