# Pending AI reviews

## #160 consolidation (commits ba674cd, 9ccdafe, f5e0b2d)
- Could not run: the working tree carries unrelated modifications from another
  session (usr/share/secure-terminal-tests/test_*.py) and ai-review requires a
  clean tree; not stashing another session's work.
- New logic to review: usr/bin/dm-reproducible-build-tests (the runner) and the
  qmp_client.py trim (mostly a verbatim extract of QMPClient).
- Already validated: full dist-ai package BUILDS clean (all .install/control
  resolve); iso-boot-tests-fuzz passes end-to-end (4 properties, 200 examples);
  the reproducible runner tested SKIP-77 (no repo / no args) + PASS(0)/FAIL(1) via
  the real comparator; shellcheck + bash -n clean.
- Re-run `ai-review f5e0b2d~3` once the tree is clean.
