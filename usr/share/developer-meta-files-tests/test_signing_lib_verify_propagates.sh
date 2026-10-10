#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression tests for signing-lib.bsh.
##
## Scheme under test:
##   - sign_and_verify          : OpenPGP ('.asc') ONLY. The safe DEFAULT, used
##                                for a huge disk image. Must NEVER invoke signify.
##   - sign_and_verify_signify  : OpenPGP + signify ('.sig'). For a SMALL artifact
##                                only (torrent, sha512sums, buildinfo, installer).
##   - verify_signature         : OpenPGP only.
##   - verify_signature_signify : OpenPGP + signify.
##
## Guards:
##   1. signify is NEVER run by the default sign_and_verify (the image path) --
##      an OOM-killed signify on a 919MB image is what motivated this scheme.
##   2. Every signature check propagates its failure (the lib is sourceable with
##      no errexit; an UNCHAINED statement would return only the last command's
##      status, so a bad signature could read as success).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
## Standalone dmf component checkout wins (DEVELOPER_META_FILES_DIR); else the
## derivative-maker submodule path.
lib="${DEVELOPER_META_FILES_DIR:-${dm_checkout}/packages/kicksecure/developer-meta-files}/usr/libexec/developer-meta-files/signing-lib.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FATAL: signing-lib.bsh not found at '${lib}' (set DEVELOPER_META_FILES_DIR or DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

work="$(mktemp -d)"
cleanup() {
   safe-rm -rf -- "${work}"
}
trap cleanup EXIT

## Stub `sq` and `signify-openbsd` on PATH so the REAL lib functions run without
## real keys. `sq sign` / `signify-openbsd -S` create their signature file.
## Exit codes are controllable PER OPERATION so a test can model "signs OK but
## verification fails": sq sign->SQ_SIGN_RC, sq verify->SQ_VERIFY_RC, signify
## -S->SIGNIFY_SIGN_RC, signify -V->SIGNIFY_VERIFY_RC (each falls back to the
## shared SIGNIFY_RC, then 0). Every signify call is logged to SIGNIFY_CALLS so a
## test can assert signify was (not) invoked.
bindir="${work}/bin"
mkdir -p -- "${bindir}"
cat > "${bindir}/sq" <<'SQ'
#!/bin/bash
mode="${1:-}"
case "${mode}" in
   sign)
      for a in "$@"; do
         case "${a}" in
            --signature-file=*)
               printf 'sig' > "${a#--signature-file=}"
               ;;
         esac
      done
      exit "${SQ_SIGN_RC:-0}"
      ;;
   verify)
      exit "${SQ_VERIFY_RC:-0}"
      ;;
esac
exit 0
SQ
cat > "${bindir}/signify-openbsd" <<'SIGNIFY'
#!/bin/bash
printf 'called: %s\n' "$*" >> "${SIGNIFY_CALLS}"
prev="" xfile=""
for a in "$@"; do
   if [ "${prev}" = "-x" ]; then
      xfile="${a}"
   fi
   prev="${a}"
done
if [ "${1:-}" = "-S" ]; then
   if [ -n "${xfile}" ]; then
      printf 'sig' > "${xfile}"
   fi
   exit "${SIGNIFY_SIGN_RC:-${SIGNIFY_RC:-0}}"
fi
if [ "${1:-}" = "-V" ]; then
   exit "${SIGNIFY_VERIFY_RC:-${SIGNIFY_RC:-0}}"
fi
exit "${SIGNIFY_RC:-0}"
SIGNIFY
chmod +x -- "${bindir}/sq" "${bindir}/signify-openbsd"
export PATH="${bindir}:${PATH}"

export DEBEMAIL="test@example.invalid"
export SIGNIFY_CALLS="${work}/signify-calls.log"
signify_private_key="${work}/keyname.sec"
signify_public_key="${work}/keyname.pub"
printf '%s' "priv" > "${signify_private_key}"
printf '%s' "pub" > "${signify_public_key}"

# shellcheck disable=SC1090
source "${lib}"

## Fresh artifact + clean sidecars/log for each case.
reset_artifact() {
   artifact="${work}/artifact.img"
   printf '%s' "payload" > "${artifact}"
   safe-rm -f -- "${artifact}.asc" "${artifact}.sig"
   true > "${SIGNIFY_CALLS}"
}

## CANARY 1: sign_and_verify (the image path) must produce a '.asc' and must
## NEVER invoke signify or produce a '.sig'. FAILS on the old size-gated code,
## which signify-signed any file < 1000MB.
reset_artifact
if ( SQ_VERIFY_RC=0 sign_and_verify "${artifact}" ) >/dev/null 2>&1; then
   if [ -f "${artifact}.asc" ] && [ ! -f "${artifact}.sig" ] && [ ! -s "${SIGNIFY_CALLS}" ]; then
      pass "sign_and_verify produces .asc only, never invokes signify"
   else
      fail "sign_and_verify must be OpenPGP-only but produced a .sig or invoked signify (signify call count: $(wc -l < "${SIGNIFY_CALLS}"))"
   fi
else
   fail "sign_and_verify unexpectedly failed on the happy path"
fi

## CANARY 1b: sign_and_verify must DELETE a stale '.sig' (from an earlier build
## or planted), so a signature that does not match this file cannot be published.
reset_artifact
printf '%s' "stale signature for a previous file" > "${artifact}.sig"
if ( SQ_VERIFY_RC=0 sign_and_verify "${artifact}" ) >/dev/null 2>&1; then
   if [ ! -f "${artifact}.sig" ]; then
      pass "sign_and_verify removes a stale .sig"
   else
      fail "sign_and_verify left a stale .sig in place (would publish a mismatched signature)"
   fi
else
   fail "sign_and_verify unexpectedly failed with a stale .sig present"
fi

## CANARY 2: sign_and_verify_signify DOES invoke signify and produces both
## sidecars. FAILS on the old code (no such function).
reset_artifact
if ( SQ_VERIFY_RC=0 SIGNIFY_RC=0 sign_and_verify_signify "${artifact}" ) >/dev/null 2>&1; then
   if [ -f "${artifact}.asc" ] && [ -f "${artifact}.sig" ] && [ -s "${SIGNIFY_CALLS}" ]; then
      pass "sign_and_verify_signify produces .asc + .sig and invokes signify"
   else
      fail "sign_and_verify_signify did not produce both sidecars / invoke signify"
   fi
else
   fail "sign_and_verify_signify unexpectedly failed on the happy path"
fi

## PROPAGATION: a bad OpenPGP signature must FAIL verify_signature.
reset_artifact
printf '%s' "asc" > "${artifact}.asc"
if ( SQ_VERIFY_RC=1 verify_signature "${artifact}" ) >/dev/null 2>&1; then
   fail "verify_signature returned 0 for a bad OpenPGP sig (propagation broken)"
else
   pass "verify_signature FAILS on a bad OpenPGP signature"
fi

## PROPAGATION: for the checksums path, a bad signify signature must FAIL even
## when the OpenPGP signature is GOOD (the signify check must not be masked).
reset_artifact
printf '%s' "asc" > "${artifact}.asc"
printf '%s' "sig" > "${artifact}.sig"
if ( SQ_VERIFY_RC=0 SIGNIFY_RC=1 verify_signature_signify "${artifact}" ) >/dev/null 2>&1; then
   fail "verify_signature_signify returned 0 with a bad signify sig (signify check masked)"
else
   pass "verify_signature_signify FAILS on a bad signify signature (good OpenPGP)"
fi

## PROPAGATION: both good -> verify_signature_signify succeeds.
reset_artifact
printf '%s' "asc" > "${artifact}.asc"
printf '%s' "sig" > "${artifact}.sig"
if ( SQ_VERIFY_RC=0 SIGNIFY_RC=0 verify_signature_signify "${artifact}" ) >/dev/null 2>&1; then
   pass "verify_signature_signify succeeds when both signatures are valid"
else
   fail "verify_signature_signify wrongly failed with two valid signatures"
fi

## PROPAGATION: sign_and_verify must FAIL a bad OpenPGP verify. The structural
## grep below accepts any chaining including a failure-masking '|| true', so this
## behavioural check is what actually catches a swallowed failure.
reset_artifact
if ( SQ_SIGN_RC=0 SQ_VERIFY_RC=1 sign_and_verify "${artifact}" ) >/dev/null 2>&1; then
   fail "sign_and_verify returned 0 despite a failing OpenPGP verify (failure masked)"
else
   pass "sign_and_verify FAILS when OpenPGP verification fails"
fi

## sign_and_verify_signify must VERIFY after signing: signify signs OK but the
## signify VERIFY fails -> the function must fail, not just leave a '.sig'.
reset_artifact
if ( SQ_VERIFY_RC=0 SIGNIFY_SIGN_RC=0 SIGNIFY_VERIFY_RC=1 sign_and_verify_signify "${artifact}" ) >/dev/null 2>&1; then
   fail "sign_and_verify_signify returned 0 though the signify verify failed (verify skipped)"
else
   pass "sign_and_verify_signify FAILS when the signify verification fails"
fi

## verify_signature is OpenPGP-only: a valid OpenPGP signature verifies WITHOUT
## invoking signify.
reset_artifact
printf '%s' "asc" > "${artifact}.asc"
if ( SQ_VERIFY_RC=0 verify_signature "${artifact}" ) >/dev/null 2>&1; then
   if [ ! -s "${SIGNIFY_CALLS}" ]; then
      pass "verify_signature verifies via OpenPGP only, never invoking signify"
   else
      fail "verify_signature invoked signify (must be OpenPGP-only)"
   fi
else
   fail "verify_signature wrongly failed a valid OpenPGP signature"
fi

## verify_signature_signify must PROPAGATE a bad OpenPGP signature even when the
## signify signature is good (the OpenPGP check must not be skipped).
reset_artifact
printf '%s' "asc" > "${artifact}.asc"
printf '%s' "sig" > "${artifact}.sig"
if ( SQ_VERIFY_RC=1 SIGNIFY_VERIFY_RC=0 verify_signature_signify "${artifact}" ) >/dev/null 2>&1; then
   fail "verify_signature_signify returned 0 with a bad OpenPGP sig (OpenPGP check skipped)"
else
   pass "verify_signature_signify FAILS on a bad OpenPGP signature (good signify)"
fi

## STRUCTURAL: every sign/verify check chains with '|| return'. An unchained
## '(sign|verify)_cmd_* "${1}" ...' line (no trailing '|| return') is the
## status-masking bug this guards. '\s*' so a column-0 line is caught too.
if grep --extended-regexp --quiet '^\s*(sign|verify)_cmd_(openpgp|signify) "\$\{1\}"[^|]*$' -- "${lib}"; then
   fail "signing-lib.bsh has an UNCHAINED sign/verify check (status would be masked)"
else
   pass "every sign/verify check in signing-lib.bsh is chained (|| return)"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: signing-lib sign/verify scheme + propagation."
