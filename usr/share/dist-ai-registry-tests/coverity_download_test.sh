#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/coverity-download.sh, which fetches the Coverity Scan
## build tool and verifies it two ways: md5 against Coverity's md5=1 endpoint,
## and an optional sha256 HARD-PIN from .coverity-tool-sha256.expected.
##
## WHY this exists: this is the supply-chain gate on a token-gated binary the CI
## then EXECUTES. If the sha256 hard-pin stopped failing closed on a mismatch,
## an md5-collision or a scan.coverity.com-side swap would run unverified code;
## if the md5 check regressed, CDN tampering would pass. The real download needs
## network + a token, so curl is stubbed (the allowed network stub) to feed a
## controlled tarball + digest, and the REAL verification logic runs against it.
## Pins: clean verify passes, sha256 mismatch fails closed, md5 mismatch fails,
## absent pin warns (md5-only), CI guard.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. Needs 'tar', 'md5sum', 'sha256sum'. No root,
## no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/ci/coverity-download.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/coverity-download.sh" ]; then
   printf '%s\n' 'FATAL: coverity-download-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

downloader="${repo}/ci/coverity-download.sh"

for dep in tar md5sum sha256sum; do
   if ! type -P "${dep}" >/dev/null; then
      printf '%s\n' "FAIL: coverity-download-test: ${dep} not on PATH; the downloader cannot run" >&2
      exit 1
   fi
done

work_dir="$(mktemp --directory -- "${TMP}/coverity-download-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Fixture: a real gzip tarball whose top dir carries a bin/coverity, so the
## downloader's 'tar --strip-components=1' extraction produces cov-analysis/bin.
fixture_root="${work_dir}/fixture/cov-analysis-linux64"
mkdir -p -- "${fixture_root}/bin"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${fixture_root}/bin/coverity"
chmod +x -- "${fixture_root}/bin/coverity"
fixture_tgz="${work_dir}/fixture.tgz"
tar -czf "${fixture_tgz}" -C "${work_dir}/fixture" -- cov-analysis-linux64

read -r good_md5 _ < <(md5sum -- "${fixture_tgz}")
read -r good_sha256 _ < <(sha256sum -- "${fixture_tgz}")

## curl stub: copies the fixture tarball to the .tgz output; writes a digest to
## the .md5 output (STUB_MD5_VALUE overrides, to simulate CDN tampering).
stub_bin="${work_dir}/bin"
mkdir -p -- "${stub_bin}"
cat > "${stub_bin}/curl" <<CURL_STUB
#!/bin/bash
out=''
while [ "\$#" -gt 0 ]; do
   if [ "\$1" = '--output' ]; then
      out="\$2"
      shift 2
   else
      shift
   fi
done
## The downloader takes only field 1 of the md5 file, so a lone hash suffices.
if [ "\${out%.tgz}" != "\${out}" ]; then
   cp -- "${fixture_tgz}" "\${out}"
elif [ "\${out%.md5}" != "\${out}" ]; then
   printf '%s\n' "\${STUB_MD5_VALUE:-${good_md5}}" > "\${out}"
fi
CURL_STUB
chmod +x -- "${stub_bin}/curl"

## Run the downloader in a fresh consumer cwd; echoes the pin file if $1 given.
run_download() {
   local pin_value="$1" md5_override="$2"
   local cwd rc=0
   cwd="$(mktemp --directory -- "${work_dir}/consumer.XXXXXX")"
   if [ -n "${pin_value}" ]; then
      printf '%s\n' "${pin_value}" > "${cwd}/.coverity-tool-sha256.expected"
   fi
   ( cd -- "${cwd}" && PATH="${stub_bin}:${PATH}" ALLOW_LOCAL=true \
        STUB_MD5_VALUE="${md5_override}" \
        COVERITY_TOKEN=tok COVERITY_PROJECT=org/example \
        bash -- "${downloader}" >"${cwd}/out.log" 2>&1 ) || rc=$?
   printf '%s\n' "${cwd}" "${rc}"
}

## ---- clean verify: correct md5 + matching sha256 pin -> exit 0 ------------
mapfile -t r < <(run_download "${good_sha256}" '')
if [ "${r[1]}" -ne 0 ]; then
   fail "a clean download+verify exited '${r[1]}', expected 0"
fi
if [ ! -x "${r[0]}/cov-analysis/bin/coverity" ]; then
   fail 'the tool was not extracted to cov-analysis/bin/coverity'
fi
if ! grep --quiet --fixed-strings -- 'sha256 hard-pin verified' "${r[0]}/out.log"; then
   fail 'the sha256 hard-pin was not reported as verified on a matching pin'
fi

## ---- sha256 mismatch -> fail closed ---------------------------------------
mapfile -t r < <(run_download '0000000000000000000000000000000000000000000000000000000000000000' '')
if [ "${r[1]}" -eq 0 ]; then
   fail 'a sha256 hard-pin MISMATCH did not fail closed (supply-chain gate open)'
fi

## ---- md5 mismatch -> fail --------------------------------------------------
mapfile -t r < <(run_download "${good_sha256}" 'deadbeefdeadbeefdeadbeefdeadbeef')
if [ "${r[1]}" -eq 0 ]; then
   fail 'an md5 mismatch did not fail the download'
fi

## ---- absent pin -> md5-only, warning, exit 0 ------------------------------
mapfile -t r < <(run_download '' '')
if [ "${r[1]}" -ne 0 ]; then
   fail "an absent sha256 pin did not fall back to md5-only success (rc '${r[1]}')"
fi
if ! grep --quiet --fixed-strings -- 'only md5 was verified' "${r[0]}/out.log"; then
   fail 'an absent pin did not warn that only md5 was verified'
fi

## ---- CRLF pin file: a trailing CR must not fail the compare closed --------
crlf_cwd="$(mktemp --directory -- "${work_dir}/consumer.XXXXXX")"
printf '%s\n' "${good_sha256}"$'\r' > "${crlf_cwd}/.coverity-tool-sha256.expected"
crlf_rc=0
( cd -- "${crlf_cwd}" && PATH="${stub_bin}:${PATH}" ALLOW_LOCAL=true \
   STUB_MD5_VALUE='' COVERITY_TOKEN=tok COVERITY_PROJECT=org/example \
   bash -- "${downloader}" >"${crlf_cwd}/out.log" 2>&1 ) || crlf_rc=$?
if [ "${crlf_rc}" -ne 0 ]; then
   fail "a CRLF sha256 pin failed the compare closed (rc '${crlf_rc}')"
fi
if ! grep --quiet --fixed-strings -- 'sha256 hard-pin verified' "${crlf_cwd}/out.log"; then
   fail 'a CRLF pin did not verify (trailing CR not stripped)'
fi

## ---- CI guard: refuses without CI or ALLOW_LOCAL --------------------------
guard_rc=0
( cd -- "${work_dir}" && env -u CI -u ALLOW_LOCAL PATH="${stub_bin}:${PATH}" \
   COVERITY_TOKEN=tok COVERITY_PROJECT=org/example \
   bash -- "${downloader}" ) >/dev/null 2>&1 || guard_rc=$?
if [ "${guard_rc}" -ne 1 ]; then
   fail "did not refuse outside CI without ALLOW_LOCAL (rc '${guard_rc}', expected 1)"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "coverity-download-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'coverity-download-test: all checks passed'
