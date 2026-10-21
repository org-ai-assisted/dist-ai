#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards test-results-deploy's SERIALIZATION lock. site-generate rewrites the whole Pages
## repo in place while site-deploy's website-tests then decodes every image there; two
## overlapping runs (the hourly timer + a manual run) let one run's regenerate rewrite a
## file mid-decode in the other's gate -- a partial read surfaces as a spurious
## "undecodable/corrupt image" that falsely blocks publish (observed: a different, VALID
## webp flagged each concurrent run). The fix is an exclusive flock on the Pages repo held
## for the whole run.
##
## Drives the REAL test-results-deploy (no copy) with a stub `sandbox` whose `pull` records
## START/END around a sleep then exits non-zero, so the script dies right after the
## lock-protected pull without reaching the heavy generator. Two instances run concurrently;
## the lock must serialize them, so at no point are two inside the pull at once.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
deploy="${script_dir}/../../bin/test-results-deploy"
[ -x "${deploy}" ] || deploy='/usr/bin/test-results-deploy'
if [ ! -x "${deploy}" ]; then
   printf '%s\n' "test-results-deploy not found" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass(){ printf '%s\n' "PASS: $1"; pass_count=$(( pass_count + 1 )); }
fail(){ printf '%s\n' "FAIL: $1" >&2; fail_count=$(( fail_count + 1 )); }

work="$(mktemp --directory)"
cleanup(){
   # shellcheck disable=SC2317  # invoked indirectly via the EXIT trap
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## A throwaway Pages repo the way test-results-deploy validates it: a git checkout holding
## automated-test-results/ and an index.html.
pages="${work}/pages"
mkdir --parents -- "${pages}/automated-test-results"
git -c init.defaultBranch=master -C "${pages}" init --quiet
printf '%s\n' '<!doctype html><title>t</title>' > "${pages}/index.html"

## Stub sandbox: on `pull`, bracket a sleep with START/END markers (so overlap is visible),
## then exit non-zero so the real script dies at `|| die` right after the lock-held pull --
## the generator / site-deploy are never reached. Any other sandbox call is a no-op.
bin="${work}/bin"
mkdir --parents -- "${bin}"
marker="${work}/marker"
touch -- "${marker}"
cat > "${bin}/sandbox" <<STUB
#!/bin/bash
for a in "\$@"; do
   if [ "\$a" = 'pull' ]; then
      printf '%s\n' "START \$\$" >> "${marker}"
      sleep 2
      printf '%s\n' "END \$\$" >> "${marker}"
      exit 1
   fi
done
exit 0
STUB
chmod +x "${bin}/sandbox"
## site-deploy only has to satisfy the pre-lock `command -v` check; it is never reached.
printf '%s\n' '#!/bin/bash' 'exit 0' > "${bin}/site-deploy"
chmod +x "${bin}/site-deploy"

run_instance(){
   PATH="${bin}:${PATH}" \
   TEST_RESULTS_DEPLOY_TARGET='stub' \
   TEST_RESULTS_PAGES_REPO="${pages}" \
   TEST_RESULTS_REMOTE='/var/www/results' \
      "${deploy}" >/dev/null 2>&1 || true
}

## Launch two concurrently; both pass validation and contend for the lock.
run_instance &
p1=$!
run_instance &
p2=$!
wait "${p1}" "${p2}"

## Both instances must have entered the pull (two START lines) -- else the test proved nothing.
starts="$(grep -c '^START ' "${marker}" || true)"
if [ "${starts}" -eq 2 ]; then
   pass 'both instances reached the lock-protected pull (test is meaningful)'
else
   fail "expected 2 pull attempts, saw ${starts}"
   sed 's/^/    | /' "${marker}" >&2
fi

## Serialization: scanning the marker in order, the count of open (START without END) pulls
## must NEVER exceed 1. Two at once (max 2) is the unlocked bug this guards.
max_open="$(awk '
   /^START /{open++; if(open>max)max=open}
   /^END /{open--}
   END{print max+0}
' "${marker}")"
if [ "${max_open}" -eq 1 ]; then
   pass 'lock serialized the runs (never two inside the pull at once)'
else
   fail "runs overlapped inside the pull (max concurrent = ${max_open}) -- lock missing/broken"
   sed 's/^/    | /' "${marker}" >&2
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
