#!/bin/bash

## Adversarial test for git-meld's submodule-gitlink diff path.
## Question: can a REAL submodule pointer change ever be rendered as EMPTY
## output (hidden from the reviewer)? A diff/review tool must never do that.
##
## Runs entirely locally on throwaway repos with SAFE payloads. Stubs 'meld'
## so nothing tries to open a GUI. Takes the git-meld under test as $1.

set -o errexit
set -o nounset
set -o pipefail

GIT_MELD="$(readlink -f -- "${1:?usage: run-adversarial.sh /path/to/git-meld}")"
work="$(mktemp -d)"
export HOME="${work}/home"; mkdir -p "${HOME}"
git config --global user.email t@example.com >/dev/null 2>&1 || true
git config --global user.name test >/dev/null 2>&1 || true
git config --global protocol.file.allow always >/dev/null 2>&1 || true
git config --global init.defaultBranch master >/dev/null 2>&1 || true

## Stub 'meld' -> just record that it was asked to show something.
mkdir -p "${work}/bin"
printf '%s\n' '#!/bin/bash' 'printf "MELD-CALLED: %s\n" "$*"' > "${work}/bin/meld"
chmod +x "${work}/bin/meld"
export PATH="${work}/bin:${PATH}"

## Build a submodule repo 'sub' with two real commits A and B.
sub="${work}/sub"; git init -q "${sub}"; ( cd "${sub}"
  printf 'v1\n' > f.txt; git add f.txt; git commit -qm A
  printf 'v2\n' > f.txt; git add f.txt; git commit -qm B )
A="$(git -C "${sub}" rev-parse HEAD~1)"
B="$(git -C "${sub}" rev-parse HEAD)"
## A plausible-looking but ABSENT commit id (models an unfetched submodule commit).
ABSENT="0123456789abcdef0123456789abcdef01234567"

## Craft the two "Subproject commit" blob temp files git would hand the driver.
blob() { printf 'Subproject commit %s\n' "$1" > "${work}/blob_$2"; printf '%s' "${work}/blob_$2"; }

## Invoke git-meld exactly as git invokes an external diff driver for a gitlink
## change: driver mode (GIT_DIFF_PATH_TOTAL set), 7 positional args
##   path old-file old-hex old-mode new-file new-hex new-mode
## diff_path is the submodule working tree (here: 'sub').
run_case () {
  local name old_commit new_commit oldf newf out rc
  name="$1"; old_commit="$2"; new_commit="$3"
  oldf="$(blob "${old_commit}" old)"; newf="$(blob "${new_commit}" new)"
  set +e
  out="$( cd "${work}" && GIT_DIFF_PATH_TOTAL=1 "${GIT_MELD}" \
            "sub" "${oldf}" "${old_commit}" 160000 "${newf}" "${new_commit}" 160000 2>&1 )"
  rc=$?
  set -e
  ## Does the output reveal that a change happened (either commit id shown, or a
  ## loud warning), or is it hidden (nothing that names old/new, no warning)?
  local visible="no"
  if printf '%s' "${out}" | grep -qiE "warn|error|cannot|not (present|available|fetched)|${old_commit:0:12}|${new_commit:0:12}"; then
    visible="yes"
  fi
  printf '=== case: %s (%.12s -> %.12s) rc=%s ===\n' "${name}" "${old_commit}" "${new_commit}" "${rc}"
  printf '  output: %s\n' "$(printf '%s' "${out}" | tr '\n' '|' | cut -c1-200)"
  printf '  CHANGE VISIBLE TO REVIEWER: %s\n' "${visible}"
  if [ "${visible}" = "no" ]; then
    printf '  >>> FAIL: a real gitlink change was HIDDEN (empty/no-signal output)\n'
    return 1
  fi
  printf '  >>> ok: change is surfaced\n'
  return 0
}

fails=0
run_case "both-commits-present"  "${A}" "${B}"       || fails=$((fails+1))
run_case "NEW-commit-unfetched"  "${A}" "${ABSENT}"  || fails=$((fails+1))
run_case "OLD-commit-unfetched"  "${ABSENT}" "${B}"  || fails=$((fails+1))
run_case "BOTH-commits-unfetched" "${ABSENT}" "0000000000000000000000000000000000000000" || fails=$((fails+1))

printf '\n==== TOTAL HIDDEN-CHANGE FAILURES: %s ====\n' "${fails}"
rm -rf "${work}"
exit "${fails}"
