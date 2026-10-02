#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pin that tirdad loads its kernel module via a SecureBoot-tolerant mechanism,
## not via the strict /usr/lib/modules-load.d/ entry.
##
## WHY this exists: the tirdad module is unsigned and out-of-tree, so under
## Secure Boot (without an enrolled DKMS MOK) the kernel rejects it ("Key was
## rejected by service"). The old packaging listed the module in
## /usr/lib/modules-load.d/30_tirdad.conf, which is processed by the STRICT
## systemd-modules-load.service: one module there that fails to load fails the
## WHOLE service, marking the system degraded. That is NOT ignorable at the
## release gate (systemd-modules-load also loads jitterentropy_rng via
## security-misc's 30_security-misc.conf, so a unit-wide ignore would mask a
## real shipped-module load regression). The operator accepts tirdad being
## absent under Secure Boot, but the system must not go degraded on its account.
##
## The fix: drop the modules-load.d entry and ship a dedicated oneshot
## tirdad-load.service whose ExecStart is prefixed with "-", so a failed
## modprobe (Secure Boot rejection) is non-fatal and the unit stays successful.
## The load is still ATTEMPTED every boot, so tirdad loads normally and under
## Secure Boot when the MOK is enrolled -- only genuine rejection is tolerated.
## Ordering places the modprobe AFTER systemd-modules-load.service and BEFORE
## security-misc's harden-module-loading.service (which sets
## kernel.modules_disabled=1); if it ran after that lockdown, even a loadable
## module would fail. The positive-load guarantee on a normal (non-SB) boot is
## kept by systemcheck's check_tirdad_module (crit when tirdad is absent and
## Secure Boot is off) and exercised end-to-end by the dm-image-boot release
## gate; this unit test pins the packaging that makes that behavior possible.
##
## Source-tree test: set TIRDAD_REPO or run from a checkout; exits 1 (FATAL)
## when the tirdad tree is absent -- a required subject absent is an environment
## bug (R-220). Its required tooling (systemd-analyze) is assumed present -- an
## absent one FAILS, it does not skip: "an unauthorized skip is a failure, not
## green".

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${TIRDAD_REPO:-}"
if [ -z "${repo}" ]; then
   ## usr/share/tirdad-tests/<this> -> candidate is the tirdad checkout only
   ## when run straight from a tirdad tree (not the dist-ai monorepo). The
   ## dist-ai orchestrator always wires TIRDAD_REPO, so this fallback only aids
   ## a direct invocation from within a tirdad checkout's own copy.
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/debian/tirdad-dkms.install" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi
if [ -z "${repo}" ] || [ ! -f "${repo}/debian/tirdad-dkms.install" ]; then
   printf '%s\n' 'FATAL: tirdad-modules-load-tolerance-test: no tirdad source tree (set TIRDAD_REPO).' >&2
   exit 1
fi

if ! type -P systemd-analyze >/dev/null; then
   printf '%s\n' 'FAIL: tirdad-modules-load-tolerance-test: systemd-analyze (systemd) not on PATH; the gate cannot run' >&2
   exit 1
fi

service_file="${repo}/debian/tirdad-dkms.tirdad-load.service"
rules_file="${repo}/debian/rules"
modprobe_conf="${repo}/debian/30-tirdad.conf"

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $1"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $1"
}

## --- helpers -----------------------------------------------------------------

## Non-comment, non-blank install lines across ALL binary packages' .install
## files (tirdad AND tirdad-dkms): debhelper's filedoublearray drops lines whose
## first non-space char is '#', so a comment mentioning a path installs nothing.
## Scanning every *.install closes the "other binary re-ships the strict loader"
## gap.
install_lines() {
   local f
   for f in "${repo}"/debian/*.install; do
      [ -f "${f}" ] || continue
      sed -e 's/^[[:space:]]*//' -e '/^#/d' -e '/^[[:space:]]*$/d' "${f}"
   done
}

## Body of a single [Section] in a unit file (lines until the next [Header]).
section_body() {
   awk -v want="$2" '
      /^[[:space:]]*\[/ {
         h=$0; sub(/^[[:space:]]*\[/,"",h); sub(/\][[:space:]]*$/,"",h)
         insec=(h==want); next
      }
      insec { print }
   ' "$1"
}

## True iff, within <section>, some <key>= line lists <token> as a whole
## whitespace-separated value (systemd allows several units per directive).
## Literal compare, so 'sysinit.target' never matches 'sysinit-target' and the
## directive must sit in the RIGHT section (a 'Before=' in [Install] is ignored
## by systemd and must not satisfy the check).
directive_has_token() {
   local file="$1" section="$2" key="$3" token="$4"
   section_body "${file}" "${section}" | awk -v key="${key}" -v tok="${token}" '
      { line=$0; sub(/^[[:space:]]+/,"",line)
        eq=index(line,"="); if(eq==0) next
        k=substr(line,1,eq-1); sub(/[[:space:]]+$/,"",k); if(k!=key) next
        v=substr(line,eq+1); n=split(v,a,/[[:space:]]+/)
        for(i=1;i<=n;i++) if(a[i]==tok) found=1 }
      END{ exit found?0:1 }'
}

## Collected once; here-strings below avoid a quiet grep on a pipe (R-161).
install_out="$(install_lines)"

## --- 1. The strict modules-load.d mechanism is GONE (all binary packages) ---
## Both the source config and any install INTO modules-load.d, across every
## binary, are the exact packaging that degrades systemd-modules-load under SB.
## nullglob drops a non-matching WILDCARD, but a literal path with no wildcard
## (30_tirdad.conf) survives even when absent -- so test each candidate with -e.
shopt -s nullglob
stale_modules_load=()
for cand in "${repo}"/debian/*modules-load*.conf "${repo}"/debian/30_tirdad.conf; do
   [ -e "${cand}" ] && stale_modules_load+=( "${cand}" )
done
shopt -u nullglob
if [ "${#stale_modules_load[@]}" -ne 0 ]; then
   fail "a strict modules-load.d source config is still present (${stale_modules_load[*]##*/}) -- it degrades systemd-modules-load under Secure Boot"
else
   pass 'no strict modules-load.d source config in debian/'
fi

if grep --quiet --fixed-strings -- 'modules-load.d' <<< "${install_out}"; then
   fail "a debian/*.install still ships into modules-load.d -- the strict loader must be gone from every binary package"
else
   pass 'no debian/*.install ships anything into modules-load.d'
fi

## --- 2. The tolerant load service is shipped ---
if [ -f "${service_file}" ]; then
   pass 'tirdad-load.service shipped (debian/tirdad-dkms.tirdad-load.service)'
else
   fail 'debian/tirdad-dkms.tirdad-load.service missing -- no tolerant load mechanism'
   ## The remaining service-content checks cannot run without the file.
   printf '%s\n' "Result: ${pass_count} pass, ${fail_count} fail, 0 skip"
   [ "${fail_count}" -eq 0 ]
   exit
fi

## --- 2b. The packaging actually INSTALLS the unit ---
## The unit is named debian/<binpkg>.<name>.service. dh_installsystemd ignores
## that form unless invoked with --name <name>: without it, it only looks for
## debian/<binpkg>.service and ships NOTHING, silently leaving no boot-time load
## mechanism. So shipping the file in debian/ is NOT enough -- the install
## mechanism must reference it. Accept either the dh_installsystemd --name hook
## (derived from the unit's own filename) or an explicit .install entry.
## Matches the standard single-line forms 'dh_installsystemd ... --name<sep>NAME'
## (space or '=' separator, any other options between) in a NON-comment rules
## line, or an explicit .install entry shipping NAME.service into a SYSTEM unit
## dir (systemd/system, not systemd/user). Comments are stripped on both sides so
## a '# dh_installsystemd --name ...' does not count. (A line-continuation recipe
## or a dh-exec rename would need a test update -- out of scope here.)
service_basename="$(basename -- "${service_file}")"           # <binpkg>.<name>.service
unit_name="${service_basename%.service}"                      # <binpkg>.<name>
unit_name="${unit_name##*.}"                                  # <name>
unit_name_re="${unit_name//./\\.}"
rules_noncomment="$(sed -e 's/^[[:space:]]*//' -e '/^#/d' "${rules_file}")"
if grep --extended-regexp --quiet "dh_installsystemd.*--name(=|[[:space:]]+)${unit_name_re}([[:space:]]|=|\$)" <<< "${rules_noncomment}" \
   || grep --extended-regexp --quiet "(^|/)${unit_name_re}\.service[[:space:]].*/systemd/system(/|[[:space:]]|\$)" <<< "${install_out}"; then
   pass "the packaging installs ${unit_name}.service (dh_installsystemd --name or .install)"
else
   fail "nothing installs ${unit_name}.service: debian/rules lacks 'dh_installsystemd --name ${unit_name}' and no .install ships it into a system unit dir -- dh would ignore debian/${service_basename} and the unit would be absent"
fi

## --- 3. The tirdad load is failure-TOLERANT, and nothing loads it strictly ---
## Every ExecStart=/ExecStartPre= that loads tirdad must carry systemd's "-"
## tolerance prefix. A single strict one (no "-") fails the oneshot on Secure
## Boot rejection -- the regression this guards. The module name is anchored so
## a typo'd 'modprobe tirdad_other' (loads the wrong module) is NOT accepted, and
## an explicit 'modprobe -- tirdad' IS.
exec_verdict="$(section_body "${service_file}" Service | awk '
   function loads_tirdad(cmd,   n,a,i,seen) {
      n=split(cmd,a,/[[:space:]]+/); seen=0
      for(i=1;i<=n;i++){
         if(a[i] ~ /(^|\/)modprobe$/){ seen=1; continue }
         if(seen){ if(a[i]=="--") continue
                   if(a[i]=="tirdad") return 1
                   if(a[i] !~ /^-/) return 0 }      # a different module name
      }
      return 0
   }
   { line=$0; sub(/^[[:space:]]+/,"",line)
     eq=index(line,"="); if(eq==0) next
     k=substr(line,1,eq-1); sub(/[[:space:]]+$/,"",k)
     if(k!="ExecStart" && k!="ExecStartPre") next
     v=substr(line,eq+1); sub(/^[[:space:]]+/,"",v)
     tol=0
     while(match(v,/^[-@+!:]/)){ if(substr(v,1,1)=="-") tol=1; v=substr(v,2) }
     if(loads_tirdad(v)){ total++; if(tol) tolerant++; else strict++ } }
   END{ printf "%d %d %d", total+0, tolerant+0, strict+0 }')"
read -r ev_total ev_tol ev_strict <<< "${exec_verdict}"
if [ "${ev_total}" -ge 1 ] && [ "${ev_strict}" -eq 0 ] && [ "${ev_tol}" -ge 1 ]; then
   pass 'every ExecStart/ExecStartPre that loads tirdad uses the failure-tolerant "-" prefix'
else
   fail "tirdad load is not uniformly failure-tolerant (loaders=${ev_total} tolerant=${ev_tol} strict=${ev_strict}) -- a strict one degrades on Secure Boot rejection"
fi

## --- 4. Ordering (section-aware): AFTER modules-load, BEFORE the lockdown ---
check_directive() {
   local section="$1" key="$2" token="$3" why="$4"
   if directive_has_token "${service_file}" "${section}" "${key}" "${token}"; then
      pass "[${section}] ${key}=...${token}... (${why})"
   else
      fail "missing '${key}=${token}' in [${section}] -- ${why}"
   fi
}
check_directive Unit After systemd-modules-load.service 'run after the strict modules-load has settled'
check_directive Unit Before systemd-sysctl.service 'load before the network stack (net units are After=systemd-sysctl.service)'
check_directive Unit Before harden-module-loading.service 'load tirdad BEFORE security-misc sets kernel.modules_disabled=1'
check_directive Unit Before lkrg.service 'load before LKRG baselines the kernel, or LKRG panics on the livepatch'
check_directive Unit Before sysinit.target 'load during early boot'
check_directive Install WantedBy sysinit.target 'the unit is actually pulled into the boot transaction'

## --- 5. The modprobe.d softdep drop-in is still shipped ---
## LKRG load-order is primarily guaranteed by Before=lkrg.service above; this
## pre-existing softdep is the secondary (modprobe-path) guarantee. Assert the
## drop-in still ships a 'softdep <module> pre: ... tirdad' (tirdad as a
## pre-dependency) and is installed to /etc/modprobe.d.
softdep_ok() {
   awk '/^[[:space:]]*softdep[[:space:]]+[^[:space:]]+[[:space:]]+pre:/ {
           p=index($0,"pre:"); rest=substr($0,p+4); n=split(rest,a,/[[:space:]]+/)
           for(i=1;i<=n;i++) if(a[i]=="tirdad") ok=1 }
        END{ exit ok?0:1 }' "$1"
}
if [ -f "${modprobe_conf}" ] \
   && softdep_ok "${modprobe_conf}" \
   && grep --quiet --fixed-strings -- 'etc/modprobe.d/' <<< "${install_out}"; then
   pass 'the modprobe.d softdep pre-loading tirdad is shipped to /etc/modprobe.d'
else
   fail 'the /etc/modprobe.d softdep pre-loading tirdad is no longer shipped'
fi

## --- 6. systemd accepts the unit (own-unit errors are fatal) ---
## --recursive-errors=no makes systemd-analyze return non-zero on THIS unit's own
## problems (e.g. a directive in the wrong section -> "Unknown key ... ignoring")
## while not failing on warnings from unrelated pulled-in dependency units. The
## default (no flag) returns 0 even when the unit has such warnings -- a false
## PASS. Run on a COPY in an isolated dir so the filename is the unit name.
verify_dir="$(mktemp --directory)"
cleanup_verify_dir() {
   safe-rm --recursive --force -- "${verify_dir}" || true
}
trap cleanup_verify_dir EXIT
cp -- "${service_file}" "${verify_dir}/tirdad-load.service"
if systemd-analyze verify --recursive-errors=no "${verify_dir}/tirdad-load.service" 2>"${verify_dir}/verify.err"; then
   pass 'systemd-analyze verify (--recursive-errors=no) accepts tirdad-load.service'
else
   fail "systemd-analyze verify rejects tirdad-load.service: $(cat "${verify_dir}/verify.err")"
fi

printf '%s\n' "Result: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
