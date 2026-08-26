#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive the REAL 'main' + 'export-libvirt-xml' of
## build-steps.d/1600_export-libvirt-xml (path in argv 1), with the build
## environment stubbed:
##   error  -> report on stderr and exit 1, exactly as help-steps/pre's does
##   cp     -> announce the copy instead of performing it, so a case can assert
##             that the step DID reach the copy
##
## The inputs the step reads come from the environment, so a case is expressed by
## what the caller exports: $dist_build_source_run, $dist_build_raw,
## $dist_build_qcow2, $libvirt_source_kvm_file, $dist_build_flavor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

step_file="$1"

error() {
   printf '%s\n' "$*" >&2
   exit 1
}

cp() {
   printf '%s\n' "STUB-CP: $*"
}

## The step colourizes its skip messages from variables set in help-steps/pre.
green=""
reset=""

## Extract the two functions rather than sourcing the file: its top level does a
## 'cd' into help-steps and sources 'pre' and 'variables', which pull in the whole
## build environment. Under test are the gating and the precondition, so the
## functions are driven directly and everything they call is stubbed above.
body="$( sed -n -e '/^export-libvirt-xml()/,/^}/p' -e '/^main()/,/^}/p' -- "${step_file}" )"
if [ -z "${body}" ]; then
   printf '%s\n' "${0##*/}: could not extract export-libvirt-xml / main from '${step_file}'." >&2
   exit 2
fi
eval "${body}"

## Verify the extraction produced BOTH, so a rename upstream fails here rather
## than leaving a case that exercises nothing.
for extracted_function in export-libvirt-xml main; do
   if ! declare -F "${extracted_function}" >/dev/null; then
      printf '%s\n' "${0##*/}: '${extracted_function}' not defined after extraction from '${step_file}'." >&2
      exit 2
   fi
done

main
