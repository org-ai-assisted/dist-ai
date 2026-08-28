#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Compare the INPUTS recorded in two '.dm-buildinfo' records.
##
## WHY THIS IS SEPARATE FROM COMPARING THE IMAGES: two images that differ tell
## you nothing until you know they were built from the same inputs. A local build
## and a CI build of "the same commit" can still differ in the submodule commits
## that commit resolved to, in the APT snapshot, or in SOURCE_DATE_EPOCH -- and a
## byte difference then proves only that the inputs differed. Reporting that as a
## reproducibility failure is worse than useless: it sends someone hunting a
## nondeterminism bug that is not there.
##
## So the inputs are compared FIRST, and a mismatch is its own outcome.
##
## Usage: dm-buildinfo-compare.py A.dm-buildinfo B.dm-buildinfo
##
## Exit: 0 every input field matches | 3 at least one differs | 2 unreadable.
##       Differing fields are printed, one per line, as
##       '<field>: A=<value> B=<value>'.

import sys

## The fields that DETERMINE the output. A difference in any of these makes a
## byte comparison meaningless.
##
## 'Submodule-State' is the one this whole exercise turned on: a commit does not
## pin its submodules when they are checked out to a moving branch tip, so two
## builds of the same Source-Commit can legitimately carry different submodule
## SHAs -- and nothing recorded that until the source-state work landed.
INPUT_FIELDS = (
    'Source-Commit',
    'Submodule-State',
    'Source-Version',
    'Flavor',
    'Target',
    'Build-Type',
    'Architecture',
    'Freedom',
    'Debian-Suite',
    'APT-Snapshot',
    'Source-Date-Epoch',
)

## Recorded, but NOT inputs: the repo URL is provenance, the file name is derived
## from fields already compared, and the format markers describe the record
## itself. Listing them explicitly keeps an unknown NEW field from being silently
## ignored -- see the unknown-field check below.
INFORMATIONAL_FIELDS = (
    'Format',
    'Buildinfo-Type',
    'Source-Repo',
    'Image-File',
)


def parse(path):
    """Deb822 into {field: value}, with continuation lines folded in.

    A continuation line (leading space) belongs to the field above it, which is
    how Submodule-State carries one entry per submodule.
    """
    fields = {}
    order = []
    current = None
    with open(path, encoding='utf-8') as handle:
        for raw in handle:
            line = raw.rstrip('\n')
            if not line:
                ## The record terminator. Anything after it is a second
                ## paragraph, which a well-formed buildinfo does not have.
                break
            if line[0] in ' \t':
                if current is None:
                    raise ValueError(
                        '%s: continuation line before any field' % path)
                fields[current] += '\n' + line
                continue
            name, separator, value = line.partition(':')
            if not separator:
                raise ValueError('%s: not a Deb822 field: %r' % (path, line))
            current = name.strip()
            if current in fields:
                raise ValueError('%s: duplicate field %r' % (path, current))
            fields[current] = value.strip()
            order.append(current)
    return fields, order


def main():
    if len(sys.argv) != 3:
        print('usage: dm-buildinfo-compare.py A.dm-buildinfo B.dm-buildinfo',
              file=sys.stderr)
        return 2
    try:
        a_fields, a_order = parse(sys.argv[1])
        b_fields, b_order = parse(sys.argv[2])
    except (OSError, ValueError) as exc:
        print('dm-buildinfo-compare: %s' % exc, file=sys.stderr)
        return 2

    if not a_fields or not b_fields:
        print('dm-buildinfo-compare: an empty record cannot be compared',
              file=sys.stderr)
        return 2

    ## A field present in EITHER record but in NEITHER list is new, and silently
    ## ignoring it would let a future input drift without anyone noticing. Both
    ## orders are scanned: a field present only in the B record is just as
    ## unclassified, and scanning A alone leaves a B-only field uncompared.
    known = set(INPUT_FIELDS) | set(INFORMATIONAL_FIELDS)
    unknown = [name for name in dict.fromkeys(a_order + b_order)
               if name not in known]
    if unknown:
        print('dm-buildinfo-compare: unclassified field(s) %s -- add them to '
              'INPUT_FIELDS or INFORMATIONAL_FIELDS; an unclassified field is '
              'not compared, so a difference in it would go unreported'
              % ', '.join(unknown), file=sys.stderr)
        return 2

    differing = []
    for name in INPUT_FIELDS:
        a_value = a_fields.get(name)
        b_value = b_fields.get(name)
        if a_value is None and b_value is None:
            ## Absent from BOTH: an older record predating the field. Not a
            ## difference, but say so rather than passing over it.
            print('dm-buildinfo-compare: NOTE: %s absent from both records'
                  % name, file=sys.stderr)
            continue
        if a_value != b_value:
            differing.append((name, a_value, b_value))

    if not differing:
        return 0
    for name, a_value, b_value in differing:
        print('%s: A=%r B=%r' % (name, a_value, b_value))
    return 3


if __name__ == '__main__':
    sys.exit(main())
