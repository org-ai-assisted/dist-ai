#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Print the largest contiguous run of pure-background rows in an image.

A tight shot has no band of dead space: the longest run of rows entirely equal
to the top-left (background) pixel is just the frame margin plus small
inter-element gaps. A dead-space regression (a review pane's reserved empty
height, or a stray scrollbar band) blows far past that. shot_generators_smoke_test.sh
reads this number and asserts it stays small.

QImage loads a PNG with no QApplication, so this is a plain metric, not a GUI.

    largest_bg_row_run.py <image.png>
"""

import sys

from PyQt6.QtGui import QImage


def largest_bg_row_run(path):
    image = QImage(path)
    if image.isNull():
        raise SystemExit('largest_bg_row_run: cannot read %s' % path)
    width, height = image.width(), image.height()
    background = image.pixel(0, 0)
    best = current = 0
    for y in range(height):
        if all(image.pixel(x, y) == background for x in range(width)):
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def main(argv):
    if len(argv) != 2:
        sys.stderr.write('usage: largest_bg_row_run.py <image.png>\n')
        return 2
    print(largest_bg_row_run(argv[1]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
