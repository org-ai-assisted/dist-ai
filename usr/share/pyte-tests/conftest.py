#!/usr/bin/python3 -Bsu

"""Make this suite's shared helper modules importable.

pytest runs these files with ``--import-mode=importlib``, which deliberately
keeps the test directory off ``sys.path``; without this the sibling
``pyte_audit_fixes`` helper would not resolve.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
