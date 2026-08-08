#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generates task 03's audit golden files from the reference Python.

Usage: python3 scripts/gen_golden_audit.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "reference"))

import srxaudit  # noqa: E402

FIXTURES = [
    "sample.xml",
    "sample2.txt",
    "sample-show-config.txt",
    "sample-display-set.txt",
]


def build(path):
    m, units, screens, zones, policies = srxaudit.parse(path)
    F = []
    srxaudit.check_policies(zones, policies, F)
    srxaudit.check_zones(zones, screens, F)
    if m["system"] is not None:
        srxaudit.check_system(m["system"], m["snmp"], F)
    return srxaudit.build_findings_json(F)


def main():
    outdir = os.path.join(ROOT, "testdata", "golden")
    os.makedirs(outdir, exist_ok=True)
    for name in FIXTURES:
        path = os.path.join(ROOT, "testdata", "fixtures", name)
        out = os.path.join(outdir, "audit-%s.json" % name)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(build(path), fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        print("written:", os.path.relpath(out, ROOT))


if __name__ == "__main__":
    main()
