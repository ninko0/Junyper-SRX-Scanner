#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generates task 01's golden files from the reference Python.

The Go model (`internal/config.Model`) is the UNION of the two Python
models: `srxtool.parse_config()`'s (units/vlans/zones/global_books/policies)
and `srxaudit.parse()`'s (system_services/protocols/screen/public per zone,
+ screens + logs per policy). This script redoes the same union on the
Python side and serializes the result with exactly the same JSON keys, so
that the `TestGoldenModelAllFixtures` test can compare field by field.

Usage (from the repo root, with reference/ and testdata/fixtures/):

    python3 scripts/gen_golden_model.py

Only rerun this if the reference Python's behavior changes — which, by
this project's definition, shouldn't happen anymore.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "reference"))

import srxtool   # noqa: E402
import srxaudit  # noqa: E402

FIXTURES = [
    "sample.xml",
    "sample2.txt",
    "sample-show-config.txt",
    "sample-display-set.txt",
]


def build(path):
    model = srxtool.parse_config(path)
    _m, _units, screens, azones, apolicies = srxaudit.parse(path)

    for zn, z in model["zones"].items():
        az = azones.get(zn, {})
        z["system_services"] = az.get("system_services", [])
        z["protocols"] = az.get("protocols", [])
        z["screen"] = az.get("screen")
        z["public"] = bool(az.get("public", False))

    # `logs` (srxaudit) and `flags` (srxtool) describe the same `then`
    # stanza in two forms; policies are produced in the same order by
    # both parsers, so pairing by index is exact.
    for i, p in enumerate(model["policies"]):
        p["logs"] = apolicies[i]["logs"] if i < len(apolicies) else []

    model["screens"] = sorted(screens)
    return model


def main():
    outdir = os.path.join(ROOT, "testdata", "golden")
    os.makedirs(outdir, exist_ok=True)
    for name in FIXTURES:
        path = os.path.join(ROOT, "testdata", "fixtures", name)
        model = build(path)
        out = os.path.join(outdir, "model-%s.json" % name)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(model, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        print("written:", os.path.relpath(out, ROOT))


if __name__ == "__main__":
    main()
