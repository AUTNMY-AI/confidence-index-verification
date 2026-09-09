"""Kind is a sealed leaf field and must be read from cells.json.

Regression: build_confidence_leaf always hashed kind=\"confidence\", and
_ordered_leaf_bytes never passed the published cell's kind through. Editing
kind in a published cycle still produced the original Merkle root and
verify-cycle reported VERIFIED.
"""
from __future__ import annotations

import copy
import unittest

from confidence_verification import merkle as M
from confidence_verification.cli import LEAF_KIND, _ordered_leaf_bytes, build_confidence_leaf


def _cell(**overrides):
    cell = {
        "index": "robotaxi",
        "methodology_version": "robotaxi-1.3",
        "headline": "49.7",
        "band": "Constructive",
        "pillars": {"capability": "37.2", "commercial": "62.5"},
        "source_snapshot": "snap-2026-08-11T06:01Z",
        "computed_at_utc": "2026-08-11T06:01:00Z",
        "cadence": "12h",
        "kind": "confidence",
    }
    cell.update(overrides)
    return cell


def _root(cells_doc):
    leaf_bytes, _ = _ordered_leaf_bytes(cells_doc)
    return M.merkle_root(leaf_bytes)


class KindIsSealed(unittest.TestCase):
    def test_published_kind_is_hashed_into_the_leaf(self):
        clean = {"cells": [_cell()]}
        tampered = {"cells": [_cell(kind="indices")]}
        self.assertNotEqual(_root(clean), _root(tampered))

    def test_missing_kind_defaults_to_confidence(self):
        with_field = {"cells": [_cell(kind="confidence")]}
        omitted = {"cells": [_cell()]}
        del omitted["cells"][0]["kind"]
        self.assertEqual(_root(with_field), _root(omitted))

    def test_leaf_carries_the_published_kind(self):
        _, leaves = _ordered_leaf_bytes({"cells": [_cell(kind="indices")]})
        self.assertEqual(leaves[0]["kind"], "indices")
        self.assertEqual(
            leaves[0],
            build_confidence_leaf(
                index="robotaxi",
                methodology_version="robotaxi-1.3",
                headline="49.7",
                band="Constructive",
                pillars={"capability": "37.2", "commercial": "62.5"},
                source_snapshot="snap-2026-08-11T06:01Z",
                computed_at_utc="2026-08-11T06:01:00Z",
                cadence="12h",
                kind="indices",
            ),
        )

    def test_default_kind_constant_is_confidence(self):
        self.assertEqual(LEAF_KIND, "confidence")

    def test_multi_cell_kind_edit_does_not_preserve_root(self):
        clean = {
            "cells": [
                _cell(index="robotaxi", headline="49.7"),
                _cell(index="trucks", headline="40.1"),
            ]
        }
        tampered = copy.deepcopy(clean)
        tampered["cells"][1]["kind"] = "indices"
        self.assertNotEqual(_root(clean), _root(tampered))


if __name__ == "__main__":
    unittest.main()
