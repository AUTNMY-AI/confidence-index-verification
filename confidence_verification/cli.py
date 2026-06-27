"""
confidence-verify command line.

  confidence-verify verify-cycle DIR
      Recompute the snapshot root from DIR/cells.json and confirm it matches the
      anchored RFC 3161 token(s) DIR/root-*.tsr.

  confidence-verify verify-category DIR --index INDEX
      Confirm one Confidence Index reading belongs to that anchored root via its
      Merkle inclusion proof. INDEX is one of robotaxi, trucks, delivery_bots,
      licensing.

DIR is a folder holding a cycle's public files (cells.json, tree.json,
root-*.tsr), e.g. downloaded from a cycle's permalink under /verification/.

Everything is recomputed from cells.json (the published readings), NOT from
tree.json, so the tool never trusts our convenience files.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from typing import List, Optional, Tuple

from confidence_verification import canonical as C
from confidence_verification import merkle as M
from confidence_verification import anchor as A

LEAF_KIND = "confidence"


def build_confidence_leaf(*, index: str, methodology_version: str, headline,
                          band: str, pillars, source_snapshot: str,
                          computed_at_utc: str, cadence: str = C.CADENCE) -> dict:
    """Rebuild one canonical Confidence leaf from its published fields, exactly
    as the server sealed it. Any altered value changes the leaf and breaks the
    root: that is the tamper-detection property."""
    return {
        "kind": LEAF_KIND,
        "index": index,
        "methodology_version": methodology_version,
        "headline": C.format_score(headline),
        "band": band,
        "pillars": {str(name): C.format_score(v) for name, v in pillars.items()},
        "source_snapshot": source_snapshot,
        "cadence": cadence,
        "computed_at_utc": computed_at_utc,
    }


def _load(dir_path: str) -> Tuple[dict, Optional[dict]]:
    with open(os.path.join(dir_path, "cells.json")) as fh:
        cells = json.load(fh)
    tree = None
    tree_path = os.path.join(dir_path, "tree.json")
    if os.path.exists(tree_path):
        with open(tree_path) as fh:
            tree = json.load(fh)
    return cells, tree


def _ordered_leaf_bytes(cells_doc: dict) -> Tuple[List[bytes], List[dict]]:
    leaves = []
    for c in cells_doc["cells"]:
        leaf = build_confidence_leaf(
            index=c["index"],
            methodology_version=c["methodology_version"],
            headline=c["headline"],
            band=c["band"],
            pillars=c["pillars"],
            source_snapshot=c["source_snapshot"],
            computed_at_utc=c["computed_at_utc"],
            cadence=c.get("cadence", C.CADENCE),
        )
        leaves.append(leaf)
    leaves.sort(key=lambda lf: lf["index"])
    return [C.canonical_bytes(lf) for lf in leaves], leaves


def _tsr_files(dir_path: str) -> List[str]:
    return sorted(glob.glob(os.path.join(dir_path, "root-*.tsr")))


def verify_cycle(dir_path: str, trust_roots: Optional[List[str]] = None) -> bool:
    cells_doc, tree = _load(dir_path)
    leaf_bytes, _ = _ordered_leaf_bytes(cells_doc)
    root = M.merkle_root(leaf_bytes)
    root_hex = root.hex()
    print(f"recomputed snapshot_root: {root_hex}")
    print(f"leaf_count: {len(leaf_bytes)}  canonicalization: {cells_doc.get('canonicalization_version')}")

    ok = True
    if tree is not None:
        if tree.get("snapshot_root") != root_hex:
            print(f"  MISMATCH: tree.json root {tree.get('snapshot_root')} != recomputed")
            ok = False
        else:
            print("  tree.json root matches recomputed root")

    tsrs = _tsr_files(dir_path)
    if not tsrs:
        print("  NO external anchor file (root-*.tsr) present -> NOT verified")
        return False
    anchored = 0
    for path in tsrs:
        with open(path, "rb") as fh:
            tsr = fh.read()
        passed = A.verify_token(tsr, root, trust_root_pem_paths=trust_roots)
        authority = os.path.basename(path)[len("root-"):-len(".tsr")]
        chain = "sig+chain" if trust_roots else "imprint-only"
        when = ""
        try:
            when = "  certified " + A.token_time(tsr)
        except Exception:  # noqa: BLE001
            pass
        print(f"  anchor {authority}: {'OK' if passed else 'FAIL'} ({chain}){when}")
        ok = ok and passed
        anchored += 1 if passed else 0
    if anchored == 0:
        ok = False
    print("RESULT:", "VERIFIED" if ok else "NOT VERIFIED")
    return ok


def verify_category(dir_path: str, index: str,
                    trust_roots: Optional[List[str]] = None) -> bool:
    cells_doc, tree = _load(dir_path)
    leaf_bytes, leaves = _ordered_leaf_bytes(cells_doc)
    root = M.merkle_root(leaf_bytes)

    pos = next((i for i, lf in enumerate(leaves) if lf["index"] == index), None)
    if pos is None:
        print(f"  category {index} not found in cells.json -> NOT verified")
        return False

    leaf = leaves[pos]
    lh = M.leaf_hash(leaf_bytes[pos])
    path = M.audit_path(pos, leaf_bytes)
    included = M.verify_inclusion(lh, pos, len(leaf_bytes), path, root)
    print(f"{index}: headline={leaf['headline']} band={leaf['band']} position={pos}")
    print(f"  leaf_hash: {lh.hex()}")
    print(f"  inclusion proof against recomputed root: {'OK' if included else 'FAIL'}")

    if tree is not None:
        published = next((l for l in tree["leaves"] if l["index"] == index), None)
        if published is not None:
            same_hash = published["leaf_hash"] == lh.hex()
            same_path = published["audit_path"] == [h.hex() for h in path]
            print(f"  tree.json leaf_hash matches: {same_hash}; audit_path matches: {same_path}")
            included = included and same_hash and same_path

    cycle_ok = verify_cycle(dir_path, trust_roots=trust_roots) if included else False
    result = included and cycle_ok
    print("RESULT:", "VERIFIED" if result else "NOT VERIFIED")
    return result


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="confidence-verify",
                                 description="Independently verify a sealed Confidence Index cycle.")
    ap.add_argument("--trust-root", action="append", dest="trust_roots",
                    help="PEM file of a TSA root cert to verify signature+chain "
                         "(repeatable). Omit for imprint-only checking.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("verify-cycle", help="verify a whole cycle's root + anchor")
    pc.add_argument("dir", help="directory with cells.json, tree.json, root-*.tsr")
    po = sub.add_parser("verify-category", help="verify a single index reading")
    po.add_argument("dir")
    po.add_argument("--index", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "verify-cycle":
        ok = verify_cycle(args.dir, trust_roots=args.trust_roots)
    else:
        ok = verify_category(args.dir, args.index, trust_roots=args.trust_roots)
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
