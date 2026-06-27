"""
RFC 6962 Merkle tree for the Integrity Seal layer.

We use Certificate-Transparency-style hashing with domain separation so a leaf
hash can never be confused with an internal node hash (second-preimage
safety):

    leaf  hash:  SHA-256(0x00 || leaf_bytes)
    node  hash:  SHA-256(0x01 || left || right)

The odd-node rule follows RFC 6962 exactly: the largest power of two strictly
below n splits the tree, so a lone trailing node is PROMOTED (carried up
unchanged), never duplicated as in Bitcoin's tree.

The single anchored value per cycle is :func:`merkle_root`. A single published
cell is proven to belong to that root by :func:`audit_path` +
:func:`verify_inclusion`, without revealing or re-anchoring the others.

Inputs here are the canonical leaf BYTES from ``canonical.canonical_bytes``.
Callers must order leaves deterministically (by ``(index, operator)`` byte-wise
ascending) BEFORE building the tree; this module preserves the given order and
does not sort.
"""
from __future__ import annotations

import hashlib
from typing import List

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(leaf_bytes: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf_bytes)."""
    return hashlib.sha256(LEAF_PREFIX + leaf_bytes).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: List[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash (MTH) over an ordered list of leaf byte blobs.

    MTH({})  = SHA-256("")            (empty tree)
    MTH(d0)  = SHA-256(0x00 || d0)    (single leaf)
    MTH(D)   = SHA-256(0x01 || MTH(D[:k]) || MTH(D[k:]))  with k as above.
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_below(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(index: int, leaves: List[bytes]) -> List[bytes]:
    """RFC 6962 audit path (inclusion proof) for the leaf at ``index``.

    Returns the ordered list of sibling subtree hashes from the leaf's nearest
    sibling up to (but not including) the root.
    """
    n = len(leaves)
    if index < 0 or index >= n:
        raise IndexError(f"leaf index {index} out of range for {n} leaves")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return audit_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return audit_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def verify_inclusion(
    leaf_hash_bytes: bytes,
    index: int,
    tree_size: int,
    path: List[bytes],
    root: bytes,
) -> bool:
    """Verify an RFC 6962 inclusion proof (algorithm from RFC 6962 sec 2.1.1).

    Recomputes the root from a leaf hash and its audit path, tracking the
    leaf's node index (fn) and the last node index (sn) to decide hash order
    at each level. Returns True only if the reconstructed root matches and the
    path length is exactly right (sn collapses to 0).
    """
    if index >= tree_size or index < 0:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash_bytes
    for p in path:
        if sn == 0:
            return False  # path longer than the tree allows
        if (fn & 1) or (fn == sn):
            r = _node_hash(p, r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
