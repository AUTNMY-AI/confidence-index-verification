"""
RFC 3161 timestamp-token verification (read-only).

This is the verifier half of the anchor: given a stored RFC 3161 reply and a
recomputed Merkle root, confirm the token's message imprint equals SHA-256 of
the root, and (when trust roots are supplied) verify the token signature and
certificate chain. There is no submission/signing path here on purpose: a
verifier never needs to mint timestamps.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional

import rfc3161_client as tsp


def verify_token(tsr_der: bytes, root: bytes, *,
                 trust_root_pem_paths: Optional[List[str]] = None) -> bool:
    """Verify a stored RFC 3161 reply against a (recomputed) 32-byte root.

    Always checks the message imprint equals SHA-256(root). If trust roots are
    supplied, additionally verifies the token signature + certificate chain.
    Returns True only if every requested check passes.
    """
    response = tsp.decode_timestamp_response(tsr_der)
    if response.tst_info.message_imprint.message != hashlib.sha256(root).digest():
        return False
    if not trust_root_pem_paths:
        return True
    builder = tsp.VerifierBuilder()
    for path in trust_root_pem_paths:
        with open(path, "rb") as fh:
            builder = builder.add_root_certificate(fh.read())
    verifier = builder.build()
    try:
        return verifier.verify_message(response, root)
    except tsp.VerificationError:
        return False


def token_time(tsr_der: bytes) -> str:
    """Return the certified gen_time from a stored RFC 3161 reply (ISO-8601)."""
    info = tsp.decode_timestamp_response(tsr_der).tst_info
    return info.gen_time.isoformat() if info.gen_time else ""
