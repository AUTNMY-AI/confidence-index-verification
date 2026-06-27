"""
FROZEN canonicalization for the Integrity Seal layer.

    canonicalization_version = "jcs-1"

Verification fails for innocent reasons if serialization drifts across
machines, languages, or releases. This module locks ONE canonical form and
must never change silently. If the rule ever must change, it changes under a
NEW canonicalization version recorded in the seal log, and old cycles keep
verifying under the old rule (see merkle.py / seal_stage.py).

The same rules are reimplemented in the public verification CLI by importing
this exact module as the shared core, so the server and any third party
compute identical leaf bytes.

Locked decisions
----------------
* Canonical form: RFC 8785 JSON Canonicalization Scheme (JCS) via the pinned
  ``rfc8785`` package. Sorted keys, no insignificant whitespace, UTF-8. All
  leaf field names and pillar names are ASCII, so JCS key ordering (UTF-16
  code units) and Python ordering (Unicode code points) cannot diverge.
* Numbers: every score (composite and each pillar) is emitted as a STRING at
  fixed precision, so floating-point representation never varies across
  machines or languages. Composite and pillars are published at one decimal
  place (the precision the site displays). Rounding is ROUND_HALF_EVEN, which
  matches the ``round(x, 1)`` already applied at scoring time, so the leaf
  reproduces the displayed value. Canonicalization formats; it does not invent
  precision the scorer did not already apply.
* Timestamp: UTC, second precision, trailing ``Z`` (e.g. 2026-06-03T12:00:00Z).
* Cadence: the fixed string "12h".

Leaf schema (one per published cell)::

    {
      "index": "robotaxi",
      "methodology_version": "robotaxi-1.3",
      "operator": "waymo",
      "composite": "77.2",
      "pillars": { "<pillar>": "<value>", ... },
      "cadence": "12h",
      "computed_at_utc": "2026-06-03T12:00:00Z"
    }

Pillar names are NOT hardcoded here: each index has its own rubric (robotaxi,
trucks, delivery_bots, and licensing do not share pillar sets), so the leaf
carries whatever pillars the caller supplies. JCS sorts them deterministically.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN
from typing import Mapping, Union

import rfc8785

# Bump ONLY by introducing a new value; never redefine an existing one.
CANONICALIZATION_VERSION = "jcs-1"

# One decimal place for composite and every pillar, matching site display.
_SCORE_QUANTUM = Decimal("0.1")

# Fixed cadence string baked into every leaf.
CADENCE = "12h"

ScoreValue = Union[str, int, float, Decimal]


def format_score(value: ScoreValue) -> str:
    """Normalize a score to its frozen canonical string form.

    Accepts a number or an already-formatted string and always returns the
    same canonical representation (e.g. 77 -> "77.0", "77.20" -> "77.2",
    77.25 -> "77.2" under ROUND_HALF_EVEN). Going through ``str(value)`` first
    avoids binary float artifacts (Decimal(0.1) would not, Decimal("0.1")
    does).
    """
    if value is None:
        raise ValueError("a sealed leaf score cannot be None")
    quantized = Decimal(str(value)).quantize(_SCORE_QUANTUM, rounding=ROUND_HALF_EVEN)
    # Decimal renders 77.2 -> "77.2", 77.0 -> "77.0", 0 -> "0.0".
    return format(quantized, "f")


def format_timestamp(dt: datetime) -> str:
    """Format a datetime as the frozen UTC second-precision ``...Z`` string."""
    if dt.tzinfo is None:
        raise ValueError("computed_at must be timezone-aware (UTC)")
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_leaf(
    *,
    index: str,
    methodology_version: str,
    operator: str,
    composite: ScoreValue,
    pillars: Mapping[str, ScoreValue],
    computed_at_utc: str,
    cadence: str = CADENCE,
) -> dict:
    """Build one canonical leaf object (a plain dict ready for canonical_bytes).

    ``composite`` and each pillar value are normalized through
    :func:`format_score`. ``computed_at_utc`` must already be the frozen
    timestamp string (use :func:`format_timestamp`).
    """
    if not index or not operator or not methodology_version:
        raise ValueError("index, operator, and methodology_version are required")
    if not pillars:
        raise ValueError("a leaf must carry at least one pillar")
    return {
        "index": index,
        "methodology_version": methodology_version,
        "operator": operator,
        "composite": format_score(composite),
        "pillars": {str(name): format_score(v) for name, v in pillars.items()},
        "cadence": cadence,
        "computed_at_utc": computed_at_utc,
    }


def canonical_bytes(leaf: Mapping) -> bytes:
    """Serialize a leaf to its frozen canonical byte form (RFC 8785 JCS)."""
    return rfc8785.dumps(leaf)
