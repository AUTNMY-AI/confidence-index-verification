# confidence-index-verification

Independently verify **The Road to Autonomy Confidence Indices**.

Every twelve hours, the four Confidence Index readings (Robotaxi, Autonomous
Driving Licensing, Autonomous Trucks, Delivery Bots) are serialized in a fixed
canonical form, hashed into a single RFC 6962 Merkle tree, and the resulting
32-byte root is timestamped by independent RFC 3161 Time-Stamping Authorities
(DigiCert and Sectigo). This tool recomputes that root from the published
readings and checks it against the anchored tokens, with **no trust in AUTNMY AI
required**.

It proves **integrity** (a reading was not altered after sealing) and **timing**
(it existed at the certified time). It does **not** assess correctness; that is
governed by the methodology. This is a separate seal lineage from the flagship
indices verifier ([indices-verification](https://github.com/AUTNMY-AI/indices-verification)).

## Install

```bash
pip install "git+https://github.com/AUTNMY-AI/confidence-index-verification.git"
```

## Use

Download a cycle's public files from its permalink under `/verification/<cycle_id>/`
(`cells.json`, `tree.json`, and `root-*.tsr`) into a folder, then:

```bash
# verify a whole cycle: recompute the root and match it to the anchored token
confidence-verify verify-cycle ./confidence-2026-06-27-0600/

# verify a single index reading via its Merkle inclusion proof
confidence-verify verify-category ./confidence-2026-06-27-0600/ --index robotaxi
```

`verify-cycle` recomputes the Merkle root from `cells.json` (the published
readings, not the convenience `tree.json`) and confirms it matches the message
imprint inside each signed RFC 3161 token. Any altered value produces a
different root that matches none of the tokens: `NOT VERIFIED`.

By default the token signature is checked imprint-only. To also verify the
token signature and certificate chain, pass TSA root certificates:

```bash
confidence-verify --trust-root digicert-root.pem --trust-root sectigo-root.pem verify-cycle ./CYCLE/
```

## What's in a cycle

- `cells.json` — the published Confidence readings (headline, band, pillars) for the cycle.
- `tree.json` — the Merkle root and a Merkle proof for each reading.
- `root-digicert.tsr`, `root-sectigo.tsr` — the signed RFC 3161 timestamp tokens.

## License

MIT. The canonicalization (RFC 8785 JCS) and Merkle (RFC 6962) core is identical
to the server's, so anyone computes the same bytes.
