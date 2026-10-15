# qtc-core

Components QTC Core owns outright. Nothing here depends on the external
QTC-Wallet reference folder.

## `pq/`

The Dilithium and Kyber C reference trees (PQClean, public domain). The build
reads `Dilithium C lang/Dilithium C/ref/fips202.c` for SHA3-256 and SHAKE256.

ML-DSA-65 and ML-KEM-1024 come from **liboqs** — see `pq/README.md` for why, and
for the pre-finalisation sizing caveat that matters when reading these trees.

## `wallet/`

The internal QTC wallet — the shipped path for key generation, address
derivation and signing. See `docs/DAY6.md` Phase 1.

Frozen rules it must follow:

- Seed derivation: `SHAKE256("oqs_wallet_cli" || domain || seed, 48)` feeding a
  SHAKE256 counter-mode stream (`docs/DAY5.md` §4). Same seed, same keys as the
  reference wallet.
- ML-DSA-65 signing seed: `SHAKE256(wallet_seed || "QTC_PQHD_DILITHIUM", 32)` —
  independent of the KEM shared secret.
- v1 address: `SHA3-256(SHAKE256(kyber_shared_secret || ml_dsa_65_pk))[0:20]`,
  bech32m, witness version 1 (`docs/DAY5.md` §7).
- Never persist the ML-KEM shared secret.
- Signature message: the `signature_hash` layout in `docs/DAY5.md` §3.
