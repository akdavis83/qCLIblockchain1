# QTC Day 5 — ML-DSA-65 Transaction Verification

Status: **complete**. `qtc selftest` → 123 passed, 0 failed.

The roadmap requirement (`Week1 Start.txt:698-712`) is met: QTC-Wallet generates PQ keys, generates a `qtc1` address, and signs a message that QTC Core verifies.

---

## 1. Frozen constants

| Parameter | Value | Notes |
|---|---|---|
| Signature algorithm | **ML-DSA-65** (FIPS-204) | id `0x01`; formerly "Dilithium3", removed from liboqs |
| KEM algorithm | **ML-KEM-1024** (FIPS-203) | id `0x01`; "Kyber1024" survives only as a deprecated alias |
| Public key | 1952 bytes | agrees across liboqs 0.7.2 and 0.15.0 |
| Secret key | **4032 bytes** | was 4000 pre-finalization |
| Signature | **3309 bytes** | was 3293 pre-finalization |
| Linked liboqs | 0.15.0 | asserted at runtime by `pq::linked_sizes_match()` |
| SHA3-256 / SHAKE256 | vendored PQClean `ref/fips202.c` | liboqs 0.15.0 exports no callable SHA3 |

The old 4000/3293 figures appear in `Witness Compression Upgrade.txt` and older docs; they are pre-FIPS-204 and must not be reintroduced.

### Witness versions

| Version | Layout | Status |
|---|---|---|
| v1 | full signature (3309 B) + full public key (1952 B) on-chain, verified against `signature_hash` | **Day 5, final** |
| v2 | 32-byte witness hash on-chain; full witness still verified by consensus | future soft fork |

Per `Witness Compression Upgrade.txt`, v2 is the witness compression upgrade — not a second pubkey-hash flavour.

## 2. Transaction wire format

```
version            uint32 LE
input count        CompactSize
inputs             prevout(36) | script_len | script | sequence(uint32 LE)
output count       CompactSize
outputs            amount(uint64 LE) | script_len | script
locktime           uint32 LE
--- witness, present only when the algorithm id is non-zero ---
sig_algorithm_id   uint8
public_key         CompactSize | 1952 bytes
signature          CompactSize | 3309 bytes
```

`txid = SHA256d(serialize())`, which includes the witness (decision D4, Option A).

## 3. `signature_hash` byte layout

Domain-separated, then hashed with SHA-256d to produce the 32-byte message that ML-DSA-65 signs. Signing **never** covers a serialization that already contains the signature.

```
"QTCSIG1"                          8 bytes domain tag
version                            uint32 LE
input_index                        uint64 LE
prevout                            36 bytes (txid || vout LE)
prev_amount                        uint64 LE
prev_script_len                    CompactSize
prev_script                        variable
output_count                       CompactSize
  per output:
    amount                          uint64 LE
    script_len                      CompactSize
    script                          variable
locktime                           uint32 LE
sig_algorithm_id                   uint8
```

Bindings verified by test: changing the message, public key, signature, prev amount, prev script, locktime, any output amount, or the algorithm id all cause rejection.

**Known limitation:** `Transaction` carries one `public_key`/`signature` pair for the whole transaction, so a multi-input transaction cannot commit each input to its own prevout. `sign_input`/`verify_input` take an `input_index` and are ready for per-input witnesses; the container needs splitting before multi-input spends are supported. Until then `UTXOSet::validate_transaction` **rejects** any signed transaction with more than one input rather than leaving the second input unverified.

## 4. Deterministic key generation

`liboqs` 0.15.0 **removed** the NIST-KAT DRBG (`OQS_randombytes_nist_kat_init_256bit`, `OQS_RAND_alg_nist_kat`) and exposes no seeded/derand keygen. The only remaining hook is `OQS_randombytes_custom_algorithm()`.

Both Core and the wallet therefore use the same SHAKE256 counter-mode stream, built on the vendored `fips202`:

```
drbg_seed = SHAKE256("oqs_wallet_cli" || domain || seed, 48)
block_i   = SHAKE256(drbg_seed || uint64_le(i), 64)
```

Verified: Core and `oqs_wallet_cli` derive **identical public and secret keys** from the same seed.

### What "deterministic" does and does not cover

| Property | Deterministic |
|---|---|
| Keypair from a seed | Yes |
| Verification result | Yes |
| Signature **bytes** | **No** — FIPS-204 signing is hedged by design |

`tests/pq_test_vector.txt` is therefore a one-time known-answer signature, regenerated with `qtc pqvector`. A liboqs upgrade that changes verification will fail the suite, which is the intent.

## 5. Decisions

| # | Decision | Outcome |
|---|---|---|
| D1 | PQ baseline | Migrate to liboqs 0.15.0 / FIPS-204. Core links liboqs for verification; the wallet CLI is driven as a subprocess to produce interop vectors, so both sides provably share one implementation. |
| D2 | Address derivation / ownership | **Settled (W3.1).** See section 7. Ownership verification is deferred; signature verification is enforced. |
| D3 | bech32 vs bech32m | **Settled (W3.2): bech32m.** QTC has no witness v0, so BIP-350 requires bech32m for every address. The decoder rejects BIP-173. |
| D4 | txid | Option A — witness included. |
| D5 | Day 5 vectors | Core-generated, plus a wallet-signed interop vector. |

## 6. Consensus enforcement

`UTXOSet::validate_transaction` verifies the PQ witness, so `Chain::add_block` cannot accept a block whose transactions carry forged signatures. It rejects:

| Condition | Reason reported |
|---|---|
| Signature does not verify | `PQ signature rejected: signature does not verify against this key and message` |
| Algorithm id set but no signature | `PQ signature rejected: transaction is not signed` |
| More than one input on a signed tx | `Signed transaction has N inputs but the v1 witness covers only one` |
| Signature made against a different prev amount | signature mismatch on the reconstructed hash |

Covered by five checks in the standing suite.

## 7. Address rules (settled)

**Checksum.** QTC has no witness v0, so every address uses bech32m (BIP-350). `decode_address` rejects the original BIP-173 checksum rather than accepting both, so the two can never be confused. The wallet encodes with bech32m via `qti3_bech32m.mjs`.

**v1 program (consensus rule).** The standard wallet is `qti3.js`:

```
kyber_public_key, ml_dsa_65_public_key   from the wallet
master_entropy  = SHAKE256(kyber_shared_secret || ml_dsa_65_public_key, 64)
program         = SHA3-256(master_entropy)              # full 32 bytes
address         = bech32m(hrp, program)                 # no version word
```

v1 carries **no version word** and **no truncation**. `decode_address` rejects both a truncated 20-byte program and any version-worded address, so the compression-era forms cannot reappear by accident. A 62-character address, e.g.
`qtc1x86zw4qg4ye728l37ghy4x00sxvh8jw68w8mwaqn8kd0p3wsw60sstgv4j`.

**Deferred upgrades — none of this is in use:**

| Upgrade | Effect |
|---|---|
| Truncated program | `SHA3-256(...)[0:20]`, a shorter address |
| `WitnessVersion::V1` | explicit version word for the truncated form |
| `WitnessVersion::V2` | witness compression — only a hash committed on-chain, full witness still verified |

They wait until block space actually matters. `MAX_BLOCK_SIZE` is 32 MB (raised from 4 MB for the KEM + DSA-65 key sizes) and is now enforced in `Chain::add_block`.

A validating node must be able to obtain everything the derivation consumes. The ML-DSA-65 public key and the KEM shared secret are both required, and neither is recoverable from a signature alone. Until the v2 upgrade commits them, this binding is **wallet-side only**: the node verifies that a spend carries a valid ML-DSA-65 signature over the reconstructed `signature_hash`, and does not recompute the address. `demo-day5` therefore reports ownership as not yet verifiable rather than claiming it.

**Key schedule.** The ML-DSA-65 signing seed is `SHAKE256(wallet_seed || "QTC_PQHD_DILITHIUM", 32)` — derived from the wallet seed under its own domain tag, **not** from the KEM shared secret, so the two key schedules are independent. The KEM shared secret is used only for address derivation and is no longer written to the wallet JSON.

**Retired.** `qti2.js` (SHA3-256 of the public key, a different scheme) is marked deprecated; its address is BIP-173 and is now rejected. `qti3_hd.js` is retained and aligned: bech32m addresses, flattened keys, a top-level `address` and `witness_program_hex`.

## 8. Hardening done

- `Transaction::deserialize` takes a length and bounds-checks every read; `OutPoint`, `TxInput` and `TxOutput` do the same.
- Element counts are capped to stop a hostile CompactSize driving a huge allocation loop.
- 5351 of 5352 truncated serializations are rejected cleanly.
- `MAX_BLOCK_SIZE` (32 MB) is now enforced in `Chain::add_block`; it was previously declared and never checked.

## 9. Deferred

**Day 6** — see `docs/DAY6.md`.
- Per-input witnesses, which would replace the single-input rejection rule in section 6.
- Ownership verification once the node can obtain the v1 address inputs.
- JSON-RPC server, mempool, send/receive.

**Day 7**
- `Chain::load()` still re-initialises instead of restoring saved state.

**Wallet day** — see `QTC-Wallet Structure Fix Plan.md` for E1–E12 and W1–W6. Remaining: stop persisting `kyber_shared_secret` at rest, retire the `qti2.js` and HD SHA3-512 derivations, and separate the DSA seed from the KEM shared secret with distinct domain tags.

## 10. Commands

```bash
./qtc pqtest       # ML-DSA-65 report, negative cases, committed vector
./qtc demo-day5    # mine 101, spend a PQ UTXO, mine it, validate
./qtc pqvector     # regenerate the known-answer vector
./qtc selftest     # 121 checks including all of the above
```

Both `make` and `cmake` build. The vendored `fips202.c` path is set by `PQ_REF_DIR` in the `Makefile` and `PQ_REF_DIR` in `CMakeLists.txt`; both point at `QTC-Wallet/Dilithium C lang/Dilithium C/ref`.