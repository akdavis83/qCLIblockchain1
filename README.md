# QTC Protocol

QTC (Quantum Coin) Protocol — a standalone CLI blockchain implementation for protocol development and testing.

## Status

**v0.4-development** — Days 1-5 complete.

## Architecture

- **`qtc-protocol` is QTC Core** — the component being built and shipped. It builds
  standalone: no sibling folders required.
- **`QTC-Wallet` is an external reference** — the address/key specification and the
  cross-check oracle. Day 5 proved interop against it; the final node must not need it.
- **QTC Core owns an internal wallet** at `qtc-core/wallet/`. Same seed, same keys
  and same address as the reference wallet. It can receive, report a balance, and
  sign spends the node accepts.

Day 1-2: Project structure, consensus constants, block/genesis, SHA-256 hashing, chain state.
Day 3: Transactions, UTXO set, transaction validation, balance calculation, serialization/deserialization.
Day 4: SHA-256 mining, block templates, subsidy halving, chain validation with UTXO rebuild, tamper detection.
Day 5: ML-DSA-65 (FIPS-204) transaction signatures via liboqs, deterministic key generation, witness serialization, frozen signature hash, address decoding.

This is a clean laboratory for developing and proving the QTC protocol. It is NOT the production node.

## Architecture

```
qtc-protocol/
├── include/
│   ├── consensus.h       Protocol constants, enums, version IDs
│   ├── crypto.h          SHA-256, SHA3-256, SHAKE256, hex utils, serialization helpers
│   ├── transaction.h     UTXO-based transaction model
│   ├── block.h           Block header, block, merkle root, PoW
│   ├── chain.h           Chain state management
│   └── pq_crypto.h       ML-DSA-65 / ML-KEM-1024 interface and address decoding
├── src/
│   ├── crypto.cpp        Self-contained SHA-256, SHA3-256, SHAKE256, hex, LE serialization
│   ├── pq_crypto.cpp     liboqs adapter: ML-DSA-65 keygen, sign, verify, bech32m decode
│   ├── transaction.cpp    Transaction serialization, txid, coinbase
│   ├── block.cpp          Block hashing, merkle root, genesis
│   ├── chain.cpp          Chain state, validation, persistence
│   └── main.cpp           CLI entrypoint
├── tests/
│   └── selftest.cpp       Placeholder (use `qtc selftest`)
├── qtc-core/              QTC Core's own components
│   ├── pq/                Dilithium + Kyber C reference trees (FIPS-202 source)
│   └── wallet/            Internal wallet (keys, v1 address, signing)
├── data/                  Chain state files (runtime)
├── tests/
│   └── pq_test_vector.txt Known-answer ML-DSA-65 vector (qtc pqvector)
├── docs/
│   ├── DAY5.md            Frozen Day 5 constants and signature hash layout
│   ├── DAY6.md            Day 6 plan (RPC, mempool, send/receive) — plan only
│   └── DEVELOPMENT_PLAN.md
├── CMakeLists.txt
└── README.md
```

## Key Design Decisions

- **SHA-256 PoW** (not qRandomX) for v1 — simpler, ASIC-compatible, deferred PQ mining
- **ML-DSA-65** (FIPS-204) for transaction signatures — live on Day 5
- **ML-KEM-1024** (FIPS-203) for key establishment only (future P2P)
- **UTXO-based** model — no account balances, wallet computes from UTXO set
- **bech32m** (BIP-350) addresses with HRP `qtc` (mainnet) / `tqtc` (testnet). QTC has no witness v0, so the original bech32 checksum is rejected outright.
- **21M max supply**, ~10 minute blocks, 32MB block target
- **C++17** with CMake + Makefile build systems
- **Self-contained** SHA-256, SHA3-256 and SHAKE256 (no runtime crypto dependency for hashing)
- **liboqs 0.15.0** linked for PQ crypto; SHA3/SHAKE come from the vendored PQClean `fips202`

## Build

Tested with the Makefile on Linux/g++ 15. CMakeLists.txt is included for WSL/dev environments with CMake installed but was not tested in this build.

### Using Makefile (tested)

```bash
make
./qtc init
./qtc selftest
```

### Using CMake (requires cmake installed)

```bash
cmake -S . -B build
cmake --build build
./build/qtc init
./build/qtc selftest
```

## Usage

```bash
# Initialize the chain (creates genesis block + UTXO set)
./qtc init

# View chain state
./qtc getblockchaininfo

# View a specific block
./qtc getblock 0

# Get block hash at height
./qtc getblockhash 0

# Get balance for a dev-format address
./qtc getbalance Alice

# List UTXOs (all or for a specific address)
./qtc listunspent
./qtc listunspent Alice

# Run Day 3 demo (UTXO lifecycle, transactions, validation)
./qtc demo-day3

# Run Day 4 demo (mining, validation, tamper test)
./qtc demo-day4

# Mine blocks
./qtc mine 5 Alice

# Run the Day 5 post-quantum report
./qtc pqtest

# Run the Day 5 end-to-end transaction demo
./qtc demo-day5

# Create an internal wallet from a seed, then show it and its balance
./qtc wallet-new <seed_hex> wallet.dat
./qtc wallet-info wallet.dat

# Run self-tests (147 tests)
./qtc selftest

# Validate the chain
./qtc validatechain
```

## Day 5 verification

`./qtc selftest` → **123 passed, 0 failed**. Both `make` and `cmake` build clean.

| Check | Result |
|---|---|
| `./qtc pqtest` | 28 PQ checks plus the committed vector — `Verification: PASS` |
| `./qtc demo-day5` | mines 101 blocks, signs an ML-DSA-65 spend, `RESULT: ACCEPTED`, chain `PASSED` |
| Core ↔ wallet key agreement | identical public **and** secret key from one seed |
| Wallet signs → Core verifies | `VALID`; tampered message `INVALID` |
| Forged signature | rejected by consensus validation |
| Signed tx, no signature | rejected |
| Multi-input signed tx | rejected — the v1 witness covers one input |
| Truncated serializations | 5351 of 5352 rejected cleanly |

Consensus enforces the witness: `UTXOSet::validate_transaction` verifies the
signature, so `Chain::add_block` cannot accept a block carrying a forged one.

Two things to know:

- ML-DSA signing is **hedged** by design, so signature bytes are not reproducible. Compare by
  verification, never by equality. `tests/pq_test_vector.txt` is a one-time known-answer value;
  regenerate it with `./qtc pqvector`.
- liboqs 0.15.0 removed the NIST-KAT DRBG, so Core and QTC-Wallet share a SHAKE256 DRBG built on
  the vendored PQClean `fips202`. That is what makes their keys agree.

Full detail in [`docs/DAY5.md`](docs/DAY5.md).

## Roadmap

### Sprint 1 (Days 1-7)

| Day | Focus | Status |
|-----|-------|--------|
| 1 | Project structure, consensus constants | Done |
| 2 | Block, genesis, SHA-256 hashing | Done |
| 3 | Transactions, UTXO set, validation | Done |
| 4 | SHA-256 mining, block templates, chain validation | Done |
| 5 | PQ wallet integration (ML-DSA-65) | Done |
| 6 | Internal wallet + chain persistence done; RPC, mempool, send/receive to go — see `docs/DAY6.md` |
| 7 | Integration tests | Pending |

### Sprint 2
Mining → receive → send → sign → validate → mempool → block → confirm

### Sprint 3
Two-node P2P network

### Sprint 4
QTC-Wallet compatibility testing

### Sprint 5+
BitcoinII-Core integration

## Protocol Constants (v0.1)

| Parameter | Value |
|-----------|-------|
| Max supply | 21,000,000 QTC |
| Block interval | ~10 minutes (600s) |
| Max block size | 32 MB (development target) |
| PoW algorithm | SHA-256d (double SHA-256) |
| Signature algorithm | ML-DSA-65 (FIPS-204) |
| ML-DSA-65 key sizes | pk 1952 B, sk 4032 B, sig 3309 B |
| KEM algorithm | ML-KEM-1024 (FIPS-203) |
| Address format | bech32m (BIP-350), HRP `qtc`; BIP-173 rejected |
| v1 address derivation | `SHA3-256(SHAKE256(kyber_shared_secret ‖ ml_dsa_65_pk))[0:20]`, bech32m, witness v1 |
| DSA key seed | `SHAKE256(wallet_seed ‖ "QTC_PQHD_DILITHIUM", 32)` — independent of the KEM secret |
| Witness version | 1 = full witness on-chain (current); 2 = 32-byte compressed witness (future soft fork) |
| Coinbase maturity | 100 blocks |
| Initial subsidy | 50 QTC |
| Halving interval | 210,000 blocks |

## License

QTC implements its own difficulty algorithm.
