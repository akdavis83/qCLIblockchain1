# QTC Protocol

QTC (Quantum Coin) Protocol — a standalone CLI blockchain implementation for protocol development and testing.

## Status

**v0.3-development** — Days 1-4 foundation sprint complete.

Day 1-2: Project structure, consensus constants, block/genesis, SHA-256 hashing, chain state.
Day 3: Transactions, UTXO set, transaction validation, balance calculation, serialization/deserialization.
Day 4: SHA-256 mining, block templates, subsidy halving, chain validation with UTXO rebuild, tamper detection.

This is a clean laboratory for developing and proving the QTC protocol. It is NOT the production node.

## Architecture

```
qtc-protocol/
├── include/
│   ├── consensus.h       Protocol constants, enums, version IDs
│   ├── crypto.h          SHA-256, hex utils, serialization helpers
│   ├── transaction.h     UTXO-based transaction model
│   ├── block.h           Block header, block, merkle root, PoW
│   ├── chain.h           Chain state management
│   └── pq_crypto.h       PQ crypto placeholder interface (liboqs, Day 5+)
├── src/
│   ├── crypto.cpp        Self-contained SHA-256, hex, LE serialization
│   ├── transaction.cpp    Transaction serialization, txid, coinbase
│   ├── block.cpp          Block hashing, merkle root, genesis
│   ├── chain.cpp          Chain state, validation, persistence
│   └── main.cpp           CLI entrypoint
├── tests/
│   └── selftest.cpp       Placeholder (use `qtc selftest`)
├── data/                  Chain state files (runtime)
├── docs/                  Documentation
├── CMakeLists.txt
└── README.md
```

## Key Design Decisions

- **SHA-256 PoW** (not qRandomX) for v1 — simpler, ASIC-compatible, deferred PQ mining
- **ML-DSA-65 (Dilithium3)** for transaction signatures (Day 5+)
- **ML-KEM-1024 (Kyber1024)** for key establishment only (future P2P)
- **UTXO-based** model — no account balances, wallet computes from UTXO set
- **bech32m** addresses with HRP `qtc` (mainnet) / `tqtc` (testnet)
- **21M max supply**, ~10 minute blocks, 32MB block target
- **C++17** with CMake + Makefile build systems
- **No external dependencies** for Days 1-2 (SHA-256 is self-contained)
- **liboqs** will be linked starting Day 5 for PQ crypto

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

# Run self-tests (92 tests)
./qtc selftest

# Validate the chain
./qtc validatechain
```

## Roadmap

### Sprint 1 (Days 1-7)

| Day | Focus | Status |
|-----|-------|--------|
| 1 | Project structure, consensus constants | Done |
| 2 | Block, genesis, SHA-256 hashing | Done |
| 3 | Transactions, UTXO set, validation | Done |
| 4 | SHA-256 mining, block templates, chain validation | Done |
| 5 | PQ wallet integration (ML-DSA) | Next |
| 6 | RPC + send/receive | Pending |
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
| Signature algorithm | ML-DSA-65 (Dilithium3) |
| KEM algorithm | ML-KEM-1024 (Kyber1024) |
| Address format | bech32m, HRP `qtc` |
| Witness version | 1 (standard PQ wallet) |
| Coinbase maturity | 100 blocks |
| Initial subsidy | 50 QTC |
| Halving interval | 210,000 blocks |

## License

QTC implements its own difficulty algorithm.
