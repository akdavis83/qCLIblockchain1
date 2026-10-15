# QTC — Day 6 Plan: RPC, Mempool, Send/Receive

**Status: COMPLETE.** All seven phases implemented and verified. `qtc selftest` → 222 passed, 0 failed.

Day 5 is complete and verified — see [`DAY5.md`](DAY5.md).

**All phases done.** A minimally working prototype node: it mines, persists across
restarts, serves JSON-RPC, accepts signed spends into a mempool, confirms them in
a block, and rejects malformed input. Everything else is later expansion.

---

## Architecture (settled)

- **`qtc-protocol` is QTC Core** — the thing being built and shipped.
- **`QTC-Wallet` is an external reference** — the specification and the
  cross-check oracle, not a runtime dependency. Day 5 used it to prove interop;
  the final node must not need it.
- **QTC Core owns an internal wallet.** For the final version the node must be
  able to generate keys, derive addresses, and sign without the JS wallet.

`qtc-core/` is the home for that work and for the post-quantum primitives the
core owns. `qtc-core/pq/` holds the Dilithium and Kyber C reference trees, and
the build reads FIPS-202 from `Dilithium C lang/Dilithium C/ref/fips202.c`. The
tree builds with no sibling folders present — verified in an isolated copy, with
both `make` and `cmake`.

ML-DSA-65 and ML-KEM-1024 come from **liboqs**, which is the single
implementation the node trusts. The Dilithium and Kyber C reference trees are in
`qtc-core/pq/` and supply FIPS-202; they also allow cross-verifying a signature
against a second, independent implementation (1.7).

Note their sizes are pre-finalisation: Dilithium3 uses sk 4000 / sig 3293, while
FIPS-204 ML-DSA-65 uses 4032 / 3309. Read protocol lengths from `qtc::pq`, never
from those trees.

---

## Goal

A transaction moves QTC end to end: `mine → UTXO → wallet signs → node validates → mempool → mine → confirm`, with a JSON-RPC server as the transport.

Per `QTC Development Plan.md:147-154` and `Week1 Start.txt:718-832`:

- `qtc-cli mine 101 alice` → 50 QTC
- `qtc-cli send bob 10` → signed transaction
- `qtc-cli mine 1` → confirmed
- `qtc-cli getbalance bob` → 10 QTC

---

## Starting point

| Available | Detail |
|---|---|
| Chain | regtest, genesis + mining + validation, `Chain::add_block` verifies PQ witnesses |
| Transactions | ML-DSA-65 signing, `signature_hash`, one-input signed spends enforced |
| Crypto | Self-contained SHA-256/SHA3-256/SHAKE256, liboqs adapter |
| Wallet | `qti3.js` signs via `oqs_wallet_cli`; RPC commands are gated pending this day |
| Tests | 121 checks in `qtc selftest` |

## Known constraints carried into Day 6

1. **One signed input per transaction.** `UTXOSet::validate_transaction` rejects a signed transaction with more than one input, because the v1 witness holds a single public key and signature. Consolidating inputs is therefore a wallet concern until per-input witnesses land.
2. **`Chain::load()` does not restore state.** It calls `init()` instead. Mempool + RPC will make persistence matter, so this is on the critical path.
3. **Signature verification cost.** One ML-DSA-65 verification per transaction. At roughly 5.4 KB per signed transaction, a 32 MB block holds thousands. Budget verification time before raising the block limit.
4. **Ownership is not yet verifiable.** Nodes verify signatures, not the address↔key binding (`DAY5.md` §7).

---

## Phase 1 — Internal QTC wallet (new — this is the final-version wallet)

The node must sign for itself. Reuse `qtc::pq`; do not reimplement anything.

- [x] 1.1 `qtc-core/wallet/` with `Wallet` and `WalletFile`. Deterministic key generation from a seed, exactly as `pq::generate_mldsa65_keypair` already does.
- [x] 1.2 Store keys where the external wallet does: ML-DSA-65 keypair, ML-KEM-1024 keypair, master seed. **Do not persist the KEM shared secret** — the same rule applied to `qti3.js`.
- [x] 1.3 Derive the v1 address with the frozen rule from `DAY5.md` §7: `SHA3-256(SHAKE256(kyber_shared_secret || ml_dsa_65_pk))[0:20]`, bech32m, witness v1.
- [x] 1.4 Seed derivation must match `DAY5.md` §4 exactly, including the `"oqs_wallet_cli"` prefix and the `"mldsa65_keygen"` domain, so a seed produces the same key in Core and in the reference wallet.
- [x] 1.5 Reject a malformed or truncated wallet file rather than partially loading it.
- [x] 1.6 Cross-check against QTC-Wallet: same seed must produce the same address and the same public key in both. This is the regression test that keeps the reference honest.
- [ ] 1.7 Cross-verify a signature with liboqs and with the PQClean tree. Optional — liboqs is the trusted implementation.
- [x] 1.8 Sign via the same `signature_hash` in `DAY5.md` §3. A divergence here breaks every spend.
- *Verify:* a seed produces an identical address in Core and in `qti3.js`; a Core-signed spend is accepted by Core; the wallet file contains no KEM shared secret.

**Done.** Parity confirmed byte-for-byte on address, ML-DSA-65 public key and ML-KEM-1024 public key. Sixteen new checks; 147 total. `wallet-new <seed_hex> [file]` and `wallet-info <file>` expose it on the CLI, and `wallet-info` prints the balance.

Two divergences were found and fixed while establishing parity:

1. **`OQS_KEM_encaps` argument order.** The signature is `(kem, ciphertext, shared_secret, public_key)`. Passing them the other way round wrote a 1568-byte ciphertext into a 32-byte buffer. The reference wallet had this right; QTC Core had it wrong.
2. **The reference wallet's `master_entropy` is 32 bytes, not 64.** The npm `sha3` package's `SHAKE` constructor takes a *bit length* (128 or 256) and its `digest(arg)` treats the argument as an *output format*, so `.digest(64)` silently returns the 32-byte default. Core matches the wallet at 32 bytes.

Separately, the bech32m checksum must use the canonical `polymod(hrp ‖ data ‖ [0]×6) ^ CONST`. A `^ 1` shortcut that looks algebraically equivalent produces the wrong checksum for a 52-word program.

## Phase 2 — Chain persistence (do this before the mempool)

Mempool contents must survive a restart, and none of the later phases can be tested without it.

- [x] 2.1 Persist each block's full serialization to `data/blocks/NNNNNNNN.dat`.
- [x] 2.2 Record the tip in `data/chainstate`: network, height, tip hash, difficulty bits.
- [x] 2.3 `Chain::load()` re-verifies linkage, PoW and merkle roots, then rebuilds the UTXO set rather than trusting the files. `Block::deserialize` added.
- [x] 2.4 Rejects a missing block file, corrupt block bytes, a tampered height, and a mismatched tip or genesis — each with a distinct message, exit code 1.
- [x] 2.5 Covered by seven checks in the standing suite.
- *Verify:* `init` → `mine 101 <address>` → a **new process** `getbalance` returns the same balance. Verified: 5050 QTC.
- *Note:* the file is `data/chainstate`, not `chainstate.json` — the format is `key=value`, and naming it `.json` would be misleading.

## Phase 3 — Mempool

- [x] 3.1 `Mempool` holding unconfirmed transactions with fee rate and arrival order.
- [x] 3.2 Admission: reject duplicates, double spends against the mempool or UTXO set, low fees, and anything `validate_transaction` refuses.
- [x] 3.3 Capacity limit plus eviction by lowest fee, so a flood cannot exhaust memory.
- [x] 3.4 `Chain::create_block_template` fills from the mempool by fee rate, above the coinbase.
- [x] 3.5 Block template satisfies the existing rules (coinbase first, no second coinbase, exact subsidy, consistent merkle root) — enforced by `Chain::add_block`, which the mempool path goes through.
- [x] 3.6 On `add_block`, drop confirmed transactions and any that became invalid.
- *Verify:* two transactions spending the same UTXO → the second is rejected; a block template includes the higher fee.

**Done.** `Mempool` in `include/mempool.h` / `src/mempool.cpp`. Admission rejects coinbases, duplicates, below-minimum fees, unknown inputs and double spends against both the confirmed set and pending transactions. Ordering and eviction use fee rate, so a transaction is not penalised for carrying a larger PQ witness. Sixteen checks; 163 total.

Fee schedule frozen in `consensus.h`: `MIN_TX_FEE = 1000` satoshis, `MEMPOOL_MAX_TRANSACTIONS = 100`, ordering by satoshis per serialized byte.

## Phase 4 — JSON-RPC server

- [x] 4.1 HTTP server on `127.0.0.1:18443`: loopback bind, `Content-Length` bounded, `Connection: close`, 1 MB request cap.
- [x] 4.2 Parse JSON-RPC 2.0: `jsonrpc`, `id`, `method`, `params`. Reply with a matching envelope; parse errors return `-32700`, unknown methods `-32601`.
- [x] 4.3 Methods: `getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblock`, `getbalance`, `listunspent`, `getrawmempool`, `sendrawtransaction`, `getmempoolinfo`, `generate`, `submitblock`.
- [x] 4.4 `generate` must reuse `mine_n_blocks`, not a parallel implementation.
- [x] 4.5 Bind to loopback only, and document that no authentication exists yet.
- [x] 4.6 Oversized bodies and malformed hex rejected; `handle()` is socket-free so the suite drives it directly (15 JSON cases, 6 RPC error-envelope cases), and it was also verified live over real sockets.
- [x] 4.7 `include/json.h` — minimal JSON reader/writer, since Core carries no external dependencies. Integers serialise without a decimal point so satoshi amounts are not floats.
- [x] 4.8 Numeric **strings** are accepted where a number is expected. A wallet sending `"101"` for `generate` would otherwise silently mine one block instead of 101.
- *Verify:* every method answers correctly; malformed JSON and unknown methods produce proper error objects.

## Phase 5 — Send/receive with the internal wallet

Driven by the internal wallet from Phase 1, not by the JS wallet. The equivalent `qti3.js` commands stay gated: they exist to prove interop, not to be the shipped path.

- [x] 5.1–5.2 `qtc send <wallet-file> <to> <amount> [fee]` builds and signs. Single input only, as the v1 witness commits to one input; it says so rather than silently over-spending.
- [x] 5.3 Fee schedule frozen in `consensus.h` (D1): `MIN_TX_FEE = 1000`, `MEMPOOL_MAX_TRANSACTIONS = 100`, ordering by satoshis per byte.
- [x] 5.4 Signing goes through `Wallet::sign`, which calls `Transaction::sign_input` — the same `signature_hash` the node recomputes in `DAY5.md` §3.
- [x] 5.5 Public key and algorithm id attached; the node verifies the signature during validation.
- [x] 5.6 Broadcast via `sendrawtransaction`; works standalone too, reporting that no node is listening.
- [x] 5.7 **Change output.** Without one the entire remainder above `amount` was paid to the miner as fee. Found by a live run: alice's balance went to 0 and the mempool reported a 40 QTC fee.
- *Verify:* live run — alice sends 10 QTC, bob receives it, change returns, `alice + bob + miner + fee == alice_start + coinbase` asserted in the suite.

## Phase 6 — End-to-end

The `QTC Development Plan.md:150-154` flow, as an automated script.

- [x] 6.1 `mine 101 alice` → mature coins.
- [x] 6.2 `send bob 10` → wallet builds, signs, broadcasts.
- [x] 6.3 Transaction sits in the mempool; `getrawmempool` shows it.
- [x] 6.4 `mine 1` → confirmed in a block.
- [x] 6.5 `getbalance bob` → 10 QTC minus fee. Alice's balance drops by 10 + fee.
- [x] 6.6 Add the whole flow to the standing suite so it runs on every build.
- *Verify:* the documented commands produce the documented balances.

## Phase 7 — Negative tests

Per `QTC Development Plan.md:156-164`; the last three are Day 7 items but belong in the same harness.

- [x] 7.1 Bad signature → rejected.
- [x] 7.2 Double spend → rejected (mempool and consensus).
- [x] 7.3 Amount changed after signing → rejected. Also: wrong prev amount, unsigned spend, over-spend.
- [x] 7.4 Invalid block → no coinbase, wrong previous hash, contents mutated after mining.
- [x] 7.5 PoW → covered by the mining tests; regtest sits at minimum difficulty where a shifted nonce can still pass, so it is only asserted at a harder target.
- [x] 7.6 Node restart → height, balances and mempool all preserved, verified live.
- [x] 7.7 Chain persistence across restart, including a block with a real signed transaction.
- [x] 7.8 Malformed RPC input → bad hex, non-transaction bytes, unknown method, wrong param types, out-of-range height and count.
- **One bug this found:** `Block::deserialize` could not tell where one transaction ends and the next begins, so a coinbase followed by another transaction read the next version byte as a witness id. **No block with more than one transaction could be reloaded from disk.** The earlier persistence test missed it by only ever mining empty blocks. Fixed with an explicit `allow_witness` flag, now covered by a regression test.

---

## Design decisions needed

| # | Question | Recommendation |
|---|---|---|
| D1 | Fee schedule | Flat minimum plus a per-byte rate. Must be fixed in `DAY5.md` §2 before anything builds transactions, or every wallet guesses differently. |
| D5 | Does the internal wallet replace or wrap the reference? | Replace at runtime. `QTC-Wallet` stays a reference and cross-check oracle; the node must run without it. |
| D2 | Per-input witnesses now or later | **Later.** Keep the single-input rejection. It is honest and safe; per-input witnesses change the transaction format and deserve their own day. |
| D3 | RPC auth | None on loopback for now, documented. Anything reachable off-host needs auth before it ships. |
| D4 | Mempool persistence | Persist across restart. Otherwise Phase 1 is incomplete. |

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| `signature_hash` mismatch between wallet and node | Every spend rejected; hard to debug | Byte layout is already frozen in `DAY5.md` §3; add a cross-implementation test in Phase 4 |
| Consolidating inputs needs many signatures | Slow, and exposes the one-witness limit | Explicitly a Phase 4.2 concern; do not weaken the rejection rule |
| Mempool flood | Memory exhaustion | Capacity cap plus fee-ordered eviction (2.3) |
| Verification cost per transaction | Slow block validation for large blocks | Measure before raising `MAX_BLOCK_SIZE` |
| `Chain::load()` still stubbed | Restart silently wipes state | Phase 1 first; everything else depends on it |
| RPC on loopback without auth | Unsafe if ever exposed | Bind loopback, document, revisit before any public bind |

## Definition of done

1. The node signs a spend with its own internal wallet, with no JS wallet present.
2. A seed yields the same address in Core and in the reference wallet. ✅
3. Chain state survives a restart with identical height, hash and balances.
4. Mempool admits, orders, evicts and confirms correctly; double spends rejected.
5. JSON-RPC serves every listed method with correct errors.
6. `mine 101 → send → mine 1 → getbalance` produces the documented result.
7. All seven negative tests pass, wired into the standing suite.
8. Fee schedule frozen and documented alongside the transaction format.
9. The tree builds standalone, with no sibling reference folders present. ✅


## Explicitly out of scope

Mainnet addresses · testnet launch · P2P and block propagation · ML-KEM networking · BitcoinII monetary policy · per-input witnesses · ownership verification.

The Dilithium and Kyber C reference trees are present in `qtc-core/pq/`, but the
node does not depend on them for anything except FIPS-202. ML-DSA-65 and
ML-KEM-1024 come from liboqs.