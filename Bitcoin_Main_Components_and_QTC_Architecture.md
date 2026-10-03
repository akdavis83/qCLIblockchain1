# Bitcoin Main Components and QTC Architecture

## Overview

Bitcoin is not a single technology. It is a collection of interacting systems covering cryptography, transactions, UTXO accounting, blocks, blockchain storage, consensus, mining, networking, nodes, wallets, and applications.

## Main Components

| # | Component | Brief explanation |
|---|---|---|
| 1 | **1. Blockchain** | The blockchain is Bitcoin's permanent public historical record. Blocks are cryptographically linked through previous-block hashes. |
| 2 | **2. Block Structure** | A block packages transactions with consensus data such as the previous block hash, timestamp, difficulty target, nonce, and Merkle root. |
| 3 | **3. Consensus Mechanism** | Bitcoin uses Proof of Work (PoW) to establish which valid chain has the greatest accumulated computational work. |
| 4 | **4. Mining Algorithm** | Bitcoin mining uses double SHA-256 on block-header data. Miners repeatedly change adjustable fields, especially the nonce, until the resulting hash satisfies the current target. |
| 5 | **5. Mining** | Mining creates candidate blocks, performs Proof of Work, broadcasts successful blocks, and earns the block subsidy plus transaction fees. |
| 6 | **6. Difficulty Adjustment** | Bitcoin adjusts mining difficulty every 2,016 blocks so the long-term average block interval targets about 10 minutes. |
| 7 | **7. Block Reward** | A successful miner receives a block subsidy through the coinbase transaction plus transaction fees included in the block. |
| 8 | **8. Halving** | The block subsidy is reduced approximately every 210,000 blocks, roughly once every four years at the intended block interval. |
| 9 | **9. Transactions** | Bitcoin transactions consume previously unspent outputs and create new outputs with spending conditions. |
| 10 | **10. UTXO System** | UTXO means Unspent Transaction Output. Bitcoin tracks spendable outputs rather than maintaining conventional account balances. |
| 11 | **11. Script** | Bitcoin Script defines the conditions that must be satisfied to spend transaction outputs. It supports signatures, multisignature constructions, timelocks, Taproot-related spending conditions, and more. |
| 12 | **12. Cryptography** | Bitcoin traditionally uses ECDSA signatures over the secp256k1 elliptic curve for transaction authorization. |
| 13 | **13. Hashing** | SHA-256 is used extensively in Proof of Work, block hashing, Merkle trees, and other protocol operations. RIPEMD-160 is also used in legacy address construction. |
| 14 | **14. Merkle Tree** | Transactions in a block are combined into a Merkle tree, producing a single Merkle root that is committed to by the block header. |
| 15 | **15. Wallet** | A wallet manages private keys and related metadata, derives addresses, creates transactions, selects inputs, calculates fees, and signs transactions. |
| 16 | **16. Private Keys** | Private keys are secret cryptographic values that authorize spending under corresponding spending conditions. Anyone controlling the necessary private key material can generally authorize the associated funds. |
| 17 | **17. Public Keys** | Public keys are derived from private keys and are used by the network to verify digital signatures. |
| 18 | **18. Addresses** | Addresses are human-friendly representations of Bitcoin spending conditions. Major formats include legacy, P2SH, SegWit, and Taproot formats. |
| 19 | **19. Full Node** | A full node independently downloads, validates, and relays blocks and transactions according to Bitcoin's consensus rules. It does not simply trust miners. |
| 20 | **20. P2P Network** | Bitcoin uses a decentralized peer-to-peer network in which nodes communicate directly with other nodes to exchange transactions, blocks, and network information. |
| 21 | **21. Mempool** | A node's mempool holds valid, unconfirmed transactions that the node is willing to relay and potentially include in a future block. |
| 22 | **22. Block Propagation** | Nodes relay newly received valid blocks across the peer-to-peer network so other nodes can verify and build on them. |
| 23 | **23. Transaction Propagation** | Nodes relay transactions across the network before confirmation, subject to their local validation and relay policies. |
| 24 | **24. Chain Selection** | Bitcoin nodes follow the valid chain with the greatest accumulated Proof of Work, subject to the protocol's consensus rules. |
| 25 | **25. Confirmations** | A transaction receives its first confirmation when included in a valid block. Additional blocks built on top increase its depth in the chain. |
| 26 | **26. Monetary Policy** | Bitcoin's protocol defines a limited issuance schedule with a nominal maximum supply of 21 million BTC, subject to the exact consensus rules governing issuance. |
| 27 | **27. Genesis Block** | Block 0 is Bitcoin's genesis block and establishes the beginning of the blockchain. |
| 28 | **28. Coinbase Transaction** | The coinbase transaction is the special first transaction in a block that collects the block subsidy and eligible transaction fees for the miner. |
| 29 | **29. Transaction Fees** | Users attach fees to transactions to compensate miners for block-space consumption and to influence transaction inclusion priority. |
| 30 | **30. Time Mechanism** | Block timestamps and difficulty adjustment provide Bitcoin with a protocol-level approximation of time. They are not a centralized clock. |
| 31 | **31. Network Rules** | Consensus rules define what transactions and blocks are valid. Full nodes enforce these rules independently. |
| 32 | **32. Node Software** | Bitcoin Core is the dominant reference implementation, while other compatible implementations also exist. Node software implements validation, networking, storage, and related services. |
| 33 | **33. Mining Software** | Mining software constructs block templates and coordinates Proof of Work, usually sending work to specialized mining hardware. |
| 34 | **34. Mining Pools** | Mining pools coordinate many miners, distribute work, and generally distribute rewards according to contributed work under the pool's payout system. |
| 35 | **35. RPC Interface** | Bitcoin Core's RPC interface allows applications and scripts to query and control supported node functions programmatically. |
| 36 | **36. APIs and Explorers** | External services expose blockchain data in user-friendly forms. These are application-layer services rather than core consensus components. |
| 37 | **37. HD Wallets** | Hierarchical deterministic wallets derive many keys and addresses from wallet seed material, making backups and key management more practical. |
| 38 | **38. Seed Phrase** | A seed phrase is a human-readable representation of wallet seed material used by many wallet systems to recover derived keys. |
| 39 | **39. Script Types** | Bitcoin has multiple transaction/output constructions, including P2PKH, P2SH, SegWit constructions, and Taproot. |
| 40 | **40. Protocol Upgrades** | Bitcoin can evolve through proposals and consensus-compatible upgrades, commonly documented through Bitcoin Improvement Proposals (BIPs). |

## Bitcoin Architecture in Layers

```text
USER / APPLICATION
        |
       RPC
        |
        v
+-----------------------+
|         NODE          |
| Consensus validation  |
| UTXO set              |
| Mempool               |
| Blockchain            |
| Wallet                |
+----------+------------+
           |
       P2P Network
           |
           v
+-----------------------+
|        MINING         |
| Block template        |
| Proof of Work         |
| SHA-256               |
| Difficulty            |
+----------+------------+
           |
           v
       NEW BLOCK
           |
           v
+-----------------------+
|      BLOCKCHAIN       |
| Blocks                |
| Transactions          |
| Merkle roots          |
| Previous hashes       |
| Proof of Work         |
+-----------------------+
```

## Key Concepts

### Transactions and UTXOs

Bitcoin does not fundamentally maintain conventional account balances. Instead, transactions consume UTXOs and create new UTXOs.

Example:

```text
UTXO A = 1 BTC
UTXO B = 0.7 BTC
UTXO C = 0.3 BTC

Total controlled value = 2 BTC
```

A transaction spending 1.2 BTC might consume 1 BTC + 0.7 BTC and create:

```text
1.20 BTC -> recipient
0.49 BTC -> change
0.01 BTC -> miner fee
```

The consumed UTXOs become spent and the new outputs become future UTXOs.

### Mining

Bitcoin mining uses double SHA-256 Proof of Work:

```text
Block Header
     |
   SHA-256
     |
   SHA-256
     |
    Hash
```

The miner searches for a result below the current network target.

### Proof of Work

Proof of Work makes block production computationally expensive. Nodes select the valid chain with the greatest accumulated work, rather than simply trusting whichever miner announces a block.

### Difficulty

Bitcoin adjusts difficulty every 2,016 blocks. The intended average interval is approximately 10 minutes per block, making 2,016 blocks roughly two weeks.

### Wallets

A wallet generally manages:

- Seed material
- Private keys
- Public keys
- Addresses
- UTXO discovery
- Transaction construction
- Fee selection
- Transaction signing
- Backups

A wallet does not literally contain the coins. It manages the cryptographic information needed to control on-chain outputs.

### Full Nodes

A full node independently verifies:

- Transaction structure
- UTXO availability
- Digital signatures
- Script rules
- Block structure
- Proof of Work
- Block subsidy
- Consensus rules

A miner can propose a block, but nodes independently decide whether it is valid.

### P2P Network

Bitcoin nodes exchange transactions and blocks directly with peers. There is no central Bitcoin server responsible for maintaining the ledger.

### Mempool

The mempool is a node's pool of valid, unconfirmed transactions waiting for possible inclusion in a block. Different nodes can have different mempool contents.

### Merkle Trees

Transactions are recursively hashed into a Merkle tree. The resulting Merkle root is placed in the block header, committing the header to the block's transaction set.

## Bitcoin System Stack

```text
Cryptography
     |
Transactions
     |
UTXO Model
     |
Bitcoin Script
     |
Blocks
     |
Blockchain
     |
Consensus Rules
     |
Proof of Work
     |
Mining
     |
P2P Network
     |
Full Nodes
     |
Wallets / RPC / Applications
```

# QTC Comparison

The following maps the Bitcoin components to the QTC architecture discussed for the project.

| Bitcoin component | Bitcoin | QTC direction |
|---|---|---|
| Blockchain | Bitcoin blockchain | QTC blockchain |
| Consensus | Proof of Work | Proof of Work |
| Mining | SHA-256 | RandomX/Cuckoo-oriented design under consideration |
| Mining hardware | ASIC-dominated | CPU-oriented / ASIC-resistant goal |
| Signatures | ECDSA / secp256k1 | Dilithium 3 in the current QTC design |
| Key establishment | Classical cryptographic mechanisms | Kyber1024 where applicable |
| Hashing | SHA-256 | SHA3-512 preference / selected PQ-safe primitives |
| Addresses | bc1... and other formats | qtc1... target format |
| Transactions | UTXO | UTXO-style design |
| Node | Bitcoin Core and compatible nodes | QTC node |
| P2P | Bitcoin P2P | PQ-aware P2P design |
| Wallet | Bitcoin wallet ecosystem | QTC post-quantum wallet |
| Block structure | Bitcoin block format | QTC-specific format/rules |
| Block time | Target ~10 minutes | QTC-selected target |
| Supply | 21 million BTC | 84 million QTC design target |
| Block size | Bitcoin consensus limits | QTC-selected block limit |
| Mining reward | Bitcoin issuance schedule | QTC issuance schedule |
| Difficulty | Bitcoin retargeting | QTC retargeting |
| Script | Bitcoin Script | Compatible or modified QTC scripting |
| RPC | Bitcoin Core RPC | QTC RPC |
| Upgrades | BIPs | QTC improvement proposals |

## QTC Architecture Summary

The QTC design can be viewed as a Bitcoin-like modular stack in which the major areas are independently replaceable:

1. **Ledger:** UTXO-style blockchain.
2. **Consensus:** Proof of Work.
3. **Mining:** CPU-oriented / ASIC-resistant design using the RandomX/Cuckoo direction under development.
4. **Signatures:** Dilithium 3 in the current implementation direction.
5. **KEM / key establishment:** Kyber1024 where applicable.
6. **Hashing:** SHA3-512 preference.
7. **Addresses:** `qtc1...` target format.
8. **Networking:** QTC P2P with a post-quantum-aware handshake design.
9. **Wallet:** Post-quantum wallet capable of managing QTC keys and transactions.
10. **Node:** QTC node implementing validation, storage, networking, mempool, and RPC.
11. **Monetary policy:** 84 million QTC design target.
12. **Protocol:** QTC-specific block, difficulty, issuance, scripting, and upgrade rules.

## The Core Engineering Insight

Bitcoin is best understood as a set of interacting modules rather than one monolithic technology:

**Cryptography → Transactions → UTXO → Blocks → Blockchain → Consensus → Mining → P2P Network → Nodes → Wallets / Applications**

For a BTC-fork project such as QTC, each layer can be treated as a separate engineering subsystem. The critical task is ensuring that the interfaces between those subsystems are consistent and that every node can deterministically reach the same consensus result from the same blockchain state.

## Important Distinction

Some QTC items above are design targets or directions rather than statements about an independently verified production implementation. In particular, the mining algorithm, block parameters, post-quantum networking, and final protocol rules should be treated as project specifications until they are finalized, implemented, tested, and independently reviewed.
