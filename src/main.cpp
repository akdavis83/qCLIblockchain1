#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include <sstream>
#include "chain.h"
#include "block.h"
#include "transaction.h"
#include "utxo.h"
#include "mining.h"
#include "crypto.h"
#include "consensus.h"

namespace qtc {

static const char* network_name(Network net) {
    switch (net) {
        case Network::MAINNET: return "mainnet";
        case Network::TESTNET: return "testnet";
        case Network::REGTEST: return "regtest";
        default: return "unknown";
    }
}

static std::string format_qtc(uint64_t satoshis) {
    double qtc = static_cast<double>(satoshis) / static_cast<double>(COIN);
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(8) << qtc << " QTC";
    return ss.str();
}

static void print_usage() {
    std::cout
        << "QTC Protocol CLI v0.3\n"
        << "\n"
        << "Usage: qtc <command> [options]\n"
        << "\n"
        << "Chain commands:\n"
        << "  init                  Initialize QTC chain (regtest)\n"
        << "  getblockchaininfo      Display chain state\n"
        << "  getblock <height>      Display block at given height\n"
        << "  getblockhash <height>  Display block hash at given height\n"
        << "  validatechain          Validate the entire chain\n"
        << "\n"
        << "Mining commands:\n"
        << "  mine [n] [address]     Mine n blocks (default 1) to an address (default Miner)\n"
        << "  demo-day4              Run Day 4 mining demo (mine, validate, tamper test)\n"
        << "\n"
        << "Transaction/UTXO commands:\n"
        << "  demo-day3              Run Day 3 UTXO/transaction demo\n"
        << "  listunspent [address]   List all UTXOs (optionally for an address)\n"
        << "  getbalance <address>    Get balance for a dev-format address\n"
        << "\n"
        << "Testing:\n"
        << "  selftest               Run internal self-tests\n"
        << "  help                   Show this help\n"
        << "\n"
        << "Future commands (not yet implemented):\n"
        << "  wallet <create|balance|send|listunspent>\n"
        << "  tx <create|sign|validate|broadcast>\n"
        << "  mine [n] [address]\n"
        << "  node <start|status|stop>\n";
}

static void print_block(const Block& block, uint32_t height) {
    std::string hash_str = block.header.hash_hex();
    
    std::cout << "Block #" << height << "\n";
    std::cout << "  Version:          " << block.header.version << "\n";
    std::cout << "  Previous hash:    " << crypto::to_hex(block.header.prev_block_hash) << "\n";
    std::cout << "  Merkle root:      " << crypto::to_hex(block.header.merkle_root) << "\n";
    std::cout << "  Timestamp:        " << block.header.timestamp;
    
    time_t ts = block.header.timestamp;
    char time_buf[64];
    struct tm* tm_info = gmtime(&ts);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S UTC", tm_info);
    std::cout << " (" << time_buf << ")\n";
    
    std::cout << "  Difficulty bits:  0x" << std::hex << std::setfill('0') << std::setw(8)
              << block.header.difficulty_bits << std::dec << "\n";
    std::cout << "  Nonce:            " << block.header.nonce << "\n";
    std::cout << "  Block hash:       " << hash_str << "\n";
    std::cout << "  PoW valid:        " << (block.validate_pow() ? "YES" : "NO") << "\n";
    std::cout << "  Transactions:     " << block.transactions.size() << "\n";
    
    for (size_t i = 0; i < block.transactions.size(); ++i) {
        const auto& tx = block.transactions[i];
        std::cout << "    TX[" << i << "]: " << tx.txid_hex() << "\n";
        std::cout << "      Inputs:  " << tx.inputs.size() << "\n";
        std::cout << "      Outputs: " << tx.outputs.size() << "\n";
        std::cout << "      Coinbase: " << (tx.is_coinbase() ? "YES" : "NO") << "\n";
        if (tx.is_coinbase() && !tx.inputs.empty() && !tx.inputs[0].script.empty()) {
            std::string message;
            for (size_t j = 1; j < tx.inputs[0].script.size(); ++j) {
                char c = static_cast<char>(tx.inputs[0].script[j]);
                if (c >= 32 && c < 127) message += c;
            }
            if (!message.empty()) {
                std::cout << "      Message: " << message << "\n";
            }
        }
        for (size_t j = 0; j < tx.outputs.size(); ++j) {
            std::cout << "      Output[" << j << "]: " << format_qtc(tx.outputs[j].amount) << "\n";
            std::string addr = script::address_from(tx.outputs[j].script);
            if (!addr.empty()) {
                std::cout << "        To: " << addr << "\n";
            }
        }
    }
}

// ============================================================
// Day 3 Demo: UTXO lifecycle
// ============================================================

static int run_demo_day3() {
    std::cout << "=== QTC Day 3 Demo: Transactions & UTXO Set ===\n\n";
    
    // Initialize chain
    Chain chain;
    chain.init(Network::REGTEST);
    
    UTXOSet& utxos = chain.utxo_set();
    
    // The genesis block's coinbase created a UTXO, but it uses OP_TRUE
    // as the script (not a dev-format address). For the demo, we'll
    // create a fresh UTXO for Alice.
    
    std::cout << "--- Step 1: Create initial UTXO for Alice ---\n";
    
    // Create a coinbase-like transaction that pays Alice
    auto alice_script = script::for_address("Alice");
    Transaction alice_funding = Transaction::create_coinbase(
        1, "Demo: Alice funding", INITIAL_SUBSIDY, alice_script);
    
    std::cout << "Created funding transaction:\n";
    std::cout << "  TXID: " << alice_funding.txid_hex() << "\n";
    std::cout << "  Output: " << format_qtc(alice_funding.outputs[0].amount) << " to Alice\n\n";
    
    // Apply the funding transaction to the UTXO set
    std::string error;
    if (!utxos.apply_transaction(alice_funding, 1, error)) {
        std::cerr << "ERROR: Failed to apply funding tx: " << error << "\n";
        return 1;
    }
    std::cout << "Funding transaction applied to UTXO set.\n\n";
    
    // Show balances
    std::cout << "--- Step 2: Check balances ---\n";
    uint64_t alice_balance = utxos.get_balance_for_address("Alice");
    uint64_t bob_balance = utxos.get_balance_for_address("Bob");
    std::cout << "Alice balance: " << format_qtc(alice_balance) << "\n";
    std::cout << "Bob balance:   " << format_qtc(bob_balance) << "\n";
    std::cout << "UTXO count:    " << utxos.size() << "\n\n";
    
    // Step 3: Create Alice → Bob transaction
    std::cout << "--- Step 3: Alice sends 10 QTC to Bob ---\n";
    
    // Find Alice's UTXO
    auto alice_utxos = utxos.list_unspent_for_address("Alice");
    if (alice_utxos.empty()) {
        std::cerr << "ERROR: Alice has no UTXOs\n";
        return 1;
    }
    
    const UTXO& alice_utxo = alice_utxos[0];
    uint64_t send_amount = 10 * COIN;
    uint64_t fee = COIN / 10;  // 0.1 QTC — integer math, no floating point
    uint64_t change_amount = alice_utxo.amount - send_amount - fee;
    
    std::cout << "Input UTXO: " << alice_utxo.outpoint.key() << "\n";
    std::cout << "  Amount: " << format_qtc(alice_utxo.amount) << "\n";
    std::cout << "Sending: " << format_qtc(send_amount) << " to Bob\n";
    std::cout << "Fee:     " << format_qtc(fee) << "\n";
    std::cout << "Change:  " << format_qtc(change_amount) << " to Alice\n\n";
    
    // Build the transaction
    Transaction send_tx;
    send_tx.version = TX_VERSION;
    
    // Input: Alice's UTXO
    TxInput input;
    input.prevout = alice_utxo.outpoint;
    input.script = {};  // Empty script — Day 5 will add PQ signature
    input.sequence = 0xffffffff;
    send_tx.inputs.push_back(input);
    
    // Output 1: 10 QTC to Bob
    TxOutput out_bob;
    out_bob.amount = send_amount;
    out_bob.script = script::for_address("Bob");
    send_tx.outputs.push_back(out_bob);
    
    // Output 2: Change to Alice
    TxOutput out_alice;
    out_alice.amount = change_amount;
    out_alice.script = script::for_address("Alice");
    send_tx.outputs.push_back(out_alice);
    
    std::cout << "Transaction created:\n";
    std::cout << "  TXID: " << send_tx.txid_hex() << "\n";
    std::cout << "  Inputs:  1\n";
    std::cout << "  Outputs: 2\n\n";
    
    // Step 4: Validate the transaction
    std::cout << "--- Step 4: Validate transaction ---\n";
    if (utxos.validate_transaction(send_tx, error)) {
        std::cout << "Transaction validation: PASSED\n\n";
    } else {
        std::cerr << "Transaction validation: FAILED: " << error << "\n\n";
        return 1;
    }
    
    // Step 5: Apply the transaction
    std::cout << "--- Step 5: Apply transaction ---\n";
    if (!utxos.apply_transaction(send_tx, 1, error)) {
        std::cerr << "ERROR: Failed to apply transaction: " << error << "\n";
        return 1;
    }
    std::cout << "Transaction applied to UTXO set.\n\n";
    
    // Step 6: Check new balances
    std::cout << "--- Step 6: Check new balances ---\n";
    alice_balance = utxos.get_balance_for_address("Alice");
    bob_balance = utxos.get_balance_for_address("Bob");
    std::cout << "Alice balance: " << format_qtc(alice_balance) << "\n";
    std::cout << "Bob balance:   " << format_qtc(bob_balance) << "\n";
    std::cout << "UTXO count:    " << utxos.size() << "\n\n";
    
    // Step 7: List all UTXOs
    std::cout << "--- Step 7: List all UTXOs ---\n";
    auto all_alice = utxos.list_unspent_for_address("Alice");
    auto all_bob = utxos.list_unspent_for_address("Bob");
    std::cout << "Alice's UTXOs:\n";
    for (const auto& u : all_alice) {
        std::cout << "  " << u.outpoint.key() << " = " << format_qtc(u.amount) << "\n";
    }
    std::cout << "Bob's UTXOs:\n";
    for (const auto& u : all_bob) {
        std::cout << "  " << u.outpoint.key() << " = " << format_qtc(u.amount) << "\n";
    }
    std::cout << "\n";
    
    // Step 8: Try double-spend (should fail)
    std::cout << "--- Step 8: Attempt double-spend (should fail) ---\n";
    Transaction double_spend;
    double_spend.version = TX_VERSION;
    TxInput ds_input;
    ds_input.prevout = alice_utxo.outpoint;  // Same UTXO, already spent
    ds_input.script = {};
    ds_input.sequence = 0xffffffff;
    double_spend.inputs.push_back(ds_input);
    
    TxOutput ds_output;
    ds_output.amount = send_amount;
    ds_output.script = script::for_address("Charlie");
    double_spend.outputs.push_back(ds_output);
    
    if (utxos.validate_transaction(double_spend, error)) {
        std::cout << "Double-spend validation: PASSED (BUG!)\n";
    } else {
        std::cout << "Double-spend validation: REJECTED\n";
        std::cout << "  Error: " << error << "\n";
    }
    std::cout << "\n";
    
    // Step 9: Try overspend (should fail)
    std::cout << "--- Step 9: Attempt overspend (should fail) ---\n";
    // Bob only has 10 QTC, try to send 100 QTC
    auto bob_utxos = utxos.list_unspent_for_address("Bob");
    if (!bob_utxos.empty()) {
        Transaction overspend;
        overspend.version = TX_VERSION;
        TxInput os_input;
        os_input.prevout = bob_utxos[0].outpoint;
        os_input.script = {};
        os_input.sequence = 0xffffffff;
        overspend.inputs.push_back(os_input);
        
        TxOutput os_output;
        os_output.amount = 100 * COIN;  // Way more than Bob has
        os_output.script = script::for_address("Charlie");
        overspend.outputs.push_back(os_output);
        
        if (utxos.validate_transaction(overspend, error)) {
            std::cout << "Overspend validation: PASSED (BUG!)\n";
        } else {
            std::cout << "Overspend validation: REJECTED\n";
            std::cout << "  Error: " << error << "\n";
        }
    }
    std::cout << "\n";
    
    // Step 10: Try duplicate inputs (should fail)
    std::cout << "--- Step 10: Attempt duplicate inputs (should fail) ---\n";
    Transaction dup_tx;
    dup_tx.version = TX_VERSION;
    // Use two copies of the same input
    TxInput dup_input1;
    dup_input1.prevout = bob_utxos[0].outpoint;
    dup_input1.script = {};
    dup_input1.sequence = 0xffffffff;
    dup_tx.inputs.push_back(dup_input1);
    dup_tx.inputs.push_back(dup_input1);  // Duplicate
    
    TxOutput dup_output;
    dup_output.amount = 5 * COIN;
    dup_output.script = script::for_address("Charlie");
    dup_tx.outputs.push_back(dup_output);
    
    if (utxos.validate_transaction(dup_tx, error)) {
        std::cout << "Duplicate input validation: PASSED (BUG!)\n";
    } else {
        std::cout << "Duplicate input validation: REJECTED\n";
        std::cout << "  Error: " << error << "\n";
    }
    std::cout << "\n";
    
    // Step 11: Serialize/deserialize round-trip
    std::cout << "--- Step 11: Transaction serialization round-trip ---\n";
    auto serialized = send_tx.serialize();
    auto deserialized = Transaction::deserialize(serialized);
    bool roundtrip_ok = (send_tx.txid_hex() == deserialized.txid_hex());
    std::cout << "Original TXID:    " << send_tx.txid_hex() << "\n";
    std::cout << "Deserialized TXID: " << deserialized.txid_hex() << "\n";
    std::cout << "Round-trip: " << (roundtrip_ok ? "MATCH" : "MISMATCH") << "\n";
    std::cout << "Serialized size: " << serialized.size() << " bytes\n\n";
    
    // Summary
    std::cout << "=== Day 3 Demo Complete ===\n";
    std::cout << "\nFinal state:\n";
    std::cout << "  Alice: " << format_qtc(utxos.get_balance_for_address("Alice")) << "\n";
    std::cout << "  Bob:   " << format_qtc(utxos.get_balance_for_address("Bob")) << "\n";
    std::cout << "  UTXO count: " << utxos.size() << "\n";
    
    return 0;
}

// ============================================================
// Day 4 Demo: SHA-256 Mining
// ============================================================

static int run_demo_day4() {
    std::cout << "=== QTC Day 4 Demo: SHA-256 Mining ===\n\n";
    
    // Initialize chain
    Chain chain;
    chain.init(Network::REGTEST);
    
    std::cout << "Starting height: " << chain.height() << "\n";
    std::cout << "Genesis hash: " << chain.tip().header.hash_hex() << "\n\n";
    
    // Step 1: Mine 3 blocks to Alice
    std::cout << "--- Step 1: Mine 3 blocks to Alice ---\n";
    uint32_t mined = mine_n_blocks(chain, 3, "Alice");
    std::cout << "Mined " << mined << " blocks.\n\n";
    
    std::cout << "Chain height: " << chain.height() << "\n";
    std::cout << "Alice balance: " << format_qtc(chain.utxo_set().get_balance_for_address("Alice")) << "\n\n";
    
    // Step 2: Validate the chain
    std::cout << "--- Step 2: Validate the chain ---\n";
    if (chain.validate_chain()) {
        std::cout << "Chain validation: PASSED\n\n";
    } else {
        std::cout << "Chain validation: FAILED\n\n";
        return 1;
    }
    
    // Step 3: Show block details
    std::cout << "--- Step 3: Block details ---\n";
    for (uint32_t h = 1; h <= chain.height(); ++h) {
        const auto& block = chain.get_block(h);
        std::cout << "Block " << h << ": hash=" << block.header.hash_hex()
                  << " nonce=" << block.header.nonce
                  << " txs=" << block.transactions.size() << "\n";
        if (!block.transactions.empty() && block.transactions[0].is_coinbase()) {
            std::cout << "  Coinbase: " << format_qtc(block.transactions[0].outputs[0].amount) << " to Alice\n";
        }
    }
    std::cout << "\n";
    
    // Step 4: Tamper test — break a block and verify validation fails
    std::cout << "--- Step 4: Tamper test ---\n";
    std::cout << "Modifying block 2's coinbase amount from 50 to 100 QTC...\n";
    
    // Tamper with block 2's coinbase output
    const_cast<Block&>(chain.get_block(2)).transactions[0].outputs[0].amount = 100 * COIN;
    
    std::cout << "Re-validating chain...\n";
    if (chain.validate_chain()) {
        std::cout << "Chain validation: PASSED (BUG!)\n\n";
    } else {
        std::cout << "Chain validation: FAILED (expected — merkle root mismatch)\n\n";
    }
    
    // Step 5: Bad PoW test
    std::cout << "--- Step 5: Bad PoW test ---\n";
    {
        Block block = create_block_template(chain, "Attacker");
        mine_block(block);
        
        // Switch to harder difficulty — the mined nonce won't be valid
        block.header.difficulty_bits = 0x1d00ffff;
        std::cout << "Attempting to add block with invalid PoW (harder difficulty)...\n";
        std::cout << "Block accepted: " << (chain.add_block(block) ? "YES (BUG!)" : "NO (correct)") << "\n\n";
    }
    
    // Step 6: Excessive subsidy test
    std::cout << "--- Step 6: Excessive subsidy test ---\n";
    {
        Block block;
        block.header.version = BLOCK_VERSION;
        block.header.prev_block_hash = chain.tip().header.hash();
        block.header.difficulty_bits = REGTEST_MINING_BITS;
        block.header.timestamp = chain.tip().header.timestamp + BLOCK_INTERVAL;
        
        Transaction cb = Transaction::create_coinbase(
            chain.height() + 1, "Greedy miner", 100 * COIN,
            script::for_address("Greedy")
        );
        block.transactions.push_back(cb);
        block.header.merkle_root = block.compute_merkle_root();
        mine_block(block);
        
        std::cout << "Attempting to add block with 100 QTC coinbase (max is 50)...\n";
        std::cout << "Block accepted: " << (chain.add_block(block) ? "YES (BUG!)" : "NO (correct)") << "\n\n";
    }
    
    // Summary
    std::cout << "=== Day 4 Demo Complete ===\n";
    std::cout << "\nFinal state:\n";
    std::cout << "  Height: " << chain.height() << "\n";
    std::cout << "  Alice balance: " << format_qtc(chain.utxo_set().get_balance_for_address("Alice")) << "\n";
    std::cout << "  UTXO count: " << chain.utxo_set().size() << "\n";
    
    return 0;
}

// ============================================================
// Self-tests
// ============================================================

static int run_selftest() {
    int passed = 0;
    int failed = 0;
    
    auto check = [&](const std::string& name, bool condition) {
        if (condition) {
            std::cout << "[PASS] " << name << "\n";
            passed++;
        } else {
            std::cout << "[FAIL] " << name << "\n";
            failed++;
        }
    };
    
    std::cout << "=== QTC Self-Test ===\n\n";
    
    // --- Day 1-2 tests (unchanged) ---
    
    check("SHA-256 known answer (abc)",
          crypto::to_hex(crypto::sha256(std::vector<uint8_t>{'a','b','c'}))
          == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    
    check("Double SHA-256 produces 32 bytes",
          crypto::double_sha256(std::vector<uint8_t>{'a','b','c'}).size() == 32);
    
    {
        std::vector<uint8_t> original = {0x00, 0x01, 0x02, 0xFF, 0xAB, 0xCD};
        check("Hex round-trip", original == crypto::from_hex(crypto::to_hex(original)));
    }
    
    {
        uint32_t val = 0x12345678;
        auto bytes = crypto::write_le_u32(val);
        check("LE u32 round-trip", val == crypto::read_le_u32(bytes.data()));
    }
    
    {
        Block g1 = Block::create_regtest_genesis();
        Block g2 = Block::create_regtest_genesis();
        check("Genesis block is deterministic", g1.header.hash_hex() == g2.header.hash_hex());
    }
    
    {
        Block genesis = Block::create_regtest_genesis();
        check("Genesis block PoW is valid", genesis.validate_pow());
    }
    
    {
        Block genesis = Block::create_regtest_genesis();
        bool has_cb = !genesis.transactions.empty() && genesis.transactions[0].is_coinbase();
        check("Genesis block has coinbase", has_cb);
    }
    
    {
        Block genesis = Block::create_regtest_genesis();
        check("Genesis coinbase reward is 50 QTC",
              genesis.transactions[0].outputs[0].amount == INITIAL_SUBSIDY);
    }
    
    {
        Block genesis = Block::create_regtest_genesis();
        auto computed = genesis.compute_merkle_root();
        bool matches = (computed.size() == 32);
        for (size_t i = 0; i < 32 && i < genesis.header.merkle_root.size(); ++i) {
            if (computed[i] != genesis.header.merkle_root[i]) { matches = false; break; }
        }
        check("Genesis merkle root matches computed root", matches);
    }
    
    {
        Chain chain;
        chain.init(Network::REGTEST);
        auto info = chain.get_blockchain_info();
        check("Chain initializes with height 0", info.height == 0);
        check("Chain reports as initialized", info.initialized);
        check("Chain is regtest", info.network == Network::REGTEST);
    }
    
    {
        Transaction tx = Transaction::create_genesis_coinbase("TEST", 50 * COIN);
        check("Genesis coinbase serializes to non-empty", !tx.serialize().empty());
        check("Genesis coinbase txid is 32 bytes", tx.txid().size() == 32);
    }
    
    {
        Block genesis = Block::create_regtest_genesis();
        check("Block header is exactly 80 bytes", genesis.header.serialize().size() == 80);
    }
    
    // --- Day 3 tests ---
    
    std::cout << "\n--- Day 3: Transactions & UTXO ---\n\n";
    
    // CompactSize round-trip
    {
        uint64_t small = 100;
        uint64_t medium = 300;
        uint64_t large = 100000;
        uint64_t huge = 5000000000ULL;
        
        auto s_bytes = crypto::write_compact_size(small);
        auto m_bytes = crypto::write_compact_size(medium);
        auto l_bytes = crypto::write_compact_size(large);
        auto h_bytes = crypto::write_compact_size(huge);
        
        size_t offset = 0;
        check("CompactSize small round-trip",
              crypto::read_compact_size(s_bytes.data(), offset) == small && offset == 1);
        offset = 0;
        check("CompactSize medium round-trip",
              crypto::read_compact_size(m_bytes.data(), offset) == medium && offset == 3);
        offset = 0;
        check("CompactSize large round-trip",
              crypto::read_compact_size(l_bytes.data(), offset) == large && offset == 5);
        offset = 0;
        check("CompactSize huge round-trip",
              crypto::read_compact_size(h_bytes.data(), offset) == huge && offset == 9);
    }
    
    // Script helpers
    {
        auto script = qtc::script::for_address("Alice");
        check("Script for address creates dev-format script", qtc::script::is_dev_script(script));
        check("Script address extraction", qtc::script::address_from(script) == "Alice");
        
        auto not_script = std::vector<uint8_t>{0x51};
        check("Non-dev script detected", !qtc::script::is_dev_script(not_script));
    }
    
    // OutPoint key and comparison
    {
        OutPoint a;
        a.txid = std::vector<uint8_t>(32, 0xAA);
        a.vout = 0;
        OutPoint b;
        b.txid = std::vector<uint8_t>(32, 0xAA);
        b.vout = 0;
        OutPoint c;
        c.txid = std::vector<uint8_t>(32, 0xBB);
        c.vout = 1;
        
        check("OutPoint equality", a == b);
        check("OutPoint key matches", a.key() == b.key());
        check("OutPoint less-than", a < c);
    }
    
    // Transaction serialization/deserialization round-trip
    {
        Transaction tx;
        tx.version = TX_VERSION;
        
        TxInput input;
        input.prevout.txid = std::vector<uint8_t>(32, 0x42);
        input.prevout.vout = 5;
        input.script = {0x51, 0x52, 0x53};
        input.sequence = 0x12345678;
        tx.inputs.push_back(input);
        
        TxOutput out1;
        out1.amount = 10 * COIN;
        out1.script = qtc::script::for_address("Bob");
        tx.outputs.push_back(out1);
        
        TxOutput out2;
        out2.amount = 39 * COIN;
        out2.script = qtc::script::for_address("Alice");
        tx.outputs.push_back(out2);
        
        auto serialized = tx.serialize();
        auto deserialized = Transaction::deserialize(serialized);
        
        check("TX serialization round-trip: txid matches",
              tx.txid_hex() == deserialized.txid_hex());
        check("TX serialization round-trip: version",
              tx.version == deserialized.version);
        check("TX serialization round-trip: input count",
              tx.inputs.size() == deserialized.inputs.size());
        check("TX serialization round-trip: output count",
              tx.outputs.size() == deserialized.outputs.size());
        check("TX serialization round-trip: input prevout vout",
              tx.inputs[0].prevout.vout == deserialized.inputs[0].prevout.vout);
        check("TX serialization round-trip: input script",
              tx.inputs[0].script == deserialized.inputs[0].script);
        check("TX serialization round-trip: output amount",
              tx.outputs[0].amount == deserialized.outputs[0].amount);
        check("TX serialization round-trip: output script",
              tx.outputs[0].script == deserialized.outputs[0].script);
    }
    
    // UTXO set basic operations
    {
        UTXOSet utxos;
        
        OutPoint op;
        op.txid = std::vector<uint8_t>(32, 0x11);
        op.vout = 0;
        
        utxos.add_utxo(op, 50 * COIN, qtc::script::for_address("Alice"), 1, false);
        
        check("UTXO set: have_utxo after add", utxos.have_utxo(op));
        check("UTXO set: size is 1", utxos.size() == 1);
        check("UTXO set: get_balance for Alice", utxos.get_balance_for_address("Alice") == 50 * COIN);
        check("UTXO set: get_balance for Bob is 0", utxos.get_balance_for_address("Bob") == 0);
        check("UTXO set: total_value", utxos.total_value() == 50 * COIN);
        
        // Spend the UTXO
        check("UTXO set: spend_utxo returns true", utxos.spend_utxo(op));
        check("UTXO set: have_utxo after spend is false", !utxos.have_utxo(op));
        check("UTXO set: size is 0 after spend", utxos.size() == 0);
        check("UTXO set: balance is 0 after spend", utxos.get_balance_for_address("Alice") == 0);
    }
    
    // UTXO set: transaction validation
    {
        UTXOSet utxos;
        
        // Create a funding UTXO for Alice
        OutPoint alice_utxo;
        alice_utxo.txid = std::vector<uint8_t>(32, 0xAA);
        alice_utxo.vout = 0;
        utxos.add_utxo(alice_utxo, 50 * COIN, qtc::script::for_address("Alice"), 1, false);
        
        // Create a valid transaction: Alice sends 10 QTC to Bob, 39.9 change
        Transaction tx;
        tx.version = TX_VERSION;
        
        TxInput input;
        input.prevout = alice_utxo;
        input.script = {};
        input.sequence = 0xffffffff;
        tx.inputs.push_back(input);
        
        TxOutput out_bob;
        out_bob.amount = 10 * COIN;
        out_bob.script = qtc::script::for_address("Bob");
        tx.outputs.push_back(out_bob);
        
        TxOutput out_change;
        out_change.amount = 39 * COIN + 90000000;  // 39.9 QTC
        out_change.script = qtc::script::for_address("Alice");
        tx.outputs.push_back(out_change);
        
        std::string error;
        check("TX validation: valid transaction passes", utxos.validate_transaction(tx, error));
        
        // Apply the transaction
        check("TX apply: valid transaction applied", utxos.apply_transaction(tx, 2, error));
        check("TX apply: Alice balance after send",
              utxos.get_balance_for_address("Alice") == 39 * COIN + 90000000);
        check("TX apply: Bob balance after receive",
              utxos.get_balance_for_address("Bob") == 10 * COIN);
        check("TX apply: original UTXO spent", !utxos.have_utxo(alice_utxo));
        
        // Try double-spend
        check("TX validation: double-spend rejected",
              !utxos.validate_transaction(tx, error));
    }
    
    // UTXO set: duplicate input rejection
    {
        UTXOSet utxos;
        
        OutPoint op;
        op.txid = std::vector<uint8_t>(32, 0x22);
        op.vout = 0;
        utxos.add_utxo(op, 100 * COIN, qtc::script::for_address("Test"), 1, false);
        
        Transaction tx;
        tx.version = TX_VERSION;
        
        TxInput input1;
        input1.prevout = op;
        input1.script = {};
        tx.inputs.push_back(input1);
        
        TxInput input2;
        input2.prevout = op;  // Same UTXO!
        input2.script = {};
        tx.inputs.push_back(input2);
        
        TxOutput out;
        out.amount = 50 * COIN;
        out.script = qtc::script::for_address("Dest");
        tx.outputs.push_back(out);
        
        std::string error;
        check("TX validation: duplicate input rejected",
              !utxos.validate_transaction(tx, error));
    }
    
    // UTXO set: overspend rejection
    {
        UTXOSet utxos;
        
        OutPoint op;
        op.txid = std::vector<uint8_t>(32, 0x33);
        op.vout = 0;
        utxos.add_utxo(op, 10 * COIN, qtc::script::for_address("Test"), 1, false);
        
        Transaction tx;
        tx.version = TX_VERSION;
        
        TxInput input;
        input.prevout = op;
        input.script = {};
        tx.inputs.push_back(input);
        
        TxOutput out;
        out.amount = 100 * COIN;  // Way more than input
        out.script = qtc::script::for_address("Dest");
        tx.outputs.push_back(out);
        
        std::string error;
        check("TX validation: overspend rejected",
              !utxos.validate_transaction(tx, error));
    }
    
    // UTXO set: missing input rejection
    {
        UTXOSet utxos;
        
        OutPoint op;
        op.txid = std::vector<uint8_t>(32, 0x44);
        op.vout = 0;
        // Don't add the UTXO
        
        Transaction tx;
        tx.version = TX_VERSION;
        
        TxInput input;
        input.prevout = op;
        input.script = {};
        tx.inputs.push_back(input);
        
        TxOutput out;
        out.amount = 10 * COIN;
        out.script = qtc::script::for_address("Dest");
        tx.outputs.push_back(out);
        
        std::string error;
        check("TX validation: missing input rejected",
              !utxos.validate_transaction(tx, error));
    }
    
    // Chain UTXO integration
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        // Genesis block has a coinbase with OP_TRUE script
        // The UTXO set should have that UTXO
        check("Chain UTXO: genesis creates UTXO", chain.utxo_set().size() >= 1);
    }
    
    // Coinbase creation and validation
    {
        UTXOSet utxos;
        auto cb = Transaction::create_coinbase(1, "Test coinbase", 50 * COIN,
                                               qtc::script::for_address("Miner"));
        std::string error;
        check("Coinbase validation passes", utxos.validate_transaction(cb, error));
        check("Coinbase apply succeeds", utxos.apply_transaction(cb, 1, error));
        check("Coinbase creates UTXO for miner",
              utxos.get_balance_for_address("Miner") == 50 * COIN);
    }
    
    // Multiple UTXOs and balance calculation
    {
        UTXOSet utxos;
        
        // Add 3 UTXOs for Alice
        for (int i = 0; i < 3; ++i) {
            OutPoint op;
            op.txid = std::vector<uint8_t>(32, 0x10 + i);
            op.vout = 0;
            utxos.add_utxo(op, 10 * COIN, qtc::script::for_address("Alice"), 1, false);
        }
        
        // Add 2 UTXOs for Bob
        for (int i = 0; i < 2; ++i) {
            OutPoint op;
            op.txid = std::vector<uint8_t>(32, 0x20 + i);
            op.vout = 0;
            utxos.add_utxo(op, 5 * COIN, qtc::script::for_address("Bob"), 1, false);
        }
        
        check("Multiple UTXOs: Alice balance = 30 QTC",
              utxos.get_balance_for_address("Alice") == 30 * COIN);
        check("Multiple UTXOs: Bob balance = 10 QTC",
              utxos.get_balance_for_address("Bob") == 10 * COIN);
        check("Multiple UTXOs: total UTXO count = 5", utxos.size() == 5);
        check("Multiple UTXOs: total value = 40 QTC",
              utxos.total_value() == 40 * COIN);
        check("Multiple UTXOs: Alice has 3 UTXOs",
              utxos.list_unspent_for_address("Alice").size() == 3);
    }
    
    // Block-level double-spend rejection (two txs in same block spending same UTXO)
    {
        UTXOSet utxos;
        
        // Fund Alice
        OutPoint op;
        op.txid = std::vector<uint8_t>(32, 0x55);
        op.vout = 0;
        utxos.add_utxo(op, 50 * COIN, qtc::script::for_address("Alice"), 1, false);
        
        // Create two transactions that both spend the same UTXO
        auto make_tx = [&](uint64_t amount) {
            Transaction tx;
            tx.version = TX_VERSION;
            TxInput input;
            input.prevout = op;
            input.script = {};
            input.sequence = 0xffffffff;
            tx.inputs.push_back(input);
            TxOutput out;
            out.amount = amount;
            out.script = qtc::script::for_address("Dest");
            tx.outputs.push_back(out);
            return tx;
        };
        
        Transaction tx1 = make_tx(10 * COIN);
        Transaction tx2 = make_tx(10 * COIN);  // Same input!
        
        // Apply tx1 first — should succeed
        std::string error;
        check("Block double-spend: tx1 applies", utxos.apply_transaction(tx1, 2, error));
        
        // Try to apply tx2 — should fail (UTXO already spent)
        check("Block double-spend: tx2 rejected after tx1",
              !utxos.apply_transaction(tx2, 2, error));
    }
    
    // --- Day 4: SHA-256 Mining ---
    
    std::cout << "\n--- Day 4: SHA-256 Mining ---\n\n";
    
    // Block subsidy calculation
    {
        check("Subsidy at height 0 = 50 QTC", get_block_subsidy(0) == 50 * COIN);
        check("Subsidy at height 1 = 50 QTC", get_block_subsidy(1) == 50 * COIN);
        check("Subsidy at height 209999 = 50 QTC", get_block_subsidy(209999) == 50 * COIN);
        check("Subsidy at height 210000 = 25 QTC", get_block_subsidy(210000) == 25 * COIN);
        check("Subsidy at height 420000 = 12.5 QTC", get_block_subsidy(420000) == 1250000000);
    }
    
    // Block template creation
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block tmpl = create_block_template(chain, "Miner");
        
        check("Block template: has coinbase", 
              !tmpl.transactions.empty() && tmpl.transactions[0].is_coinbase());
        check("Block template: links to genesis",
              tmpl.header.prev_block_hash == chain.tip().header.hash());
        check("Block template: has merkle root", tmpl.header.merkle_root.size() == 32);
        check("Block template: difficulty is regtest", tmpl.header.difficulty_bits == REGTEST_MINING_BITS);
        check("Block template: coinbase pays 50 QTC",
              tmpl.transactions[0].outputs[0].amount == 50 * COIN);
    }
    
    // Mine a single block
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block = create_block_template(chain, "Miner");
        MiningResult result = mine_block(block);
        
        check("Mining: finds valid nonce", result.found);
        check("Mining: PoW is valid", block.validate_pow());
        check("Mining: hash is 64 hex chars", result.hash_hex.length() == 64);
    }
    
    // Mine and add a block to the chain
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block = create_block_template(chain, "Miner");
        mine_block(block);
        
        check("Mine+add: chain accepts mined block", chain.add_block(block));
        check("Mine+add: height increases to 1", chain.height() == 1);
        check("Mine+add: miner balance is 50 QTC",
              chain.utxo_set().get_balance_for_address("Miner") == 50 * COIN);
    }
    
    // Mine 3 blocks
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        uint32_t mined = mine_n_blocks(chain, 3, "Alice");
        
        check("Mine 3: all blocks mined", mined == 3);
        check("Mine 3: height is 3", chain.height() == 3);
        check("Mine 3: Alice has 150 QTC (3 * 50)",
              chain.utxo_set().get_balance_for_address("Alice") == 150 * COIN);
    }
    
    // Chain validation after mining
    {
        Chain chain;
        chain.init(Network::REGTEST);
        mine_n_blocks(chain, 5, "Miner");
        
        check("Validate chain after mining: passes", chain.validate_chain());
        check("Validate chain: height is 5", chain.height() == 5);
    }
    
    // Bad nonce causes PoW failure
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block = create_block_template(chain, "Miner");
        MiningResult result = mine_block(block);
        
        // Switch to a harder difficulty target — the mined nonce
        // almost certainly won't produce a valid hash at this difficulty
        block.header.difficulty_bits = 0x1d00ffff;  // Bitcoin-like difficulty
        
        check("Bad nonce: PoW invalid at harder difficulty", !block.validate_pow());
    }
    
    // Tampered transaction causes merkle root mismatch
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block = create_block_template(chain, "Miner");
        mine_block(block);
        chain.add_block(block);
        
        // Tamper: change the coinbase output amount
        const_cast<Block&>(chain.get_block(1)).transactions[0].outputs[0].amount = 100 * COIN;
        
        check("Tampered tx: chain validation fails", !chain.validate_chain());
    }
    
    // Invalid previous hash is rejected
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block = create_block_template(chain, "Miner");
        mine_block(block);
        
        // Tamper: corrupt the previous hash
        block.header.prev_block_hash[0] ^= 0xFF;
        
        check("Invalid prev hash: block rejected", !chain.add_block(block));
    }
    
    // Coinbase not first is rejected
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block;
        block.header.version = BLOCK_VERSION;
        block.header.prev_block_hash = chain.tip().header.hash();
        block.header.difficulty_bits = REGTEST_MINING_BITS;
        block.header.timestamp = chain.tip().header.timestamp + BLOCK_INTERVAL;
        
        // Add a non-coinbase transaction as first tx
        Transaction tx;
        tx.version = TX_VERSION;
        TxInput input;
        input.prevout.txid = std::vector<uint8_t>(32, 0x99);
        input.prevout.vout = 0;
        input.script = {};
        input.sequence = 0xffffffff;
        tx.inputs.push_back(input);
        TxOutput out;
        out.amount = 10 * COIN;
        out.script = script::for_address("Test");
        tx.outputs.push_back(out);
        block.transactions.push_back(tx);
        
        block.header.merkle_root = block.compute_merkle_root();
        mine_block(block);
        
        check("No coinbase first: block rejected", !chain.add_block(block));
    }
    
    // Excessive coinbase subsidy is rejected
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block;
        block.header.version = BLOCK_VERSION;
        block.header.prev_block_hash = chain.tip().header.hash();
        block.header.difficulty_bits = REGTEST_MINING_BITS;
        block.header.timestamp = chain.tip().header.timestamp + BLOCK_INTERVAL;
        
        // Create coinbase with too much reward (100 QTC instead of 50)
        Transaction cb = Transaction::create_coinbase(
            1, "Overspend", 100 * COIN,
            script::for_address("Greedy")
        );
        block.transactions.push_back(cb);
        block.header.merkle_root = block.compute_merkle_root();
        mine_block(block);
        
        check("Excessive subsidy: block rejected", !chain.add_block(block));
    }
    
    // Empty block is rejected
    {
        Chain chain;
        chain.init(Network::REGTEST);
        
        Block block;
        block.header.version = BLOCK_VERSION;
        block.header.prev_block_hash = chain.tip().header.hash();
        block.header.difficulty_bits = REGTEST_MINING_BITS;
        block.header.timestamp = chain.tip().header.timestamp + BLOCK_INTERVAL;
        block.header.merkle_root = block.compute_merkle_root();
        mine_block(block);
        
        check("Empty block rejected", !chain.add_block(block));
    }
    
    // Block linking: each block's prev_hash matches previous
    {
        Chain chain;
        chain.init(Network::REGTEST);
        mine_n_blocks(chain, 3, "Miner");
        
        auto h0 = chain.get_block(0).header.hash_hex();
        auto h1 = chain.get_block(1).header.hash_hex();
        auto h2 = chain.get_block(2).header.hash_hex();
        auto h3 = chain.get_block(3).header.hash_hex();
        
        check("Block linking: blocks have different hashes",
              h0 != h1 && h1 != h2 && h2 != h3);
        check("Block linking: block 1 prev = genesis hash",
              chain.get_block(1).header.prev_block_hash == chain.get_block(0).header.hash());
        check("Block linking: block 2 prev = block 1 hash",
              chain.get_block(2).header.prev_block_hash == chain.get_block(1).header.hash());
    }
    
    // --- Summary ---
    
    std::cout << "\n";
    std::cout << "QTC Self-Test: " << passed << " passed, " << failed << " failed\n";
    if (failed == 0) {
        std::cout << "QTC Self-Test: ALL PASS\n";
    }
    
    return failed;
}

} // namespace qtc

int main(int argc, char* argv[]) {
    if (argc < 2) {
        qtc::print_usage();
        return 0;
    }
    
    std::string command = argv[1];
    
    if (command == "help" || command == "--help" || command == "-h") {
        qtc::print_usage();
        return 0;
    }
    
    if (command == "init") {
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        auto info = chain.get_blockchain_info();
        
        std::cout << "QTC chain initialized.\n";
        std::cout << "Network: " << qtc::network_name(info.network) << "\n";
        std::cout << "Height: " << info.height << "\n";
        std::cout << "Genesis hash: " << info.best_block_hash << "\n";
        std::cout << "Difficulty bits: 0x" << std::hex << info.difficulty_bits << std::dec << "\n";
        std::cout << "UTXO count: " << chain.utxo_set().size() << "\n";
        
        chain.save("data/chain_state.txt");
        std::cout << "Chain state saved to data/chain_state.txt\n";
        return 0;
    }
    
    if (command == "getblockchaininfo") {
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        
        auto info = chain.get_blockchain_info();
        std::cout << "{\n";
        std::cout << "  \"network\": \"" << qtc::network_name(info.network) << "\",\n";
        std::cout << "  \"height\": " << info.height << ",\n";
        std::cout << "  \"best_block_hash\": \"" << info.best_block_hash << "\",\n";
        std::cout << "  \"difficulty_bits\": " << info.difficulty_bits << ",\n";
        std::cout << "  \"utxo_count\": " << chain.utxo_set().size() << ",\n";
        std::cout << "  \"initialized\": " << (info.initialized ? "true" : "false") << "\n";
        std::cout << "}\n";
        return 0;
    }
    
    if (command == "getblock") {
        if (argc < 3) {
            std::cerr << "Usage: qtc getblock <height>\n";
            return 1;
        }
        
        uint32_t height = static_cast<uint32_t>(std::stoul(argv[2]));
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        
        try {
            const auto& block = chain.get_block(height);
            qtc::print_block(block, height);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
        return 0;
    }
    
    if (command == "getblockhash") {
        if (argc < 3) {
            std::cerr << "Usage: qtc getblockhash <height>\n";
            return 1;
        }
        
        uint32_t height = static_cast<uint32_t>(std::stoul(argv[2]));
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        
        try {
            const auto& block = chain.get_block(height);
            std::cout << block.header.hash_hex() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
        return 0;
    }
    
    if (command == "getbalance") {
        if (argc < 3) {
            std::cerr << "Usage: qtc getbalance <address>\n";
            return 1;
        }
        
        std::string address = argv[2];
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        
        uint64_t balance = chain.utxo_set().get_balance_for_address(address);
        std::cout << qtc::format_qtc(balance) << "\n";
        return 0;
    }
    
    if (command == "listunspent") {
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        
        std::string address;
        if (argc >= 3) {
            address = argv[2];
        }
        
        auto utxos = address.empty() 
            ? std::vector<qtc::UTXO>{}  // TODO: list all
            : chain.utxo_set().list_unspent_for_address(address);
        
        if (address.empty()) {
            std::cout << "Total UTXOs: " << chain.utxo_set().size() << "\n";
            std::cout << "Total value: " << qtc::format_qtc(chain.utxo_set().total_value()) << "\n";
        } else {
            std::cout << "UTXOs for " << address << ":\n";
            for (const auto& u : utxos) {
                std::cout << "  " << u.outpoint.key() 
                          << "  " << qtc::format_qtc(u.amount)
                          << "  height=" << u.height
                          << (u.coinbase ? " (coinbase)" : "") << "\n";
            }
            std::cout << "Balance: " << qtc::format_qtc(chain.utxo_set().get_balance_for_address(address)) << "\n";
        }
        return 0;
    }
    
    if (command == "demo-day3") {
        return qtc::run_demo_day3();
    }
    
    if (command == "demo-day4") {
        return qtc::run_demo_day4();
    }
    
    if (command == "mine") {
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        
        uint32_t count = 1;
        std::string address = "Miner";
        
        if (argc >= 3) {
            count = static_cast<uint32_t>(std::stoul(argv[2]));
        }
        if (argc >= 4) {
            address = argv[3];
        }
        
        std::cout << "Mining " << count << " block" << (count > 1 ? "s" : "")
                  << " to " << address << "...\n\n";
        
        uint32_t mined = qtc::mine_n_blocks(chain, count, address);
        
        std::cout << "\nMined " << mined << " of " << count << " blocks.\n";
        std::cout << "Chain height: " << chain.height() << "\n";
        std::cout << address << " balance: " << qtc::format_qtc(
            chain.utxo_set().get_balance_for_address(address)) << "\n";
        std::cout << "UTXO count: " << chain.utxo_set().size() << "\n";
        return 0;
    }
    
    if (command == "selftest") {
        return qtc::run_selftest();
    }
    
    if (command == "validatechain") {
        qtc::Chain chain;
        chain.init(qtc::Network::REGTEST);
        
        if (chain.validate_chain()) {
            std::cout << "Chain validation: PASSED\n";
            return 0;
        } else {
            std::cout << "Chain validation: FAILED\n";
            return 1;
        }
    }
    
    std::cerr << "Unknown command: " << command << "\n";
    qtc::print_usage();
    return 1;
}
