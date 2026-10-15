#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include <sstream>
#include <cstring>
#include <fstream>
#include <map>
#include "chain.h"
#include "block.h"
#include "transaction.h"
#include "utxo.h"
#include "mining.h"
#include "crypto.h"
#include "consensus.h"
#include "pq_crypto.h"
#include "wallet/wallet.h"
#include "mempool.h"
#include "rpc.h"
#include "json.h"

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
        << "Day 5 post-quantum:\n"
        << "  pqtest                 ML-DSA-65 sign/verify report with negative cases\n"
        << "  demo-day5              End-to-end PQ transaction (mine 101, sign, spend, mine)\n"
        << "  pqvector               Regenerate tests/pq_test_vector.txt\n"
        << "  wallet-new <seed_hex>   Create an internal wallet from a seed\n"
        << "  wallet-info <file>      Show an internal wallet and its balance\n"
        << "  send <wallet> <to> <amount> [fee]   Build, sign and broadcast a spend\n"
        << "  serve [port]           Run the JSON-RPC server (default 18443)\n"
        << "  rpccall <method> [json] Call the running node over RPC\n"
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
// Day 5 — post-quantum signature tests
// ============================================================

static const char* const PQ_TEST_SEED = "QTC-DAY5-SEED-001";
static const char* const PQ_TEST_MESSAGE = "QTC-DAY5-TEST-001";

struct PqResults {
    int passed = 0;
    int failed = 0;
};

static std::vector<uint8_t> bytes_of(const char* text) {
    return std::vector<uint8_t>(text, text + std::strlen(text));
}

static PqResults run_pq_checks(bool verbose) {
    PqResults r;
    auto check = [&](const std::string& name, bool condition) {
        if (condition) {
            if (verbose) std::cout << "[PASS] " << name << "\n";
            r.passed++;
        } else {
            if (verbose) std::cout << "[FAIL] " << name << "\n";
            r.failed++;
        }
    };

    std::string link_error;
    check("Linked liboqs reports ML-DSA-65 sizes matching pq_crypto.h",
          pq::linked_sizes_match(&link_error));

    check("SHA3-256 known answer (abc)",
          crypto::to_hex(crypto::sha3_256(bytes_of("abc")))
          == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    check("SHAKE256 known answer (abc, 32)",
          crypto::to_hex(crypto::shake256(32, bytes_of("abc")))
          == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");

    auto seed = bytes_of(PQ_TEST_SEED);
    auto message = bytes_of(PQ_TEST_MESSAGE);

    auto keys = pq::generate_mldsa65_keypair(seed);
    check("Deterministic keypair generated", keys.error.empty());
    if (!keys.error.empty()) {
        std::cout << "  keygen error: " << keys.error << "\n";
        return r;
    }

    auto keys_again = pq::generate_mldsa65_keypair(seed);
    auto keys_other = pq::generate_mldsa65_keypair(bytes_of("QTC-DAY5-SEED-002"));
    check("Public key is 1952 bytes",
          keys.public_key.size() == pq::ML_DSA_65_PUBLIC_KEY_SIZE);
    check("Secret key is 4032 bytes",
          keys.secret_key.size() == pq::ML_DSA_65_SECRET_KEY_SIZE);
    check("Same seed reproduces the same public key",
          keys.public_key == keys_again.public_key);
    check("Same seed reproduces the same secret key",
          keys.secret_key == keys_again.secret_key);
    check("A different seed yields a different keypair",
          keys.public_key != keys_other.public_key);

    std::string sign_error;
    auto signature = pq::sign_mldsa65(keys.secret_key, message, &sign_error);
    check("Signature produced", !signature.empty());
    check("Signature is 3309 bytes",
          signature.size() == pq::ML_DSA_65_SIGNATURE_SIZE);
    if (signature.empty()) {
        std::cout << "  sign error: " << sign_error << "\n";
        return r;
    }

    check("Valid signature verifies",
          pq::verify_mldsa65(keys.public_key, message, signature).valid);

    auto tampered_message = message;
    tampered_message[0] ^= 0x01;
    check("Modified message is rejected",
          !pq::verify_mldsa65(keys.public_key, tampered_message, signature).valid);

    auto tampered_key = keys.public_key;
    tampered_key[0] ^= 0x01;
    check("Modified public key is rejected",
          !pq::verify_mldsa65(tampered_key, message, signature).valid);

    auto tampered_signature = signature;
    tampered_signature[0] ^= 0x01;
    check("Modified signature is rejected",
          !pq::verify_mldsa65(keys.public_key, message, tampered_signature).valid);

    auto truncated = signature;
    truncated.resize(64);
    check("Truncated signature is rejected",
          !pq::verify_mldsa65(keys.public_key, message, truncated).valid);

    check("Secret key of wrong length is rejected",
          pq::sign_mldsa65(std::vector<uint8_t>(64, 0), message).empty());

    // v1 address: bech32m, no version word, full 32-byte program.
    auto decoded = pq::decode_address(
        "qtc1x86zw4qg4ye728l37ghy4x00sxvh8jw68w8mwaqn8kd0p3wsw60sstgv4j");
    check("Wallet v1 address decodes", decoded.valid);
    check("v1 address carries the full 32-byte program",
          decoded.program.size() == pq::WITNESS_PROGRAM_SIZE);
    check("v1 address reports its network", decoded.network == Network::MAINNET);
    check("v1 address uses the bech32m checksum", decoded.bech32m);
    check("v1 address reports no version word", decoded.witness_version == 0);
    check("Address with a broken checksum is rejected",
          !pq::decode_address(
              "qtc1x86zw4qg4ye728l37ghy4x00sxvh8jw68w8mwaqn8kd0p3wsw60sstgv4k").valid);
    check("Address with a foreign HRP is rejected",
          !pq::decode_address(
              "btc1x86zw4qg4ye728l37ghy4x00sxvh8jw68w8mwaqn8kd0p3wsw60sstgv4j").valid);
    check("Truncated 20-byte program is rejected",
          !pq::decode_address("qtc1tnvv97wmm8lexjsf6wmplrmfy6sy620aeucw3a").valid);
    check("Version-worded (v2-style) address is rejected",
          !pq::decode_address("qtc1ztnvv97wmm8lexjsf6wmplrmfy6sy620aczenur").valid);
    // Consensus must actually enforce the witness, not merely carry it.
    {
        Chain chain;
        chain.init(Network::REGTEST);
        mine_n_blocks(chain, COINBASE_MATURITY + 1, "PQCheck");
        auto coins = chain.utxo_set().list_unspent_for_script(script::for_address("PQCheck"));
        if (!coins.empty()) {
            const qtc::UTXO& u = coins.front();
            Transaction spend;
            spend.inputs.push_back({u.outpoint, bytes_of("unlock"), 0xffffffff});
            spend.outputs.push_back({u.amount - 1000, script::for_address("PQDest")});
            spend.public_key = keys.public_key;
            std::string err;
            spend.sign_input(0, u.script_pubkey, u.amount, keys.secret_key, &err);

            check("Valid signed spend passes UTXO validation",
                  chain.utxo_set().validate_transaction(spend, err));

            auto forged = spend;
            forged.signature[0] ^= 0x01;
            check("Forged signature is rejected by UTXO validation",
                  !chain.utxo_set().validate_transaction(forged, err));

            auto stripped = spend;
            stripped.signature.clear();
            check("Signed tx with no signature is rejected",
                  !chain.utxo_set().validate_transaction(stripped, err));

            if (coins.size() > 1) {
                auto multi = spend;
                multi.inputs.push_back({coins[1].outpoint, bytes_of("second"), 0xffffffff});
                check("Multi-input signed tx is rejected by the v1 witness rule",
                      !chain.utxo_set().validate_transaction(multi, err));
            }

            auto wrong_prev = spend;
            wrong_prev.outputs[0].amount = u.amount - 999;
            check("Spend signed against a different amount is rejected",
                  !chain.utxo_set().validate_transaction(wrong_prev, err));
        }
    }

    return r;
}

static int run_demo_day5() {
    std::cout << "=== QTC Day 5: Post-Quantum Transaction Demo ===\n\n";

    std::string link_error;
    if (!pq::linked_sizes_match(&link_error)) {
        std::cout << "Linked liboqs does not match the protocol: " << link_error << "\n";
        return 1;
    }
    std::cout << "Linked liboqs reports ML-DSA-65 sizes matching the protocol.\n\n";

    Chain chain;
    chain.init(Network::REGTEST);

    const std::string miner = "PQMiner";
    const std::string recipient = "PQRecipient";

    std::cout << "Mining " << COINBASE_MATURITY + 1 << " blocks to " << miner << "...";
    std::cout.flush();
    mine_n_blocks(chain, COINBASE_MATURITY + 1, miner);
    std::cout << " done, chain height " << chain.height() << "\n\n";

    auto miner_script = script::for_address(miner);
    auto utxos = chain.utxo_set().list_unspent_for_script(miner_script);
    if (utxos.empty()) {
        std::cout << "No spendable UTXO for " << miner << "\n";
        return 1;
    }
    const UTXO& funded = utxos.front();
    std::cout << "Spendable UTXO: " << funded.amount << " satoshis\n\n";

    auto keys = pq::generate_mldsa65_keypair(bytes_of("QTC-DAY5-DEMO"));
    if (!keys.error.empty()) {
        std::cout << "Key generation failed: " << keys.error << "\n";
        return 1;
    }

    Transaction spend;
    spend.inputs.push_back({funded.outpoint, bytes_of("pq-unlock"), 0xffffffff});
    spend.outputs.push_back({funded.amount - 1000, script::for_address(recipient)});
    spend.outputs.push_back({1000, script::for_address(miner)});
    spend.public_key = keys.public_key;

    std::string sign_error;
    const bool signed_ok =
        spend.sign_input(0, funded.script_pubkey, funded.amount, keys.secret_key, &sign_error);
    if (!signed_ok) {
        std::cout << "Signing failed: " << sign_error << "\n";
        return 1;
    }

    auto verified = spend.verify_input(0, funded.script_pubkey, funded.amount);

    std::cout << "Transaction validation\n";
    std::cout << "---------------------\n";
    std::cout << "Inputs:              " << spend.inputs.size() << "\n";
    std::cout << "Outputs:             " << spend.outputs.size() << "\n";
    std::cout << "Serialized size:     " << spend.serialize().size() << " bytes\n";
    std::cout << "\n";
    std::cout << "Signature algorithm: ML-DSA-65 (FIPS-204)\n";
    std::cout << "Public key:          "
              << (spend.public_key.size() == pq::ML_DSA_65_PUBLIC_KEY_SIZE
                      ? "VALID" : "INVALID") << "\n";
    std::cout << "Signature:           "
              << (spend.signature.size() == pq::ML_DSA_65_SIGNATURE_SIZE
                      ? "VALID" : "INVALID") << "\n";
    std::cout << "Signature verifies:  " << (verified.valid ? "VALID" : "INVALID") << "\n";
    std::cout << "Ownership:           NOT YET VERIFIABLE (address scheme settled Day 6)\n";
    std::cout << "\nRESULT:              " << (verified.valid ? "ACCEPTED" : "REJECTED") << "\n";

    auto round_trip = Transaction::deserialize(spend.serialize());
    std::cout << "\nSerialization round-trip: "
              << (round_trip.serialize() == spend.serialize() ? "byte-identical" : "MISMATCH")
              << "\n";
    std::cout << "Witness survives: "
              << (round_trip.signature.size() == pq::ML_DSA_65_SIGNATURE_SIZE
                      ? "yes" : "NO") << "\n";

    std::string chain_error;
    const bool accepted = chain.utxo_set().validate_transaction(spend, chain_error);
    std::cout << "\nUTXO/balance check:   " << (accepted ? "PASS" : "FAIL")
              << (accepted ? "" : " (" + chain_error + ")") << "\n";

    std::cout << "\n--- Forged-witness rejection ---\n";
    auto forged = spend;
    forged.signature[0] ^= 0x01;
    std::string forged_error;
    std::cout << "Forged signature rejected: "
              << (!chain.utxo_set().validate_transaction(forged, forged_error) ? "yes" : "NO")
              << " (" << forged_error << ")\n";
    auto stripped = spend;
    stripped.signature.clear();
    std::string stripped_error;
    std::cout << "Missing signature rejected: "
              << (!chain.utxo_set().validate_transaction(stripped, stripped_error) ? "yes" : "NO")
              << " (" << stripped_error << ")\n";
    if (utxos.size() > 1) {
        auto multi = spend;
        multi.inputs.push_back({utxos[1].outpoint, bytes_of("second"), 0xffffffff});
        std::string multi_error;
        std::cout << "Multi-input signed tx rejected: "
                  << (!chain.utxo_set().validate_transaction(multi, multi_error) ? "yes" : "NO")
                  << " (" << multi_error << ")\n";
    }

    if (accepted) {
        Block block = create_block_template(chain, miner, {spend});
        auto mined = mine_block(block);
        if (mined.found && chain.add_block(block)) {
            std::cout << "Mined into block " << chain.height() << ": " << mined.hash_hex << "\n";
            std::cout << "Recipient balance:   "
                      << chain.utxo_set().get_balance_for_address(recipient) << " satoshis\n";
        } else {
            std::cout << "Block containing the spend was rejected\n";
        }
    }

    std::cout << "\nFinal chain validation: "
              << (chain.validate_chain() ? "PASSED" : "FAILED") << "\n";
    return verified.valid ? 0 : 1;
}

#ifndef QTC_PQ_VECTOR_PATH
#define QTC_PQ_VECTOR_PATH "tests/pq_test_vector.txt"
#endif

static bool write_pq_vector(const std::string& path);
static bool verify_pq_vector(const std::string& path, std::string* detail);

static int run_pqtest() {
    std::string link_error;
    const bool linked = pq::linked_sizes_match(&link_error);

    std::cout << "QTC PQ TEST\n";
    std::cout << "===========\n\n";
    std::cout << "Algorithm: ML-DSA-65 (FIPS-204)\n";
    std::cout << "Linked liboqs sizes: " << (linked ? "match protocol" : "MISMATCH") << "\n";
    if (!linked) std::cout << "  " << link_error << "\n";

    auto seed = bytes_of(PQ_TEST_SEED);
    auto keys = pq::generate_mldsa65_keypair(seed);
    if (!keys.error.empty()) {
        std::cout << "Key generation failed: " << keys.error << "\n";
        return 1;
    }

    auto message = bytes_of(PQ_TEST_MESSAGE);
    std::string sign_error;
    auto signature = pq::sign_mldsa65(keys.secret_key, message, &sign_error);
    if (signature.empty()) {
        std::cout << "Signing failed: " << sign_error << "\n";
        return 1;
    }

    std::cout << "\nPublic key: " << keys.public_key.size() << " bytes\n";
    std::cout << "Signature:  " << signature.size() << " bytes\n";
    std::cout << "\nMessage:\n" << PQ_TEST_MESSAGE << "\n\n";
    std::cout << "Verification: "
              << (pq::verify_mldsa65(keys.public_key, message, signature).valid
                      ? "PASS" : "FAIL") << "\n";

    auto tampered_message = message;
    tampered_message[0] ^= 0x01;
    auto tampered_key = keys.public_key;
    tampered_key[0] ^= 0x01;
    auto tampered_signature = signature;
    tampered_signature[0] ^= 0x01;

    std::cout << "\n--- Negative cases (each must FAIL) ---\n";
    auto negative = [&](const std::string& name, bool valid) {
        std::cout << name << ": " << (valid ? "PASS" : "FAIL") << "\n";
    };
    negative("Modified message  ",
             pq::verify_mldsa65(keys.public_key, tampered_message, signature).valid);
    negative("Modified public key",
             pq::verify_mldsa65(tampered_key, message, signature).valid);
    negative("Modified signature",
             pq::verify_mldsa65(keys.public_key, message, tampered_signature).valid);

    Transaction signed_tx;
    signed_tx.inputs.push_back(
        {OutPoint{std::vector<uint8_t>(32, 0x11), 0}, bytes_of("unlock"), 0xffffffff});
    signed_tx.outputs.push_back({9000, script::for_address("Alice")});
    signed_tx.public_key = keys.public_key;
    std::string tx_error;
    const bool signed_ok =
        signed_tx.sign_input(0, script::for_address("Miner"), 10000,
                             keys.secret_key, &tx_error);

    std::cout << "\n--- In a transaction ---\n";
    std::cout << "Signed: " << (signed_ok ? "yes" : tx_error.c_str()) << "\n";
    if (signed_ok) {
        auto round_trip = Transaction::deserialize(signed_tx.serialize());
        std::cout << "Witness survives serialization: "
                  << (round_trip.signature.size() == pq::ML_DSA_65_SIGNATURE_SIZE &&
                      round_trip.public_key.size() == pq::ML_DSA_65_PUBLIC_KEY_SIZE
                          ? "yes" : "NO") << "\n";
        std::cout << "Transaction verifies: "
                  << (signed_tx.verify_input(0, script::for_address("Miner"), 10000).valid
                          ? "PASS" : "FAIL") << "\n";
        std::cout << "Wrong prev amount rejected: "
                  << (!signed_tx.verify_input(0, script::for_address("Miner"), 9999).valid
                          ? "yes" : "NO") << "\n";
    }

    std::cout << "\n--- Suite ---\n";
    auto results = run_pq_checks(true);
    std::cout << "\nPQ checks: " << results.passed << " passed, "
              << results.failed << " failed\n";

    std::string vector_detail;
    const bool vector_ok = verify_pq_vector(QTC_PQ_VECTOR_PATH, &vector_detail);
    std::cout << "\n--- Committed test vector (" << QTC_PQ_VECTOR_PATH << ") ---\n"
              << (vector_ok ? "Verification: PASS" : "Verification: FAIL")
              << "\n";
    if (!vector_ok) std::cout << "  " << vector_detail << "\n";

    return (results.failed == 0 && vector_ok) ? 0 : 1;
}

static bool write_pq_vector(const std::string& path) {
    auto keys = pq::generate_mldsa65_keypair(bytes_of(PQ_TEST_SEED));
    if (!keys.error.empty()) {
        std::cerr << "keygen failed: " << keys.error << "\n";
        return false;
    }
    auto message = bytes_of(PQ_TEST_MESSAGE);
    std::string sign_error;
    auto signature = pq::sign_mldsa65(keys.secret_key, message, &sign_error);
    if (signature.empty()) {
        std::cerr << "sign failed: " << sign_error << "\n";
        return false;
    }

    std::ofstream out(path);
    if (!out) {
        std::cerr << "cannot write " << path << "\n";
        return false;
    }
    out << "# QTC Day 5 post-quantum test vector\n"
        << "# ML-DSA-65 signing is hedged, so the signature below is a one-time\n"
        << "# known-answer value. It must verify on every build.\n"
        << "algorithm=ML-DSA-65\n"
        << "seed_hex=" << crypto::to_hex(bytes_of(PQ_TEST_SEED)) << "\n"
        << "message_hex=" << crypto::to_hex(message) << "\n"
        << "public_key_hex=" << crypto::to_hex(keys.public_key) << "\n"
        << "secret_key_hex=" << crypto::to_hex(keys.secret_key) << "\n"
        << "signature_hex=" << crypto::to_hex(signature) << "\n";
    out.close();

    std::cout << "Wrote " << path << "\n"
              << "  public key: " << keys.public_key.size() << " bytes\n"
              << "  secret key: " << keys.secret_key.size() << " bytes\n"
              << "  signature:  " << signature.size() << " bytes\n";
    return true;
}

static bool verify_pq_vector(const std::string& path, std::string* detail) {
    std::ifstream in(path);
    if (!in) {
        *detail = "cannot read " + path;
        return false;
    }

    std::map<std::string, std::string> fields;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        fields[line.substr(0, eq)] = line.substr(eq + 1);
    }

    auto require = [&](const char* key, std::vector<uint8_t>& out) {
        auto it = fields.find(key);
        if (it == fields.end() || it->second.empty()) {
            *detail = std::string("vector missing ") + key;
            return false;
        }
        out = crypto::from_hex(it->second);
        return true;
    };

    std::vector<uint8_t> seed, message, public_key, secret_key, signature;
    if (!require("seed_hex", seed) || !require("message_hex", message) ||
        !require("public_key_hex", public_key) || !require("secret_key_hex", secret_key) ||
        !require("signature_hex", signature)) {
        return false;
    }

    if (public_key.size() != pq::ML_DSA_65_PUBLIC_KEY_SIZE) {
        *detail = "vector public key has wrong length";
        return false;
    }
    if (signature.size() != pq::ML_DSA_65_SIGNATURE_SIZE) {
        *detail = "vector signature has wrong length";
        return false;
    }

    auto verified = pq::verify_mldsa65(public_key, message, signature);
    if (!verified.valid) {
        *detail = "vector signature failed to verify: " + verified.error;
        return false;
    }

    auto rederived = pq::generate_mldsa65_keypair(seed);
    if (rederived.error.empty() && rederived.public_key != public_key) {
        *detail = "seed no longer derives the vector public key";
        return false;
    }
    return true;
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
    
    // --- JSON ---
    {
        auto round_trip = [](const std::string& text) {
            qtc::json::Value value;
            std::string error;
            if (!qtc::json::Value::parse(text, value, error)) return std::string("ERR:" + error);
            return value.dump();
        };
        check("JSON string round-trips", round_trip("\"hello\"") == "\"hello\"");
        check("JSON integer keeps its type", round_trip("5000000000") == "5000000000");
        check("JSON negative integer", round_trip("-42") == "-42");
        check("JSON float", round_trip("1.5") == "1.5");
        check("JSON true", round_trip("true") == "true");
        check("JSON null", round_trip("null") == "null");
        check("JSON empty object", round_trip("{}") == "{}");
        check("JSON empty array", round_trip("[]") == "[]");
        check("JSON nested object",
              round_trip("{\"a\":{\"b\":[1,2,3]}}") == "{\"a\":{\"b\":[1,2,3]}}");
        check("JSON escapes a quote", round_trip("\"a\\\"b\"") == "\"a\\\"b\"");
        check("JSON escapes a newline", round_trip("\"a\\nb\"") == "\"a\\nb\"");

        qtc::json::Value value;
        std::string error;
        check("JSON rejects trailing junk",
              !qtc::json::Value::parse("{} junk", value, error));
        check("JSON rejects a truncated object",
              !qtc::json::Value::parse("{\"a\":", value, error));
        check("JSON rejects an unterminated string",
              !qtc::json::Value::parse("\"abc", value, error));
        check("JSON rejects deep nesting",
              !qtc::json::Value::parse(std::string(200, '['), value, error));
    }

    // --- JSON-RPC dispatch (no sockets) ---
    {
        qtc::rpc::Context context;
        context.datadir = "selftest-rpc";
        std::string cleanup = "rm -rf 'selftest-rpc'";
        if (std::system(cleanup.c_str()) != 0) {}
        context.chain.init(Network::REGTEST);

        auto call_method = [&](const std::string& body) {
            qtc::json::Value parsed;
            std::string error;
            qtc::json::Value::parse(body, parsed, error);
            return parsed;
        };

        check("RPC returns a result envelope",
              call_method(qtc::rpc::handle(context,
                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\"}"))
                  ["result"].is_number());
        check("RPC echoes the id",
              call_method(qtc::rpc::handle(context,
                  "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"getblockcount\"}"))
                  ["id"].as_uint() == 7);
        check("RPC rejects malformed JSON",
              call_method(qtc::rpc::handle(context, "{not json"))
                  ["error"]["code"].as_number() ==
                  static_cast<double>(qtc::rpc::kParseError));
        check("RPC rejects an unknown method",
              call_method(qtc::rpc::handle(context,
                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"nosuchmethod\"}"))
                  ["error"]["code"].as_number() ==
                  static_cast<double>(qtc::rpc::kMethodNotFound));
        check("RPC rejects a request with no method",
              call_method(qtc::rpc::handle(context, "{\"jsonrpc\":\"2.0\",\"id\":1}"))
                  ["error"]["code"].as_number() ==
                  static_cast<double>(qtc::rpc::kInvalidRequest));
        check("RPC rejects a batch",
              call_method(qtc::rpc::handle(context, "[]"))
                  ["error"]["code"].as_number() ==
                  static_cast<double>(qtc::rpc::kInvalidRequest));
        check("RPC rejects bad params",
              call_method(qtc::rpc::handle(context,
                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getbalance\",\"params\":[5]}"))
                  ["error"]["code"].as_number() ==
                  static_cast<double>(qtc::rpc::kInvalidParams));
        check("RPC rejects a malformed transaction hex",
              call_method(qtc::rpc::handle(context,
                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"zz\"]}"))
                  ["error"]["code"].as_number() ==
                  static_cast<double>(qtc::rpc::kInvalidParams));
        check("RPC reports blockchain info",
              call_method(qtc::rpc::handle(context,
                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockchaininfo\"}"))
                  ["result"].is_object());
        check("RPC returns a mempool array",
              call_method(qtc::rpc::handle(context,
                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getrawmempool\"}"))
                  ["result"].is_array());

        if (std::system(cleanup.c_str()) != 0) {}
    }

    // --- Mempool ---
    {
        Chain chain;
        chain.init(Network::REGTEST);
        auto w = qtc::wallet::Wallet::from_seed(bytes_of("QTC-MEMPOOL-001"));
        mine_n_blocks(chain, COINBASE_MATURITY + 1, w.address());
        auto coins = chain.utxo_set().list_unspent_for_script(w.script_pubkey());
        const auto& u = coins.front();

        auto build_spend = [&](uint64_t fee) {
            Transaction spend;
            spend.inputs.push_back({u.outpoint, bytes_of("pq-unlock"), 0xffffffff});
            spend.outputs.push_back({u.amount - fee, script::for_address("Miner")});
            std::string err;
            w.sign(spend, 0, u.script_pubkey, u.amount);
            return spend;
        };

        Mempool pool;
        std::string err;

        auto good = build_spend(10000);
        check("Mempool admits a valid signed spend", pool.admit(chain.utxo_set(), good, err));
        check("Mempool reports its size", pool.size() == 1);
        check("Mempool computes the fee", pool.total_fees() == 10000);
        check("Mempool recognises a known txid", pool.contains(good.txid()));

        check("Mempool rejects a duplicate", !pool.admit(chain.utxo_set(), good, err));

        auto low_fee = build_spend(MIN_TX_FEE - 1);
        check("Mempool rejects a below-minimum fee", !pool.admit(chain.utxo_set(), low_fee, err));

        auto coinbase = Transaction::create_genesis_coinbase("x", 1);
        check("Mempool rejects a coinbase", !pool.admit(chain.utxo_set(), coinbase, err));

        // A conflicting spend of the same output, from a second wallet.
        auto w2 = qtc::wallet::Wallet::from_seed(bytes_of("QTC-MEMPOOL-002"));
        Transaction conflict;
        conflict.inputs.push_back({u.outpoint, bytes_of("other"), 0xffffffff});
        conflict.outputs.push_back({u.amount - 20000, script::for_address("Miner")});
        w2.sign(conflict, 0, u.script_pubkey, u.amount);
        check("Mempool rejects a double spend against a pending transaction",
              !pool.admit(chain.utxo_set(), conflict, err));

        auto unknown = build_spend(5000);
        unknown.inputs[0].prevout.txid.assign(32, 0xEE);
        std::string sign_err;
        w.sign(unknown, 0, u.script_pubkey, u.amount);
        check("Mempool rejects an unknown input",
              !pool.admit(chain.utxo_set(), unknown, err));

        // Ordering: a higher fee rate must come first.
        auto second = qtc::wallet::Wallet::from_seed(bytes_of("QTC-MEMPOOL-003"));
        mine_n_blocks(chain, COINBASE_MATURITY + 1, second.address());
        auto coins2 = chain.utxo_set().list_unspent_for_script(second.script_pubkey());
        check("Second wallet has two spendable outputs for the ordering test",
              coins2.size() >= 2);
        if (coins2.size() >= 2) {
            // Distinct UTXOs, so these are not a double spend of each other.
            Transaction cheap, rich;
            cheap.inputs.push_back({coins2[0].outpoint, bytes_of("a"), 0xffffffff});
            cheap.outputs.push_back({coins2[0].amount - 1000, script::for_address("Miner")});
            second.sign(cheap, 0, coins2[0].script_pubkey, coins2[0].amount);
            rich.inputs.push_back({coins2[1].outpoint, bytes_of("b"), 0xffffffff});
            rich.outputs.push_back({coins2[1].amount - 900000, script::for_address("Miner")});
            second.sign(rich, 0, coins2[1].script_pubkey, coins2[1].amount);

            check("Low fee rate admitted", pool.admit(chain.utxo_set(), cheap, err));
            check("High fee rate admitted", pool.admit(chain.utxo_set(), rich, err));
            auto ordered = pool.by_fee_rate();
            check("Mempool orders by descending fee rate",
                  ordered.size() >= 2 && ordered[0].txid() == rich.txid());
        }

        // Confirming in a block clears the mempool.
        Block block = create_block_template(chain, "Miner", pool.by_fee_rate());
        auto mined = mine_block(block);
        check("Mempool transactions can be mined",
              mined.found && chain.add_block(block));
        const size_t before = pool.size();
        pool.remove_confirmed(block.transactions, chain.utxo_set());
        check("Confirmed transactions leave the mempool", pool.size() < before);
        check("Mempool is empty after confirmation", pool.empty());
    }

    // --- Internal wallet ---
    {
        using qtc::wallet::Wallet;
        auto seed = bytes_of("QTC-CORE-WALLET-001");
        auto w = Wallet::from_seed(seed);
        check("Internal wallet builds from a seed", w.valid());
        check("Internal wallet produces a v1 address",
              w.address().rfind("qtc1", 0) == 0 && w.address().size() == 62);
        check("Internal wallet program is the full 32 bytes",
              w.program().size() == pq::WITNESS_PROGRAM_SIZE);
        check("Internal wallet address decodes back to its program",
              pq::decode_address(w.address()).program == w.program());
        check("Internal wallet ML-DSA-65 key is 4032 bytes",
              w.ml_dsa_secret_key().size() == pq::ML_DSA_65_SECRET_KEY_SIZE);

        auto again = Wallet::from_seed(seed);
        check("Internal wallet is deterministic",
              again.address() == w.address() &&
              again.ml_dsa_public_key() == w.ml_dsa_public_key());

        auto other = Wallet::from_seed(bytes_of("QTC-CORE-WALLET-002"));
        check("A different seed yields a different address",
              other.address() != w.address());

        check("Empty seed is rejected",
              !Wallet::from_seed({}).valid());

        // File round-trip, plus refusal of a tampered file.
        qtc::wallet::WalletFile file;
        file.master_seed = w.master_seed();
        file.address = w.address();
        file.ml_dsa_public_key = w.ml_dsa_public_key();
        file.ml_dsa_secret_key = w.ml_dsa_secret_key();
        file.ml_kem_public_key = w.ml_kem_public_key();
        file.ml_kem_secret_key = w.ml_kem_secret_key();

        std::string text = file.serialize();
        check("Wallet file omits the KEM shared secret",
              text.find("shared") == std::string::npos);

        qtc::wallet::WalletFile parsed;
        std::string parse_error;
        check("Wallet file round-trips",
              qtc::wallet::WalletFile::deserialize(text, parsed, &parse_error));
        Wallet rebuilt;
        check("Wallet rebuilds from its file",
              qtc::wallet::wallet_from_file(parsed, rebuilt) &&
              rebuilt.address() == w.address());

        auto tampered = parsed;
        tampered.address = w.address().substr(0, w.address().size() - 1) + "x";
        Wallet rejected;
        check("Wallet file with a tampered address is refused",
              !qtc::wallet::wallet_from_file(tampered, rejected));

        auto truncated = text.substr(0, text.size() / 2);
        qtc::wallet::WalletFile partial;
        check("Truncated wallet file is refused",
              !qtc::wallet::WalletFile::deserialize(truncated, partial, &parse_error));

        // The internal wallet must produce a spend the node accepts.
        Chain chain;
        chain.init(Network::REGTEST);
        mine_n_blocks(chain, COINBASE_MATURITY + 1, w.address());
        auto coins = chain.utxo_set().list_unspent_for_script(w.script_pubkey());
        check("Internal wallet address receives mining rewards", !coins.empty());

        if (!coins.empty()) {
            const qtc::UTXO& u = coins.front();
            Transaction spend;
            spend.inputs.push_back(
                {u.outpoint, bytes_of("pq-unlock"), 0xffffffff});
            spend.outputs.push_back({u.amount - 1000, script::for_address("Miner")});
            std::string sign_error;
            check("Internal wallet signs its own spend",
                  w.sign(spend, 0, u.script_pubkey, u.amount));
            std::string accept_error;
            check("Node accepts the internally signed spend",
                  chain.utxo_set().validate_transaction(spend, accept_error));
        }
    }

    // --- End-to-end: mine 101 -> send -> mempool -> mine 1 -> confirm ---
    {
        Chain chain;
        chain.init(Network::REGTEST);
        auto alice = qtc::wallet::Wallet::from_seed(bytes_of("QTC-E2E-ALICE"));
        auto bob = qtc::wallet::Wallet::from_seed(bytes_of("QTC-E2E-BOB"));

        mine_n_blocks(chain, COINBASE_MATURITY + 1, alice.address());
        const uint64_t alice_start =
            chain.utxo_set().get_balance_for_script(alice.script_pubkey());
        check("E2E: alice is funded after 101 blocks", alice_start > 0);
        check("E2E: bob starts with nothing",
              chain.utxo_set().get_balance_for_script(bob.script_pubkey()) == 0);

        auto coins = chain.utxo_set().list_unspent_for_script(alice.script_pubkey());
        check("E2E: alice has a spendable output", !coins.empty());

        if (!coins.empty()) {
            const qtc::UTXO& u = coins.front();
            const uint64_t amount = 1000000000;  // 10 QTC
            const uint64_t fee = 5000;
            const uint64_t change = u.amount - amount - fee;

            Transaction spend;
            spend.inputs.push_back(
                {u.outpoint, bytes_of("e2e-unlock"), 0xffffffff});
            spend.outputs.push_back({amount, bob.script_pubkey()});
            spend.outputs.push_back({change, alice.script_pubkey()});
            check("E2E: wallet signs the spend",
                  alice.sign(spend, 0, u.script_pubkey, u.amount));

            Mempool pool;
            std::string error;
            check("E2E: node accepts the spend into the mempool",
                  pool.admit(chain.utxo_set(), spend, error));

            // Mined to a neutral address: paying alice would add a coinbase to
            // her balance and hide whether the change was returned correctly.
            Block block = create_block_template(chain, "E2E Miner",
                                                pool.by_fee_rate());
            auto mined = mine_block(block);
            check("E2E: the pending transaction is mined",
                  mined.found && chain.add_block(block));

            pool.remove_confirmed(block.transactions, chain.utxo_set());
            check("E2E: mempool is empty after confirmation", pool.empty());

            const uint64_t bob_balance =
                chain.utxo_set().get_balance_for_script(bob.script_pubkey());
            const uint64_t alice_balance =
                chain.utxo_set().get_balance_for_script(alice.script_pubkey());

            check("E2E: bob received the amount", bob_balance >= amount);
            check("E2E: alice kept the change plus her remaining outputs",
                  alice_balance == alice_start - amount - fee);
            // Conservation across every party, including the miner that
            // received the block subsidy.
            const uint64_t miner_balance =
                chain.utxo_set().get_balance_for_address("E2E Miner");
            const uint64_t coinbase_amount =
                block.transactions[0].outputs[0].amount;
            check("E2E: value is conserved",
                  alice_balance + bob_balance + miner_balance + fee ==
                      alice_start + coinbase_amount);
            check("E2E: chain validates end to end", chain.validate_chain());
        }
    }

    // --- Negative tests ---
    {
        Chain chain;
        chain.init(Network::REGTEST);
        auto w = qtc::wallet::Wallet::from_seed(bytes_of("QTC-NEG-001"));
        mine_n_blocks(chain, COINBASE_MATURITY + 1, w.address());
        auto coins = chain.utxo_set().list_unspent_for_script(w.script_pubkey());
        std::string error;

        if (!coins.empty()) {
            const qtc::UTXO& u = coins.front();

            // Bad signature.
            Transaction bad_sig;
            bad_sig.inputs.push_back({u.outpoint, bytes_of("x"), 0xffffffff});
            bad_sig.outputs.push_back({u.amount - 5000, w.script_pubkey()});
            w.sign(bad_sig, 0, u.script_pubkey, u.amount);
            bad_sig.signature[10] ^= 0x01;
            check("Negative: a bad signature is rejected",
                  !chain.utxo_set().validate_transaction(bad_sig, error));

            // Fake amount: the signature_hash commits to every output, so
            // changing an amount after signing must invalidate it.
            Transaction fake_amount;
            fake_amount.inputs.push_back({u.outpoint, bytes_of("x"), 0xffffffff});
            fake_amount.outputs.push_back({u.amount - 6000, w.script_pubkey()});
            w.sign(fake_amount, 0, u.script_pubkey, u.amount);
            fake_amount.outputs[0].amount = u.amount - 7000;
            error.clear();
            check("Negative: an output amount changed after signing is rejected",
                  !chain.utxo_set().validate_transaction(fake_amount, error));

            // Fake amount: signature made against a different prev amount.
            Transaction wrong_prev_amount;
            wrong_prev_amount.inputs.push_back(
                {u.outpoint, bytes_of("x"), 0xffffffff});
            wrong_prev_amount.outputs.push_back(
                {u.amount - 8000, w.script_pubkey()});
            w.sign(wrong_prev_amount, 0, u.script_pubkey, u.amount);
            error.clear();
            check("Negative: verifying against a different prev amount fails",
                  !wrong_prev_amount.verify_input(0, u.script_pubkey,
                                                  u.amount + 1).valid);

            // Unsigned.
            Transaction unsigned_tx;
            unsigned_tx.inputs.push_back({u.outpoint, bytes_of("x"), 0xffffffff});
            unsigned_tx.outputs.push_back({u.amount - 5000, w.script_pubkey()});
            unsigned_tx.sig_algorithm_id = pq::SIG_ML_DSA_65;
            error.clear();
            check("Negative: an unsigned spend is rejected",
                  !chain.utxo_set().validate_transaction(unsigned_tx, error));

            // Outputs exceeding inputs.
            Transaction overspend;
            overspend.inputs.push_back({u.outpoint, bytes_of("x"), 0xffffffff});
            overspend.outputs.push_back({u.amount + 1, w.script_pubkey()});
            w.sign(overspend, 0, u.script_pubkey, u.amount);
            error.clear();
            check("Negative: spending more than the input is rejected",
                  !chain.utxo_set().validate_transaction(overspend, error));

            // Double spend via the mempool.
            Transaction first, second_tx;
            first.inputs.push_back({u.outpoint, bytes_of("x"), 0xffffffff});
            first.outputs.push_back({u.amount - 5000, w.script_pubkey()});
            w.sign(first, 0, u.script_pubkey, u.amount);
            second_tx.inputs.push_back({u.outpoint, bytes_of("y"), 0xffffffff});
            second_tx.outputs.push_back({u.amount - 7000, w.script_pubkey()});
            w.sign(second_tx, 0, u.script_pubkey, u.amount);

            Mempool pool;
            check("Negative: the first spend is admitted",
                  pool.admit(chain.utxo_set(), first, error));
            error.clear();
            check("Negative: a double spend is rejected",
                  !pool.admit(chain.utxo_set(), second_tx, error));
        }

        // Bad PoW and malformed blocks.
        Block mined_block = create_block_template(chain, "Miner", {});
        check("Negative: a mined block is valid", mine_block(mined_block).found);
        // Mutating a transaction after mining breaks the merkle root, so the
        // block no longer commits to its own contents.
        Block mutated = mined_block;
        mutated.transactions[0].outputs[0].amount -= 1;
        check("Negative: a block whose contents changed after mining is rejected",
              !chain.add_block(mutated));
        Block no_coinbase = mined_block;
        no_coinbase.transactions.erase(no_coinbase.transactions.begin());
        check("Negative: a block without a coinbase is rejected",
              !chain.add_block(no_coinbase));
        Block bad_link = mined_block;
        bad_link.header.prev_block_hash.assign(32, 0xAA);
        check("Negative: a block with a wrong previous hash is rejected",
              !chain.add_block(bad_link));
    }

    // --- Multi-transaction block serialization ---
    {
        // Regression: a coinbase followed by a signed transaction must not read
        // the next transaction's version byte as a witness algorithm id.
        Chain chain;
        chain.init(Network::REGTEST);
        auto w = qtc::wallet::Wallet::from_seed(bytes_of("QTC-MULTITX-001"));
        mine_n_blocks(chain, COINBASE_MATURITY + 1, w.address());
        auto coins = chain.utxo_set().list_unspent_for_script(w.script_pubkey());

        if (!coins.empty()) {
            const qtc::UTXO& u = coins.front();
            Transaction spend;
            spend.inputs.push_back({u.outpoint, bytes_of("unlock"), 0xffffffff});
            spend.outputs.push_back({u.amount - 2000, script::for_address("Miner")});
            w.sign(spend, 0, u.script_pubkey, u.amount);

            Block block = create_block_template(chain, "Miner", {spend});
            check("Multi-transaction block built",
                  block.transactions.size() == 2);

            auto round_trip = Block::deserialize(block.serialize());
            check("Multi-transaction block round-trips byte-identically",
                  round_trip.serialize() == block.serialize());
            check("Coinbase survives as a coinbase",
                  round_trip.transactions[0].is_coinbase());
            check("Signed transaction keeps its witness",
                  round_trip.transactions[1].signature.size() ==
                      pq::ML_DSA_65_SIGNATURE_SIZE);
            check("Second transaction verifies after reload",
                  round_trip.transactions[1].verify_input(
                      0, u.script_pubkey, u.amount).valid);

            auto mined = mine_block(block);
            check("Multi-transaction block mines and is accepted",
                  mined.found && chain.add_block(block));
            check("Chain validates with a multi-transaction block",
                  chain.validate_chain());

            // And it must survive a save/load cycle.
            const std::string dir = "selftest-multitx";
            std::string cleanup = "rm -rf '" + dir + "'";
            if (std::system(cleanup.c_str()) != 0) {}
            check("Multi-transaction block saves", chain.save(dir));
            Chain reloaded;
            check("Multi-transaction block reloads", reloaded.load(dir));
            check("Reloaded height matches", reloaded.height() == chain.height());
            check("Reloaded chain validates", reloaded.validate_chain());
            check("Reloaded spend is intact",
                  reloaded.blocks().back().transactions.size() == 2 &&
                  reloaded.blocks().back().transactions[1].signature.size() ==
                      pq::ML_DSA_65_SIGNATURE_SIZE);
            if (std::system(cleanup.c_str()) != 0) {}
        }
    }

    // --- Chain persistence ---
    {
        const std::string dir = "selftest-chain";
        std::string rm = "rm -rf '" + dir + "'";
        if (std::system(rm.c_str()) != 0) { /* nothing to clean */ }

        Chain writer;
        writer.init(Network::REGTEST);
        mine_n_blocks(writer, 5, "PersistCheck");
        const uint64_t expected = writer.utxo_set().get_balance_for_address("PersistCheck");
        const std::string tip = writer.tip().header.hash_hex();
        check("Chain state saves to disk", writer.save(dir));

        Chain reader;
        check("Chain state loads from disk", reader.load(dir));
        check("Restored height matches", reader.height() == writer.height());
        check("Restored tip hash matches", reader.tip().header.hash_hex() == tip);
        check("Restored balances match",
              reader.utxo_set().get_balance_for_address("PersistCheck") == expected);
        check("Restored chain validates", reader.validate_chain());

        // A truncated block file must be refused, not silently accepted.
        if (std::system(("rm -f '" + dir + "/blocks/00000002.dat'").c_str()) != 0) {}
        Chain damaged;
        check("Missing block file is refused", !damaged.load(dir));

        if (std::system(rm.c_str()) != 0) {}
    }

    // --- Day 5 post-quantum tests ---
    std::cout << "\n=== Day 5 Post-Quantum Tests ===\n\n";
    auto pq_results = run_pq_checks(false);
    passed += pq_results.passed;
    failed += pq_results.failed;
    std::cout << "PQ checks: " << pq_results.passed << " passed, "
              << pq_results.failed << " failed\n";

    std::string vector_detail;
    check("Committed post-quantum test vector verifies",
          verify_pq_vector(QTC_PQ_VECTOR_PATH, &vector_detail));
    if (!vector_detail.empty()) std::cout << "  " << vector_detail << "\n";

    // --- Summary ---

    std::cout << "\n";
    std::cout << "QTC Self-Test: " << passed << " passed, " << failed << " failed\n";
    if (failed == 0) {
        std::cout << "QTC Self-Test: ALL PASS\n";
    }
    
    return failed;
}

} // namespace qtc

static const char* DATA_DIR = "data";

// Opens the chain: restores persisted state when present, otherwise starts a
// fresh regtest chain. Mutating callers must follow up with persist_chain().
static void open_chain(qtc::Chain& chain, bool create_if_missing = true) {
    if (qtc::Chain::has_saved_state(DATA_DIR)) {
        if (!chain.load(DATA_DIR)) {
            std::cerr << "Failed to load chain state from '" << DATA_DIR
                      << "'. Refusing to continue with a partial chain.\n";
            std::exit(1);
        }
        return;
    }
    if (!create_if_missing) {
        std::cerr << "No chain found. Run 'qtc init' first.\n";
        std::exit(1);
    }
    chain.init(qtc::Network::REGTEST);
}

static void persist_chain(const qtc::Chain& chain) {
    if (!chain.save(DATA_DIR)) {
        std::cerr << "Warning: could not persist chain state to '" << DATA_DIR << "'\n";
    }
}

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

        // Persist after printing, so a failure is visible rather than silent.
        persist_chain(chain);
        return 0;
    }
    
    if (command == "getblockchaininfo") {
        qtc::Chain chain;
        open_chain(chain, false);
        
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
        open_chain(chain, false);
        
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
        open_chain(chain, false);
        
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
        open_chain(chain, false);
        
        uint64_t balance = chain.utxo_set().get_balance_for_address(address);
        std::cout << qtc::format_qtc(balance) << "\n";
        return 0;
    }
    
    if (command == "listunspent") {
        qtc::Chain chain;
        open_chain(chain, false);
        
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

    if (command == "demo-day5") {
        return qtc::run_demo_day5();
    }

    if (command == "pqtest") {
        return qtc::run_pqtest();
    }

    if (command == "wallet-new" || command == "wallet-info") {
        const bool from_seed = (command == "wallet-new");
        if (from_seed && argc < 3) {
            std::cerr << "Usage: qtc wallet-new <seed_hex> [wallet-file]\n"
                      << "       qtc wallet-info <wallet-file>\n";
            return 1;
        }

        std::string path = (argc >= (from_seed ? 4 : 3)) ? argv[from_seed ? 3 : 2]
                                                         : "wallet.dat";
        qtc::wallet::WalletFile file;
        std::string error;

        if (from_seed) {
            auto w = qtc::wallet::Wallet::from_seed(qtc::crypto::from_hex(argv[2]));
            if (!w.valid()) {
                std::cerr << "Wallet generation failed: " << w.error() << "\n";
                return 1;
            }
            file.master_seed = w.master_seed();
            file.address = w.address();
            file.ml_dsa_public_key = w.ml_dsa_public_key();
            file.ml_dsa_secret_key = w.ml_dsa_secret_key();
            file.ml_kem_public_key = w.ml_kem_public_key();
            file.ml_kem_secret_key = w.ml_kem_secret_key();
            if (!file.save(path, &error)) {
                std::cerr << error << "\n";
                return 1;
            }
            std::cout << "Wallet written to " << path << "\n";
        } else if (!qtc::wallet::WalletFile::load(path, file, &error)) {
            std::cerr << error << "\n";
            return 1;
        }

        qtc::wallet::Wallet w;
        if (!qtc::wallet::wallet_from_file(file, w)) {
            std::cerr << "Wallet file failed verification; refusing to use it\n";
            return 1;
        }

        qtc::Chain chain;
        bool have_chain = false;
        try {
            open_chain(chain, false);
            have_chain = true;
        } catch (...) {
            have_chain = false;
        }

        std::cout << "\nQTC Core wallet\n";
        std::cout << "--------------\n";
        std::cout << "Address:       " << w.address() << "\n";
        std::cout << "Program:       " << qtc::crypto::to_hex(w.program()) << "\n";
        std::cout << "ML-DSA-65 pk:  " << w.ml_dsa_public_key().size() << " bytes\n";
        std::cout << "ML-KEM-1024 pk:" << w.ml_kem_public_key().size() << " bytes\n";
        if (have_chain) {
            std::cout << "Balance:       "
                      << qtc::format_qtc(chain.utxo_set().get_balance_for_script(
                             w.script_pubkey())) << "\n";
        } else {
            std::cout << "Balance:       unknown (no chain state; run 'qtc init')\n";
        }
        return 0;
    }

    // Builds, signs and submits a spend from the internal wallet. This is the
    // end-to-end send path: wallet -> signature -> mempool -> block.
    if (command == "send") {
        if (argc < 5) {
            std::cerr << "Usage: qtc send <wallet-file> <to-address> <amount> [fee]\n";
            return 1;
        }
        const std::string wallet_path = argv[2];
        const std::string to = argv[3];
        const uint64_t amount = std::stoull(argv[4]);
        const uint64_t fee = (argc >= 6) ? std::stoull(argv[5]) : qtc::MIN_TX_FEE;

        qtc::wallet::WalletFile file;
        std::string error;
        if (!qtc::wallet::WalletFile::load(wallet_path, file, &error)) {
            std::cerr << error << "\n";
            return 1;
        }
        qtc::wallet::Wallet w;
        if (!qtc::wallet::wallet_from_file(file, w)) {
            std::cerr << "Wallet file failed verification; refusing to use it\n";
            return 1;
        }

        qtc::Chain chain;
        open_chain(chain, false);
        auto destination = qtc::script::for_qtc_address(to);
        if (destination.empty()) {
            std::cerr << "Invalid destination address: " << to << "\n";
            return 1;
        }

        auto coins = chain.utxo_set().list_unspent_for_script(w.script_pubkey());
        if (coins.empty()) {
            std::cerr << "No spendable output for " << w.address() << "\n";
            return 1;
        }
        // Single-input spends only: the v1 witness commits to one input.
        const qtc::UTXO& u = coins.front();
        if (amount + fee > u.amount) {
            std::cerr << "Amount plus fee exceeds the single available output of "
                      << u.amount << " satoshis. Consolidating multiple inputs needs "
                      << "per-input witnesses.\n";
            return 1;
        }

        // Without an explicit change output the whole remainder above `amount`
        // would be paid to the miner as fee.
        const uint64_t change = u.amount - amount - fee;

        qtc::Transaction spend;
        spend.inputs.push_back(
            {u.outpoint, std::vector<uint8_t>{'p','q','-','u','n','l','o','c','k'}, 0xffffffff});
        spend.outputs.push_back({amount, destination});
        if (change > 0) {
            spend.outputs.push_back({change, w.script_pubkey()});
        }
        if (!w.sign(spend, 0, u.script_pubkey, u.amount)) {
            std::cerr << "Signing failed\n";
            return 1;
        }

        std::string accept_error;
        if (!chain.utxo_set().validate_transaction(spend, accept_error)) {
            std::cerr << "Node rejected the spend: " << accept_error << "\n";
            return 1;
        }

        std::cout << "Sending " << qtc::format_qtc(amount) << " to " << to << "\n";
        std::cout << "  fee         " << qtc::format_qtc(fee) << "\n";
        std::cout << "  from        " << qtc::crypto::to_hex(spend.inputs[0].prevout.txid)
                  << ":" << spend.inputs[0].prevout.vout << "\n";
        std::cout << "  txid        " << qtc::crypto::to_hex(spend.txid()) << "\n";
        std::cout << "  size        " << spend.serialize().size() << " bytes\n";
        std::cout << "  algorithm   ML-DSA-65 (FIPS-204)\n";
        std::cout << "  signature   " << spend.signature.size() << " bytes\n";
        std::cout << "  change      " << qtc::format_qtc(change) << "\n";

        // Hand it to the running node, if there is one.
        const std::string response =
            qtc::rpc::call("127.0.0.1", 18443, "sendrawtransaction",
                      "[" + qtc::json::Value::string(qtc::crypto::to_hex(spend.serialize())).dump() + "]");
        if (response.empty()) {
            std::cout << "\nNo node running, so the signed transaction was not broadcast.\n"
                      << "Start 'qtc serve' to accept it, or start the node and retry.\n";
            return 0;
        }
        qtc::json::Value parsed;
        std::string ignored;
        qtc::json::Value::parse(response, parsed, ignored);
        if (parsed["error"].is_object()) {
            std::cerr << "Node rejected the transaction: "
                      << parsed["error"]["message"].as_string() << "\n";
            return 1;
        }
        std::cout << "\nBroadcast accepted. Mine a block to confirm it.\n";
        return 0;
    }

    if (command == "serve") {
        qtc::rpc::Context context;
        context.datadir = DATA_DIR;
        context.load_or_init();
        const uint16_t port = (argc >= 3) ? static_cast<uint16_t>(std::stoul(argv[2]))
                                          : 18443;
        return qtc::rpc::serve(context, port);
    }

    if (command == "rpccall") {
        if (argc < 3) {
            std::cerr << "Usage: qtc rpccall <method> [params-json] [port]\n";
            return 1;
        }
        // argv[1] is the command itself, so the method starts at argv[2].
        const std::string method = argv[2];
        const std::string params = (argc >= 4) ? argv[3] : "[]";
        const uint16_t port = (argc >= 5) ? static_cast<uint16_t>(std::stoul(argv[4]))
                                          : 18443;
        const std::string response =
            qtc::rpc::call("127.0.0.1", port, method, params);
        if (response.empty()) {
            std::cerr << "error: no response from 127.0.0.1:" << port
                      << " — is 'qtc serve' running?\n";
            return 1;
        }
        std::cout << response << "\n";
        return 0;
    }

    if (command == "pqvector") {
        return qtc::write_pq_vector(QTC_PQ_VECTOR_PATH) ? 0 : 1;
    }
    
    if (command == "mine") {
        qtc::Chain chain;
        open_chain(chain);
        
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
        persist_chain(chain);
        
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
        open_chain(chain, false);
        
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
