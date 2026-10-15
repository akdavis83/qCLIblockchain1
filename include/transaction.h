#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "consensus.h"
#include "pq_crypto.h"

namespace qtc {

// ============================================================
// OutPoint — reference to a previous transaction output
// ============================================================
struct OutPoint {
    std::vector<uint8_t> txid;   // 32-byte transaction ID
    uint32_t vout = 0;           // output index

    bool is_null() const { return txid.empty(); }
    std::vector<uint8_t> serialize() const;
    static OutPoint deserialize(const uint8_t* data, size_t len, size_t& offset);
    
    // For use as map key
    std::string key() const;
    bool operator==(const OutPoint& other) const;
    bool operator<(const OutPoint& other) const;
};

// ============================================================
// TxInput
// ============================================================
struct TxInput {
    OutPoint prevout;
    std::vector<uint8_t> script;    // unlocking script / witness data
    uint32_t sequence = 0xffffffff;

    std::vector<uint8_t> serialize() const;
    static TxInput deserialize(const uint8_t* data, size_t len, size_t& offset);
};

// ============================================================
// TxOutput
// ============================================================
struct TxOutput {
    uint64_t amount = 0;             // in satoshis
    std::vector<uint8_t> script;     // locking script / address commitment

    std::vector<uint8_t> serialize() const;
    static TxOutput deserialize(const uint8_t* data, size_t len, size_t& offset);
};

// ============================================================
// QTC Transaction v1
//
// PQ witness structure (modular, for Day 5 integration):
//   - algorithm_id (1 byte): SigAlgorithm enum
//   - public_key (CompactSize length + data): ML-DSA-65 public key (1952 bytes)
//   - signature (CompactSize length + data): ML-DSA-65 signature (up to 3293 bytes)
//
struct Transaction {
    uint32_t version = TX_VERSION;
    std::vector<TxInput> inputs;
    std::vector<TxOutput> outputs;
    uint32_t locktime = 0;

    // PQ witness data (placeholder for Day 5)
    uint8_t sig_algorithm_id = 0;  // 0 = unsigned (placeholder)
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> signature;

    // Serialize the full transaction (for txid computation)
    std::vector<uint8_t> serialize() const;

    // Deserialize from bytes. `len` bounds every read; malformed input throws.
    //
    // `allow_witness` must be false when another transaction follows in the same
    // buffer. Without it a coinbase would read the next transaction's version
    // byte as a witness algorithm id. Only the coinbase lacks a witness.
    static Transaction deserialize(const uint8_t* data, size_t len, size_t& offset,
                                  bool allow_witness = true);
    static Transaction deserialize(const std::vector<uint8_t>& data);

    // Deterministic 32-byte message signed for the given input. Commits to the
    // input being signed, the output it spends, every output, locktime and the
    // signature algorithm. Never signs a serialization containing the witness,
    // which would be circular.
    std::vector<uint8_t> signature_hash(
        size_t input_index,
        const std::vector<uint8_t>& prev_script,
        uint64_t prev_amount) const;

    // Attach a PQ signature over the given input, replacing any existing one.
    bool sign_input(size_t input_index,
                    const std::vector<uint8_t>& prev_script,
                    uint64_t prev_amount,
                    const std::vector<uint8_t>& secret_key,
                    std::string* error_out = nullptr);

    // Verify the PQ signature over the given input.
    pq::SignatureResult verify_input(size_t input_index,
                                 const std::vector<uint8_t>& prev_script,
                                 uint64_t prev_amount) const;

    // Compute transaction ID (double SHA-256 of serialized tx)
    std::vector<uint8_t> txid() const;
    std::string txid_hex() const;

    // Check if this is a coinbase transaction
    bool is_coinbase() const;

    // Create a genesis coinbase transaction with a given message
    static Transaction create_genesis_coinbase(const std::string& message, uint64_t reward);

    // Create a standard coinbase for a mined block
    static Transaction create_coinbase(uint32_t height, const std::string& message,
                                       uint64_t reward,
                                       const std::vector<uint8_t>& script_pubkey);
    
    // Compute total output value
    uint64_t total_output() const;
    // Compute total input value (requires UTXO lookup — returns 0 if unknown)
    // Actual input value lookup is done by UTXOSet
};

// ============================================================
// Script helpers (development format)
// For Day 3, scripts use a simple format: marker byte + ASCII address
// This will be replaced by real witness programs in Day 5.
// ============================================================

namespace script {

// Dev script format: 0x51 (OP_TRUE) prefix is NOT used.
// Instead, we use a simple format:
//   [0xDE] (dev marker) [address bytes as ASCII]
// This allows us to extract an address from a UTXO for balance lookups.

constexpr uint8_t DEV_MARKER = 0xDE;

// Create a locking script for a dev address (e.g., "Alice", "Bob")
std::vector<uint8_t> for_address(const std::string& address);

// Extract the address from a dev-format script
// Returns empty string if not a dev-format script
std::string address_from(const std::vector<uint8_t>& script);

// Check if a script is a dev-format script
bool is_dev_script(const std::vector<uint8_t>& script);

// Locking script for a post-quantum witness program:
//
//   [0x01] [witness version] [algorithm id] [program bytes]
//
// 0x01 cannot collide with DEV_MARKER (0xDE), so the two forms stay
// distinguishable and a UTXO always reveals which one it carries.
constexpr uint8_t PQ_MARKER = 0x01;

// Build a locking script from a decoded witness program.
std::vector<uint8_t> for_witness_program(uint8_t witness_version,
                                         uint8_t algo_id,
                                         const std::vector<uint8_t>& program);

// Build a locking script from a bech32m qtc/tqtc address. Returns an empty
// script if the address is invalid, malformed, or is not a post-quantum program.
std::vector<uint8_t> for_qtc_address(const std::string& address);

// True when the script is a post-quantum witness program.
bool is_pq_script(const std::vector<uint8_t>& script);

// Extract the program bytes from a post-quantum script. Empty if not one.
std::vector<uint8_t> witness_program_from(const std::vector<uint8_t>& script);

} // namespace script

} // namespace qtc
