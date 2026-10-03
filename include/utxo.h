#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include "transaction.h"

namespace qtc {

// ============================================================
// UTXO — an unspent transaction output
// ============================================================
struct UTXO {
    OutPoint outpoint;
    uint64_t amount = 0;                    // in satoshis
    std::vector<uint8_t> script_pubkey;     // locking script / address commitment
    uint32_t height = 0;                    // block height where created
    bool coinbase = false;                  // is this from a coinbase tx?
};

// ============================================================
// UTXOSet — in-memory database of unspent outputs
//
// The UTXO set is the authoritative record of who owns what.
// Balances are NOT stored — they are computed from the UTXO set.
//
//   balance = sum(all UTXOs belonging to a script)
//
// ============================================================
class UTXOSet {
public:
    UTXOSet();

    // --- Core operations ---
    
    // Add a UTXO to the set
    void add_utxo(const OutPoint& outpoint, uint64_t amount,
                  const std::vector<uint8_t>& script_pubkey,
                  uint32_t height, bool coinbase);

    // Check if a UTXO exists
    bool have_utxo(const OutPoint& outpoint) const;

    // Get a UTXO (returns nullptr if not found)
    const UTXO* get_utxo(const OutPoint& outpoint) const;

    // Spend a UTXO (remove from set)
    // Returns true if the UTXO existed and was removed
    bool spend_utxo(const OutPoint& outpoint);

    // --- Queries ---

    // List all unspent UTXOs for a given script_pubkey
    std::vector<UTXO> list_unspent_for_script(const std::vector<uint8_t>& script) const;

    // Get balance for a given script_pubkey (sum of all matching UTXOs)
    uint64_t get_balance_for_script(const std::vector<uint8_t>& script) const;

    // List all UTXOs for a dev-format address
    std::vector<UTXO> list_unspent_for_address(const std::string& address) const;

    // Get balance for a dev-format address
    uint64_t get_balance_for_address(const std::string& address) const;

    // Total number of UTXOs in the set
    size_t size() const;

    // Total value in the set
    uint64_t total_value() const;

    // --- Transaction validation ---

    // Validate a transaction against the UTXO set
    // Checks: inputs exist, no duplicate inputs, input sum >= output sum
    // Does NOT check signatures (that's Day 5)
    // Returns true if valid, false otherwise (error message filled)
    bool validate_transaction(const Transaction& tx, std::string& error) const;

    // Apply a transaction to the UTXO set
    // Removes spent inputs, adds new outputs
    // Returns true if successful, false if validation fails
    bool apply_transaction(const Transaction& tx, uint32_t height, std::string& error);

    // Apply all transactions from a block (including coinbase)
    void connect_block(const std::vector<Transaction>& txs, uint32_t height);

    // Rebuild the UTXO set from scratch from a list of blocks
    void rebuild_from_blocks(const std::vector<class Block>& blocks);

    // Clear the entire set
    void clear();

private:
    // Keyed by OutPoint::key() (txid_hex:vout)
    std::map<std::string, UTXO> utxos_;
};

} // namespace qtc
