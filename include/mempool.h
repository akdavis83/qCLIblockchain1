#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "block.h"
#include "transaction.h"
#include "utxo.h"

namespace qtc {

// Unconfirmed transactions waiting to be mined.
//
// Admission is consensus-relevant: a transaction must be signed, must not
// double spend against either the confirmed set or the mempool, and must clear
// MIN_TX_FEE. Ordering and eviction use fee rate, not absolute fee, so a
// transaction is never penalised for carrying a larger ML-DSA-65 witness.
class Mempool {
public:
    struct Entry {
        Transaction tx;
        uint64_t fee = 0;
        size_t vbytes = 0;   // serialized size, the weight proxy used here
        uint64_t fee_rate = 0;  // satoshis per byte
        uint64_t arrival = 0;   // insertion order, for stable ordering
    };

    // Validates against the confirmed UTXO set plus everything already pending.
    // On rejection `error` explains why.
    bool admit(const UTXOSet& confirmed, const Transaction& tx, std::string& error);

    void clear();
    size_t size() const { return entries_.size(); }
    bool empty() const { return entries_.empty(); }
    uint64_t total_fees() const;
    uint64_t average_fee_rate() const;

    bool contains(const std::vector<uint8_t>& txid) const;

    // Pending transactions in descending fee rate, ties broken by arrival order.
    std::vector<Transaction> by_fee_rate() const;

    // Drops the given transactions (confirmed in a block) and anything that
    // became invalid as a result.
    void remove_confirmed(const std::vector<Transaction>& confirmed,
                          const UTXOSet& confirmed_set);

    const std::vector<Entry>& entries() const { return entries_; }

private:
    std::vector<Entry> entries_;
    uint64_t next_arrival_ = 0;
};

} // namespace qtc