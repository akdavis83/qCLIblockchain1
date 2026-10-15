#include "mempool.h"

#include <algorithm>

#include "consensus.h"
#include "crypto.h"

namespace qtc {

namespace {

bool spends_an_input_of(const Transaction& tx, const Transaction& other) {
    for (const auto& input : tx.inputs) {
        for (const auto& candidate : other.inputs) {
            if (input.prevout.key() == candidate.prevout.key()) return true;
        }
    }
    return false;
}

} // namespace

bool Mempool::admit(const UTXOSet& confirmed, const Transaction& tx,
                    std::string& error) {
    if (tx.is_coinbase()) {
        error = "coinbase transactions are not relayed";
        return false;
    }
    if (tx.inputs.empty() || tx.outputs.empty()) {
        error = "transaction has no inputs or no outputs";
        return false;
    }

    std::string utxo_error;
    if (!confirmed.validate_transaction(tx, utxo_error)) {
        error = utxo_error;
        return false;
    }

    const auto txid = tx.txid();
    if (contains(txid)) {
        error = "transaction already in the mempool";
        return false;
    }

    for (const auto& entry : entries_) {
        if (spends_an_input_of(tx, entry.tx)) {
            error = "double spend against mempool transaction " +
                    crypto::to_hex(entry.tx.txid()).substr(0, 16);
            return false;
        }
        if (spends_an_input_of(entry.tx, tx)) {
            error = "double spend: a pending transaction already spends this output";
            return false;
        }
    }

    uint64_t input_sum = 0;
    for (const auto& input : tx.inputs) {
        const UTXO* utxo = confirmed.get_utxo(input.prevout);
        if (!utxo) {
            error = "input not found in the confirmed UTXO set";
            return false;
        }
        input_sum += utxo->amount;
    }
    const uint64_t fee = input_sum - tx.total_output();

    if (fee < MIN_TX_FEE) {
        error = "fee " + std::to_string(fee) + " is below the minimum " +
                std::to_string(MIN_TX_FEE);
        return false;
    }

    Entry entry;
    entry.tx = tx;
    entry.fee = fee;
    entry.vbytes = tx.serialize().size();
    entry.fee_rate = entry.vbytes ? fee / entry.vbytes : fee;
    entry.arrival = next_arrival_++;
    entries_.push_back(std::move(entry));

    // Evict the lowest fee rate when over capacity. Ties drop the newest, so a
    // flood of identical-fee transactions cannot displace earlier ones.
    if (entries_.size() > MEMPOOL_MAX_TRANSACTIONS) {
        auto worst = std::min_element(
            entries_.begin(), entries_.end(), [](const Entry& a, const Entry& b) {
                if (a.fee_rate != b.fee_rate) return a.fee_rate < b.fee_rate;
                return a.arrival > b.arrival;
            });
        entries_.erase(worst);
    }
    return true;
}

void Mempool::clear() {
    entries_.clear();
    next_arrival_ = 0;
}

uint64_t Mempool::total_fees() const {
    uint64_t total = 0;
    for (const auto& entry : entries_) total += entry.fee;
    return total;
}

uint64_t Mempool::average_fee_rate() const {
    if (entries_.empty()) return 0;
    return total_fees() / entries_.size();
}

bool Mempool::contains(const std::vector<uint8_t>& txid) const {
    return std::any_of(entries_.begin(), entries_.end(),
                       [&](const Entry& e) { return e.tx.txid() == txid; });
}

std::vector<Transaction> Mempool::by_fee_rate() const {
    std::vector<const Entry*> sorted;
    sorted.reserve(entries_.size());
    for (const auto& entry : entries_) sorted.push_back(&entry);

    std::sort(sorted.begin(), sorted.end(), [](const Entry* a, const Entry* b) {
        if (a->fee_rate != b->fee_rate) return a->fee_rate > b->fee_rate;
        return a->arrival < b->arrival;
    });

    std::vector<Transaction> out;
    out.reserve(sorted.size());
    for (const Entry* entry : sorted) out.push_back(entry->tx);
    return out;
}

void Mempool::remove_confirmed(const std::vector<Transaction>& confirmed,
                               const UTXOSet& confirmed_set) {
    std::vector<std::vector<uint8_t>> mined;
    mined.reserve(confirmed.size());
    for (const auto& tx : confirmed) mined.push_back(tx.txid());

    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const Entry& e) {
                           const auto id = e.tx.txid();
                           if (std::find(mined.begin(), mined.end(), id) != mined.end()) {
                               return true;
                           }
                           // Drop anything that a confirmed transaction made
                           // invalid, e.g. a double spend that lost.
                           std::string err;
                           return !confirmed_set.validate_transaction(e.tx, err);
                       }),
        entries_.end());
}

} // namespace qtc