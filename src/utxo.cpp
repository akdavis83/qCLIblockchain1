#include "utxo.h"
#include "crypto.h"
#include "block.h"
#include <iostream>
#include <set>

namespace qtc {

// ============================================================
// UTXOSet
// ============================================================

UTXOSet::UTXOSet() {}

void UTXOSet::add_utxo(const OutPoint& outpoint, uint64_t amount,
                       const std::vector<uint8_t>& script_pubkey,
                       uint32_t height, bool coinbase) {
    UTXO utxo;
    utxo.outpoint = outpoint;
    utxo.amount = amount;
    utxo.script_pubkey = script_pubkey;
    utxo.height = height;
    utxo.coinbase = coinbase;
    utxos_[outpoint.key()] = utxo;
}

bool UTXOSet::have_utxo(const OutPoint& outpoint) const {
    return utxos_.find(outpoint.key()) != utxos_.end();
}

const UTXO* UTXOSet::get_utxo(const OutPoint& outpoint) const {
    auto it = utxos_.find(outpoint.key());
    if (it == utxos_.end()) return nullptr;
    return &it->second;
}

bool UTXOSet::spend_utxo(const OutPoint& outpoint) {
    auto it = utxos_.find(outpoint.key());
    if (it == utxos_.end()) return false;
    utxos_.erase(it);
    return true;
}

std::vector<UTXO> UTXOSet::list_unspent_for_script(const std::vector<uint8_t>& script) const {
    std::vector<UTXO> result;
    for (const auto& [key, utxo] : utxos_) {
        if (utxo.script_pubkey == script) {
            result.push_back(utxo);
        }
    }
    return result;
}

uint64_t UTXOSet::get_balance_for_script(const std::vector<uint8_t>& script) const {
    uint64_t total = 0;
    for (const auto& [key, utxo] : utxos_) {
        if (utxo.script_pubkey == script) {
            total += utxo.amount;
        }
    }
    return total;
}

std::vector<UTXO> UTXOSet::list_unspent_for_address(const std::string& address) const {
    return list_unspent_for_script(script::for_address(address));
}

uint64_t UTXOSet::get_balance_for_address(const std::string& address) const {
    return get_balance_for_script(script::for_address(address));
}

size_t UTXOSet::size() const {
    return utxos_.size();
}

uint64_t UTXOSet::total_value() const {
    uint64_t total = 0;
    for (const auto& [key, utxo] : utxos_) {
        total += utxo.amount;
    }
    return total;
}

bool UTXOSet::validate_transaction(const Transaction& tx, std::string& error) const {
    // Coinbase transactions bypass input validation
    if (tx.is_coinbase()) {
        // Validate coinbase: must have exactly 1 input, 1+ outputs
        if (tx.inputs.size() != 1) {
            error = "Coinbase must have exactly 1 input";
            return false;
        }
        if (tx.outputs.empty()) {
            error = "Coinbase must have at least 1 output";
            return false;
        }
        // Check coinbase reward (Day 4 will enforce exact subsidy)
        return true;
    }
    
    // 1. Check for duplicate inputs
    std::set<std::string> seen_inputs;
    for (const auto& input : tx.inputs) {
        std::string key = input.prevout.key();
        if (seen_inputs.count(key)) {
            error = "Duplicate input: " + key;
            return false;
        }
        seen_inputs.insert(key);
    }
    
    // 2. Check all inputs exist in the UTXO set
    for (const auto& input : tx.inputs) {
        if (!have_utxo(input.prevout)) {
            error = "Input not found in UTXO set: " + input.prevout.key();
            return false;
        }
    }
    
    // 3. Calculate input sum
    uint64_t input_sum = 0;
    for (const auto& input : tx.inputs) {
        const UTXO* utxo = get_utxo(input.prevout);
        input_sum += utxo->amount;
    }
    
    // 4. Calculate output sum
    uint64_t output_sum = tx.total_output();
    
    // 5. Check input_sum >= output_sum (fee = input_sum - output_sum)
    if (input_sum < output_sum) {
        error = "Input sum (" + std::to_string(input_sum) + 
                ") < output sum (" + std::to_string(output_sum) + ")";
        return false;
    }
    
    // 6. Check for zero-value outputs
    for (size_t i = 0; i < tx.outputs.size(); ++i) {
        if (tx.outputs[i].amount == 0) {
            error = "Output " + std::to_string(i) + " has zero value";
            return false;
        }
    }
    
    // Fee is valid (input_sum - output_sum >= 0)
    return true;
}

bool UTXOSet::apply_transaction(const Transaction& tx, uint32_t height, std::string& error) {
    // Validate first
    if (!validate_transaction(tx, error)) {
        return false;
    }
    
    // For coinbase: just add the output
    if (tx.is_coinbase()) {
        auto txid = tx.txid();
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            OutPoint out;
            out.txid = txid;
            out.vout = static_cast<uint32_t>(i);
            add_utxo(out, tx.outputs[i].amount, tx.outputs[i].script, height, true);
        }
        return true;
    }
    
    // Remove spent inputs
    for (const auto& input : tx.inputs) {
        spend_utxo(input.prevout);
    }
    
    // Add new outputs
    auto txid = tx.txid();
    for (size_t i = 0; i < tx.outputs.size(); ++i) {
        OutPoint out;
        out.txid = txid;
        out.vout = static_cast<uint32_t>(i);
        add_utxo(out, tx.outputs[i].amount, tx.outputs[i].script, height, false);
    }
    
    return true;
}

void UTXOSet::connect_block(const std::vector<Transaction>& txs, uint32_t height) {
    std::string error;
    for (const auto& tx : txs) {
        if (!apply_transaction(tx, height, error)) {
            std::cerr << "Warning: failed to apply transaction in block " << height
                      << ": " << error << std::endl;
        }
    }
}

void UTXOSet::rebuild_from_blocks(const std::vector<Block>& blocks) {
    clear();
    for (uint32_t h = 0; h < blocks.size(); ++h) {
        connect_block(blocks[h].transactions, h);
    }
}

void UTXOSet::clear() {
    utxos_.clear();
}

} // namespace qtc
