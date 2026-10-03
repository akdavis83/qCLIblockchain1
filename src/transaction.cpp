#include "transaction.h"
#include "crypto.h"
#include "consensus.h"
#include <cstring>
#include <stdexcept>

namespace qtc {

// ============================================================
// OutPoint
// ============================================================

std::vector<uint8_t> OutPoint::serialize() const {
    std::vector<uint8_t> result;
    result.reserve(36);
    for (size_t i = 0; i < 32; ++i) {
        result.push_back(i < txid.size() ? txid[i] : 0);
    }
    auto vout_bytes = crypto::write_le_u32(vout);
    result.insert(result.end(), vout_bytes.begin(), vout_bytes.end());
    return result;
}

OutPoint OutPoint::deserialize(const uint8_t* data, size_t& offset) {
    OutPoint out;
    out.txid.resize(32);
    std::memcpy(out.txid.data(), data + offset, 32);
    offset += 32;
    out.vout = crypto::read_le_u32(data + offset);
    offset += 4;
    return out;
}

std::string OutPoint::key() const {
    return crypto::to_hex(txid) + ":" + std::to_string(vout);
}

bool OutPoint::operator==(const OutPoint& other) const {
    return vout == other.vout && txid == other.txid;
}

bool OutPoint::operator<(const OutPoint& other) const {
    if (txid != other.txid) return txid < other.txid;
    return vout < other.vout;
}

// ============================================================
// TxInput
// ============================================================

std::vector<uint8_t> TxInput::serialize() const {
    std::vector<uint8_t> result;
    auto prevout_bytes = prevout.serialize();
    result.insert(result.end(), prevout_bytes.begin(), prevout_bytes.end());
    auto script_len = crypto::write_compact_size(script.size());
    result.insert(result.end(), script_len.begin(), script_len.end());
    result.insert(result.end(), script.begin(), script.end());
    auto seq_bytes = crypto::write_le_u32(sequence);
    result.insert(result.end(), seq_bytes.begin(), seq_bytes.end());
    return result;
}

TxInput TxInput::deserialize(const uint8_t* data, size_t& offset) {
    TxInput input;
    input.prevout = OutPoint::deserialize(data, offset);
    uint64_t script_len = crypto::read_compact_size(data, offset);
    input.script.resize(script_len);
    std::memcpy(input.script.data(), data + offset, script_len);
    offset += script_len;
    input.sequence = crypto::read_le_u32(data + offset);
    offset += 4;
    return input;
}

// ============================================================
// TxOutput
// ============================================================

std::vector<uint8_t> TxOutput::serialize() const {
    std::vector<uint8_t> result;
    auto amount_bytes = crypto::write_le_u64(amount);
    result.insert(result.end(), amount_bytes.begin(), amount_bytes.end());
    auto script_len = crypto::write_compact_size(script.size());
    result.insert(result.end(), script_len.begin(), script_len.end());
    result.insert(result.end(), script.begin(), script.end());
    return result;
}

TxOutput TxOutput::deserialize(const uint8_t* data, size_t& offset) {
    TxOutput output;
    output.amount = crypto::read_le_u64(data + offset);
    offset += 8;
    uint64_t script_len = crypto::read_compact_size(data, offset);
    output.script.resize(script_len);
    std::memcpy(output.script.data(), data + offset, script_len);
    offset += script_len;
    return output;
}

// ============================================================
// Transaction
// ============================================================

std::vector<uint8_t> Transaction::serialize() const {
    std::vector<uint8_t> result;
    
    // Version (4 bytes LE)
    auto version_bytes = crypto::write_le_u32(version);
    result.insert(result.end(), version_bytes.begin(), version_bytes.end());
    
    // Input count (CompactSize)
    auto input_count = crypto::write_compact_size(inputs.size());
    result.insert(result.end(), input_count.begin(), input_count.end());
    
    // Inputs
    for (const auto& input : inputs) {
        auto input_bytes = input.serialize();
        result.insert(result.end(), input_bytes.begin(), input_bytes.end());
    }
    
    // Output count (CompactSize)
    auto output_count = crypto::write_compact_size(outputs.size());
    result.insert(result.end(), output_count.begin(), output_count.end());
    
    // Outputs
    for (const auto& output : outputs) {
        auto output_bytes = output.serialize();
        result.insert(result.end(), output_bytes.begin(), output_bytes.end());
    }
    
    // Locktime (4 bytes LE)
    auto locktime_bytes = crypto::write_le_u32(locktime);
    result.insert(result.end(), locktime_bytes.begin(), locktime_bytes.end());
    
    // PQ witness data (appended after locktime for v1)
    // Uses CompactSize for lengths to support ML-DSA-65 key/sig sizes
    if (sig_algorithm_id != 0) {
        result.push_back(sig_algorithm_id);
        auto pk_len = crypto::write_compact_size(public_key.size());
        result.insert(result.end(), pk_len.begin(), pk_len.end());
        result.insert(result.end(), public_key.begin(), public_key.end());
        auto sig_len = crypto::write_compact_size(signature.size());
        result.insert(result.end(), sig_len.begin(), sig_len.end());
        result.insert(result.end(), signature.begin(), signature.end());
    }
    
    return result;
}

Transaction Transaction::deserialize(const uint8_t* data, size_t& offset) {
    Transaction tx;
    
    tx.version = crypto::read_le_u32(data + offset);
    offset += 4;
    
    uint64_t input_count = crypto::read_compact_size(data, offset);
    for (uint64_t i = 0; i < input_count; ++i) {
        tx.inputs.push_back(TxInput::deserialize(data, offset));
    }
    
    uint64_t output_count = crypto::read_compact_size(data, offset);
    for (uint64_t i = 0; i < output_count; ++i) {
        tx.outputs.push_back(TxOutput::deserialize(data, offset));
    }
    
    tx.locktime = crypto::read_le_u32(data + offset);
    offset += 4;
    
    // PQ witness data (if present)
    // NOTE: Day 3 deserialization only parses unsigned transactions.
    // PQ witness parsing (sig_algorithm_id, public_key, signature) will be
    // implemented in Day 5 when liboqs is linked. For now, witness data
    // after locktime is not parsed. Do not use this for signed transactions.
    if (offset < SIZE_MAX) {
        // Witness parsing would go here in Day 5
        // For now, we only deserialize the unsigned portion
    }
    
    return tx;
}

Transaction Transaction::deserialize(const std::vector<uint8_t>& data) {
    size_t offset = 0;
    return deserialize(data.data(), offset);
}

std::vector<uint8_t> Transaction::txid() const {
    return crypto::double_sha256(serialize());
}

std::string Transaction::txid_hex() const {
    return crypto::to_hex(txid());
}

bool Transaction::is_coinbase() const {
    if (inputs.size() != 1) return false;
    const auto& prevout = inputs[0].prevout;
    if (prevout.vout != 0xffffffff) return false;
    if (prevout.txid.size() != 32) return true;
    for (uint8_t b : prevout.txid) {
        if (b != 0) return false;
    }
    return true;
}

Transaction Transaction::create_genesis_coinbase(const std::string& message, uint64_t reward) {
    Transaction tx;
    tx.version = TX_VERSION;
    
    TxInput input;
    input.prevout.txid = std::vector<uint8_t>(32, 0);
    input.prevout.vout = 0xffffffff;
    
    std::vector<uint8_t> script;
    script.push_back(0x00);  // Height 0
    for (char c : message) {
        script.push_back(static_cast<uint8_t>(c));
    }
    input.script = script;
    input.sequence = 0xffffffff;
    tx.inputs.push_back(input);
    
    TxOutput output;
    output.amount = reward;
    output.script = {0x51};  // OP_TRUE for genesis
    tx.outputs.push_back(output);
    
    return tx;
}

Transaction Transaction::create_coinbase(uint32_t height, const std::string& message,
                                          uint64_t reward,
                                          const std::vector<uint8_t>& script_pubkey) {
    Transaction tx;
    tx.version = TX_VERSION;
    
    TxInput input;
    input.prevout.txid = std::vector<uint8_t>(32, 0);
    input.prevout.vout = 0xffffffff;
    
    // BIP34-style height encoding (simplified)
    std::vector<uint8_t> script;
    if (height < 253) {
        script.push_back(static_cast<uint8_t>(height));
    } else {
        script.push_back(0xFD);
        script.push_back(static_cast<uint8_t>(height & 0xFF));
        script.push_back(static_cast<uint8_t>((height >> 8) & 0xFF));
    }
    for (char c : message) {
        script.push_back(static_cast<uint8_t>(c));
    }
    input.script = script;
    input.sequence = 0xffffffff;
    tx.inputs.push_back(input);
    
    TxOutput output;
    output.amount = reward;
    output.script = script_pubkey;
    tx.outputs.push_back(output);
    
    return tx;
}

uint64_t Transaction::total_output() const {
    uint64_t total = 0;
    for (const auto& output : outputs) {
        total += output.amount;
    }
    return total;
}

// ============================================================
// Script helpers (development format)
// ============================================================

namespace script {

std::vector<uint8_t> for_address(const std::string& address) {
    std::vector<uint8_t> script;
    script.push_back(DEV_MARKER);
    for (char c : address) {
        script.push_back(static_cast<uint8_t>(c));
    }
    return script;
}

std::string address_from(const std::vector<uint8_t>& script) {
    if (!is_dev_script(script)) return "";
    std::string addr;
    for (size_t i = 1; i < script.size(); ++i) {
        addr += static_cast<char>(script[i]);
    }
    return addr;
}

bool is_dev_script(const std::vector<uint8_t>& script) {
    return !script.empty() && script[0] == DEV_MARKER;
}

} // namespace script

} // namespace qtc
