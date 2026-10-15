#include "transaction.h"
#include "crypto.h"
#include "pq_crypto.h"
#include "consensus.h"
#include <cstring>
#include <stdexcept>

namespace qtc {

namespace {

void require_bytes(size_t offset, size_t need, size_t len) {
    if (offset > len || need > len - offset) {
        throw std::runtime_error("transaction: truncated encoding");
    }
}

// Guards against a hostile CompactSize count causing a huge allocation loop.
constexpr uint64_t kMaxTxElements = 1u << 20;

} // namespace

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

OutPoint OutPoint::deserialize(const uint8_t* data, size_t len, size_t& offset) {
    require_bytes(offset, 36, len);
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

TxInput TxInput::deserialize(const uint8_t* data, size_t len, size_t& offset) {
    TxInput input;
    input.prevout = OutPoint::deserialize(data, len, offset);
    require_bytes(offset, 1, len);
    uint64_t script_len = crypto::read_compact_size(data, offset);
    require_bytes(offset, script_len, len);
    input.script.resize(script_len);
    std::memcpy(input.script.data(), data + offset, script_len);
    offset += script_len;
    require_bytes(offset, 4, len);
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

TxOutput TxOutput::deserialize(const uint8_t* data, size_t len, size_t& offset) {
    TxOutput output;
    require_bytes(offset, 8, len);
    output.amount = crypto::read_le_u64(data + offset);
    offset += 8;
    require_bytes(offset, 1, len);
    uint64_t script_len = crypto::read_compact_size(data, offset);
    require_bytes(offset, script_len, len);
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

Transaction Transaction::deserialize(const uint8_t* data, size_t len, size_t& offset,
                                     bool allow_witness) {
    Transaction tx;

    require_bytes(offset, 4, len);
    tx.version = crypto::read_le_u32(data + offset);
    offset += 4;

    require_bytes(offset, 1, len);
    uint64_t input_count = crypto::read_compact_size(data, offset);
    if (input_count > kMaxTxElements) {
        throw std::runtime_error("transaction: input count out of range");
    }
    for (uint64_t i = 0; i < input_count; ++i) {
        tx.inputs.push_back(TxInput::deserialize(data, len, offset));
    }

    require_bytes(offset, 1, len);
    uint64_t output_count = crypto::read_compact_size(data, offset);
    if (output_count > kMaxTxElements) {
        throw std::runtime_error("transaction: output count out of range");
    }
    for (uint64_t i = 0; i < output_count; ++i) {
        tx.outputs.push_back(TxOutput::deserialize(data, len, offset));
    }

    require_bytes(offset, 4, len);
    tx.locktime = crypto::read_le_u32(data + offset);
    offset += 4;

    // PQ witness follows locktime: algorithm id, then CompactSize-prefixed
    // public key and signature. Absent when the algorithm id is 0.
    if (allow_witness && offset < len && data[offset] != 0) {
        tx.sig_algorithm_id = data[offset];
        offset += 1;

        require_bytes(offset, 1, len);
        uint64_t pk_len = crypto::read_compact_size(data, offset);
        require_bytes(offset, pk_len, len);
        tx.public_key.assign(data + offset, data + offset + pk_len);
        offset += pk_len;

        require_bytes(offset, 1, len);
        uint64_t sig_len = crypto::read_compact_size(data, offset);
        require_bytes(offset, sig_len, len);
        tx.signature.assign(data + offset, data + offset + sig_len);
        offset += sig_len;
    }

    return tx;
}

Transaction Transaction::deserialize(const std::vector<uint8_t>& data) {
    size_t offset = 0;
    return deserialize(data.data(), data.size(), offset);
}

std::vector<uint8_t> Transaction::signature_hash(
        size_t input_index,
        const std::vector<uint8_t>& prev_script,
        uint64_t prev_amount) const {
    if (input_index >= inputs.size()) {
        throw std::out_of_range("signature_hash: input index out of range");
    }

    std::vector<uint8_t> preimage;
    auto append = [&preimage](const std::vector<uint8_t>& bytes) {
        preimage.insert(preimage.end(), bytes.begin(), bytes.end());
    };

    append(std::vector<uint8_t>{'Q', 'T', 'C', 'S', 'I', 'G', 'H', '1'});

    auto v32 = crypto::write_le_u32(version);
    append(v32);

    auto idx = crypto::write_le_u64(static_cast<uint64_t>(input_index));
    append(idx);

    append(inputs[input_index].prevout.serialize());

    auto amount = crypto::write_le_u64(prev_amount);
    append(amount);

    auto script_len = crypto::write_compact_size(prev_script.size());
    append(script_len);
    append(prev_script);

    auto output_count = crypto::write_compact_size(outputs.size());
    append(output_count);
    for (const auto& output : outputs) {
        auto out_amount = crypto::write_le_u64(output.amount);
        append(out_amount);
        auto out_script_len = crypto::write_compact_size(output.script.size());
        append(out_script_len);
        append(output.script);
    }

    auto lock = crypto::write_le_u32(locktime);
    append(lock);

    append(std::vector<uint8_t>{sig_algorithm_id});

    return crypto::double_sha256(preimage);
}

bool Transaction::sign_input(size_t input_index,
                             const std::vector<uint8_t>& prev_script,
                             uint64_t prev_amount,
                             const std::vector<uint8_t>& secret_key,
                             std::string* error_out) {
    if (inputs.empty() || is_coinbase()) {
        if (error_out) *error_out = "sign_input: coinbase transactions are not signed";
        return false;
    }
    if (sig_algorithm_id != pq::SIG_ML_DSA_65) {
        sig_algorithm_id = pq::SIG_ML_DSA_65;
    }

    auto digest = signature_hash(input_index, prev_script, prev_amount);
    auto sig = pq::sign_mldsa65(secret_key, digest, error_out);
    if (sig.empty()) return false;
    signature = std::move(sig);
    return true;
}

pq::SignatureResult Transaction::verify_input(size_t input_index,
                                             const std::vector<uint8_t>& prev_script,
                                             uint64_t prev_amount) const {
    pq::SignatureResult result;
    if (inputs.empty() || is_coinbase()) {
        result.error = "verify_input: coinbase transactions carry no witness";
        return result;
    }
    if (sig_algorithm_id != pq::SIG_ML_DSA_65) {
        result.error = "unsupported signature algorithm id " +
                       std::to_string(sig_algorithm_id);
        return result;
    }
    if (public_key.empty() || signature.empty()) {
        result.error = "transaction is not signed";
        return result;
    }

    auto digest = signature_hash(input_index, prev_script, prev_amount);
    return pq::verify_mldsa65(public_key, digest, signature);
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
    // A bech32m qtc/tqtc address becomes a post-quantum witness program script.
    // Everything else falls back to the dev format.
    if (address.rfind("qtc1", 0) == 0 || address.rfind("tqtc1", 0) == 0) {
        auto pq_script = for_qtc_address(address);
        if (!pq_script.empty()) return pq_script;
    }

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

std::vector<uint8_t> for_witness_program(uint8_t witness_version,
                                         uint8_t algo_id,
                                         const std::vector<uint8_t>& program) {
    std::vector<uint8_t> script;
    script.push_back(PQ_MARKER);
    script.push_back(witness_version);
    script.push_back(algo_id);
    script.insert(script.end(), program.begin(), program.end());
    return script;
}

std::vector<uint8_t> for_qtc_address(const std::string& address) {
    auto decoded = pq::decode_address(address);
    if (!decoded.valid) return {};
    if (decoded.program.size() != pq::WITNESS_PROGRAM_SIZE) return {};
    return for_witness_program(decoded.witness_version, pq::SIG_ML_DSA_65,
                               decoded.program);
}

bool is_pq_script(const std::vector<uint8_t>& script) {
    return script.size() == 4 + pq::WITNESS_PROGRAM_SIZE && script[0] == PQ_MARKER;
}

std::vector<uint8_t> witness_program_from(const std::vector<uint8_t>& script) {
    if (!is_pq_script(script)) return {};
    return std::vector<uint8_t>(script.begin() + 4, script.end());
}

bool is_dev_script(const std::vector<uint8_t>& script) {
    return !script.empty() && script[0] == DEV_MARKER;
}

} // namespace script

} // namespace qtc
