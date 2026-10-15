#include "wallet/wallet.h"

#include <cstdlib>
#include <map>
#include <fstream>
#include <random>
#include <sstream>

#include "crypto.h"

namespace qtc {
namespace wallet {
namespace {

// Domain tag the reference wallet applies to the master seed before deriving
// the ML-DSA-65 signing seed. Both sides must use these exact bytes.
const std::vector<uint8_t> kDsaSeedDomain = {
    'Q', 'T', 'C', '_', 'P', 'Q', 'H', 'D', '_', 'D', 'I', 'L', 'I', 'T', 'H', 'I', 'U', 'M'};

std::string to_hex(const std::vector<uint8_t>& data) {
    return crypto::to_hex(data);
}

std::vector<uint8_t> from_hex(const std::string& text) {
    return crypto::from_hex(text);
}

} // namespace

Wallet Wallet::from_seed(const std::vector<uint8_t>& master_seed, Network network) {
    Wallet w;
    w.network_ = network;
    w.master_seed_ = master_seed;

    if (master_seed.empty()) {
        w.error_ = "master seed must not be empty";
        return w;
    }

    auto kem = pq::kem_self_from_seed(master_seed);
    if (!kem.error.empty()) {
        w.error_ = "ML-KEM-1024: " + kem.error;
        return w;
    }
    w.kem_public_key_ = kem.public_key;
    w.kem_secret_key_ = kem.secret_key;

    // The signing seed is domain-separated from the master seed, and is derived
    // independently of the KEM shared secret.
    auto dsa_seed = crypto::shake256_expand(32, {master_seed, kDsaSeedDomain});
    auto dsa = pq::generate_mldsa65_keypair(dsa_seed);
    if (!dsa.error.empty()) {
        w.error_ = "ML-DSA-65: " + dsa.error;
        return w;
    }
    w.dsa_public_key_ = dsa.public_key;
    w.dsa_secret_key_ = dsa.secret_key;

    std::vector<uint8_t> combined = kem.shared_secret;
    combined.insert(combined.end(), dsa.public_key.begin(), dsa.public_key.end());
    // 32 bytes, matching the reference wallet. Note its `SHAKE.digest(64)` does
    // not request 64 bytes — the npm sha3 package treats that argument as an
    // output format, so it silently squeezes the 32-byte default.
    auto master_entropy = crypto::shake256(32, combined);
    w.program_ = crypto::sha3_256(master_entropy);
    w.address_ = pq::encode_address(w.program_, network);
    return w;
}

Wallet Wallet::generate(Network network) {
    std::random_device device;
    std::vector<uint8_t> seed(32);
    for (auto& byte : seed) byte = static_cast<uint8_t>(device());
    return from_seed(seed, network);
}

std::vector<uint8_t> Wallet::script_pubkey() const {
    if (program_.empty()) return {};
    return script::for_witness_program(0, pq::SIG_ML_DSA_65, program_);
}

bool Wallet::sign(Transaction& tx, size_t input_index,
                  const std::vector<uint8_t>& prev_script,
                  uint64_t prev_amount) const {
    if (!valid()) return false;
    tx.public_key = dsa_public_key_;
    return tx.sign_input(input_index, prev_script, prev_amount, dsa_secret_key_);
}

std::string WalletFile::serialize() const {
    std::ostringstream out;
    out << "algorithm=ML-KEM-1024+ML-DSA-65\n"
        << "seed_hex=" << to_hex(master_seed) << "\n"
        << "address=" << address << "\n"
        << "ml_dsa_public_hex=" << to_hex(ml_dsa_public_key) << "\n"
        << "ml_dsa_secret_hex=" << to_hex(ml_dsa_secret_key) << "\n"
        << "ml_kem_public_hex=" << to_hex(ml_kem_public_key) << "\n"
        << "ml_kem_secret_hex=" << to_hex(ml_kem_secret_key) << "\n";
    return out.str();
}

bool WalletFile::deserialize(const std::string& text, WalletFile& out,
                             std::string* error_out) {
    auto fail = [&](const std::string& message) {
        if (error_out) *error_out = message;
        return false;
    };

    std::map<std::string, std::string> fields;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) return fail("wallet line has no '=': " + line);
        fields[line.substr(0, eq)] = line.substr(eq + 1);
    }

    auto require = [&](const char* key, std::vector<uint8_t>& target) {
        auto it = fields.find(key);
        if (it == fields.end() || it->second.empty()) {
            return fail(std::string("wallet file is missing ") + key);
        }
        target = from_hex(it->second);
        if (target.empty()) return fail(std::string("wallet field ") + key + " is not hex");
        return true;
    };

    WalletFile parsed;
    if (!require("seed_hex", parsed.master_seed)) return false;
    if (!require("ml_dsa_public_hex", parsed.ml_dsa_public_key)) return false;
    if (!require("ml_dsa_secret_hex", parsed.ml_dsa_secret_key)) return false;
    if (!require("ml_kem_public_hex", parsed.ml_kem_public_key)) return false;
    if (!require("ml_kem_secret_hex", parsed.ml_kem_secret_key)) return false;

    auto it = fields.find("address");
    if (it == fields.end() || it->second.empty()) return fail("wallet file is missing address");
    parsed.address = it->second;

    if (parsed.ml_dsa_public_key.size() != pq::ML_DSA_65_PUBLIC_KEY_SIZE) {
        return fail("stored ML-DSA-65 public key has the wrong length");
    }
    if (parsed.ml_dsa_secret_key.size() != pq::ML_DSA_65_SECRET_KEY_SIZE) {
        return fail("stored ML-DSA-65 secret key has the wrong length");
    }

    out = std::move(parsed);
    if (error_out) error_out->clear();
    return true;
}

bool WalletFile::save(const std::string& path, std::string* error_out) const {
    std::ofstream file(path);
    if (!file) {
        if (error_out) *error_out = "cannot write " + path;
        return false;
    }
    file << serialize();
    return static_cast<bool>(file);
}

bool WalletFile::load(const std::string& path, WalletFile& out, std::string* error_out) {
    std::ifstream file(path);
    if (!file) {
        if (error_out) *error_out = "cannot read " + path;
        return false;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return deserialize(buffer.str(), out, error_out);
}

bool wallet_from_file(const WalletFile& file, Wallet& out) {
    // Rebuild from the seed rather than trusting the stored keys or address, so
    // a tampered file cannot silently redirect funds.
    Wallet rebuilt = Wallet::from_seed(file.master_seed);
    if (!rebuilt.valid()) {
        out = Wallet();
        return false;
    }
    if (rebuilt.address() != file.address) return false;
    if (rebuilt.ml_dsa_public_key() != file.ml_dsa_public_key) return false;
    if (rebuilt.ml_kem_public_key() != file.ml_kem_public_key) return false;

    out = std::move(rebuilt);
    return true;
}

} // namespace wallet
} // namespace qtc