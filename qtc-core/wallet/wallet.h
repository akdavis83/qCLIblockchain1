#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "consensus.h"
#include "pq_crypto.h"
#include "transaction.h"

namespace qtc {
namespace wallet {

// QTC Core's own wallet. This is the shipped path for key generation, address
// derivation and signing; the external QTC-Wallet is a cross-check reference.
//
// The derivation below is frozen in docs/DAY5.md sections 4 and 7. The same
// seed must produce the same keys and address here as in the reference wallet,
// which tests/pq_wallet_parity enforces.
class Wallet {
public:
    // Builds every key from a master seed. Rejects an empty seed.
    static Wallet from_seed(const std::vector<uint8_t>& master_seed,
                            Network network = Network::MAINNET);

    // Generates a fresh random seed and builds from it.
    static Wallet generate(Network network = Network::MAINNET);

    const std::vector<uint8_t>& master_seed() const { return master_seed_; }
    const std::vector<uint8_t>& ml_dsa_public_key() const { return dsa_public_key_; }
    const std::vector<uint8_t>& ml_dsa_secret_key() const { return dsa_secret_key_; }
    const std::vector<uint8_t>& ml_kem_public_key() const { return kem_public_key_; }
    const std::vector<uint8_t>& ml_kem_secret_key() const { return kem_secret_key_; }

    // v1 address: SHA3-256(SHAKE256(kyber_shared_secret || ml_dsa_pk)), full
    // 32 bytes, bech32m, no version word.
    const std::string& address() const { return address_; }
    const std::vector<uint8_t>& program() const { return program_; }

    const std::string& error() const { return error_; }
    bool valid() const { return error_.empty(); }

    // The locking script that receives funds for this address.
    std::vector<uint8_t> script_pubkey() const;

    // Signs a transaction spending one of this wallet's outputs.
    bool sign(Transaction& tx, size_t input_index,
              const std::vector<uint8_t>& prev_script, uint64_t prev_amount) const;

private:
    Network network_ = Network::MAINNET;
    std::vector<uint8_t> master_seed_;
    std::vector<uint8_t> dsa_public_key_, dsa_secret_key_;
    std::vector<uint8_t> kem_public_key_, kem_secret_key_;
    std::vector<uint8_t> program_;
    std::string address_;
    std::string error_;
};

// On-disk wallet file. Rejects malformed or truncated input rather than
// loading a partial wallet, and never persists the KEM shared secret.
struct WalletFile {
    std::vector<uint8_t> master_seed;
    std::string address;
    std::vector<uint8_t> ml_dsa_public_key;
    std::vector<uint8_t> ml_dsa_secret_key;
    std::vector<uint8_t> ml_kem_public_key;
    std::vector<uint8_t> ml_kem_secret_key;

    std::string serialize() const;
    static bool deserialize(const std::string& text, WalletFile& out,
                            std::string* error_out = nullptr);

    bool save(const std::string& path, std::string* error_out = nullptr) const;
    static bool load(const std::string& path, WalletFile& out,
                     std::string* error_out = nullptr);
};

// Rebuilds a Wallet from a stored file, re-deriving the address so a tampered
// file is caught rather than trusted.
bool wallet_from_file(const WalletFile& file, Wallet& out);

} // namespace wallet
} // namespace qtc