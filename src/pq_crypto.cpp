#include "pq_crypto.h"
#include "crypto.h"

#include <oqs/oqs.h>
#include <oqs/kem.h>

#include <algorithm>
#include <cstring>

namespace qtc {
namespace pq {
namespace {

// Domain separation tags. Core and QTC-Wallet must agree on these byte for
// byte or they will derive different keypairs from the same seed.
const std::vector<uint8_t> kDrbgPrefix = {'o', 'q', 's', '_', 'w', 'a', 'l', 'l',
                                          'e', 't', '_', 'c', 'l', 'i'};
const std::vector<uint8_t> kKeygenDomain = {'m', 'l', 'd', 's', 'a', '6', '5',
                                           '_', 'k', 'e', 'y', 'g', 'e', 'n'};
const std::vector<uint8_t> kKemKeygenDomain = {'k', 'y', 'b', 'e', 'r', '_',
                                              'k', 'e', 'y', 'g', 'e', 'n'};
const std::vector<uint8_t> kKemSelfDomain = {'k', 'y', 'b', 'e', 'r', '_',
                                            'k', 'e', 'm', '_', 's', 'e', 'l', 'f'};

constexpr size_t kDrbgSeedSize = 48;
constexpr size_t kDrbgBlockSize = 64;

const uint32_t kBech32Generators[5] = {0x3B6A57B2, 0x26508E6D, 0x1EA119FA,
                                        0x3D4233DD, 0x2A1462B3};
constexpr uint32_t kBech32mConstant = 0x2BC830A3;

// OQS_randombytes_custom_algorithm takes a bare function pointer with no
// user-data argument, so the stream state has to live here.
std::vector<uint8_t> g_drbg_seed;
std::vector<uint8_t> g_drbg_block;
uint64_t g_drbg_counter = 0;
size_t g_drbg_pos = 0;

void deterministic_randombytes(uint8_t* out, size_t outlen) {
    while (outlen > 0) {
        if (g_drbg_pos == g_drbg_block.size()) {
            std::vector<uint8_t> counter;
            auto c = crypto::write_le_u64(g_drbg_counter++);
            counter.assign(c.begin(), c.end());
            g_drbg_block = crypto::shake256_expand(kDrbgBlockSize,
                                                    {g_drbg_seed, counter});
            g_drbg_pos = 0;
        }
        size_t take = std::min(outlen, g_drbg_block.size() - g_drbg_pos);
        std::memcpy(out, g_drbg_block.data() + g_drbg_pos, take);
        out += take;
        outlen -= take;
        g_drbg_pos += take;
    }
}

void drbg_start(const std::vector<uint8_t>& seed) {
    g_drbg_seed = seed;
    g_drbg_counter = 0;
    g_drbg_block.clear();
    g_drbg_pos = 0;
    OQS_randombytes_custom_algorithm(deterministic_randombytes);
}

void drbg_stop() {
    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    g_drbg_seed.clear();
    g_drbg_block.clear();
    g_drbg_pos = 0;
}

OQS_KEM* mlkem1024() {
    static OQS_KEM* instance = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    return instance;
}

OQS_SIG* mldsa65() {
    static OQS_SIG* instance = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    return instance;
}

void set_error(std::string* sink, const std::string& message) {
    if (sink) *sink = message;
}

} // namespace

bool linked_sizes_match(std::string* error_out) {
    OQS_SIG* sig = mldsa65();
    if (!sig) {
        set_error(error_out, "liboqs does not provide ML-DSA-65");
        return false;
    }
    if (sig->length_public_key != ML_DSA_65_PUBLIC_KEY_SIZE ||
        sig->length_secret_key != ML_DSA_65_SECRET_KEY_SIZE ||
        sig->length_signature != ML_DSA_65_SIGNATURE_SIZE) {
        set_error(error_out,
                  "liboqs ML-DSA-65 sizes disagree with pq_crypto.h: got " +
                      std::to_string(sig->length_public_key) + "/" +
                      std::to_string(sig->length_secret_key) + "/" +
                      std::to_string(sig->length_signature) + ", expected " +
                      std::to_string(ML_DSA_65_PUBLIC_KEY_SIZE) + "/" +
                      std::to_string(ML_DSA_65_SECRET_KEY_SIZE) + "/" +
                      std::to_string(ML_DSA_65_SIGNATURE_SIZE));
        return false;
    }
    return true;
}

KeyPair generate_mldsa65_keypair(const std::vector<uint8_t>& seed) {
    KeyPair result;

    OQS_SIG* sig = mldsa65();
    if (!sig) {
        result.error = "liboqs does not provide ML-DSA-65";
        return result;
    }
    if (seed.empty()) {
        result.error = "seed must not be empty";
        return result;
    }

    auto drbg_seed = crypto::shake256_expand(kDrbgSeedSize,
                                             {kDrbgPrefix, kKeygenDomain, seed});

    drbg_start(drbg_seed);
    result.public_key.resize(sig->length_public_key);
    result.secret_key.resize(sig->length_secret_key);
    OQS_STATUS status = OQS_SIG_keypair(sig, result.public_key.data(),
                                        result.secret_key.data());
    drbg_stop();

    if (status != OQS_SUCCESS) {
        result.public_key.clear();
        result.secret_key.clear();
        result.error = "OQS_SIG_keypair failed";
    }
    return result;
}

std::vector<uint8_t> sign_mldsa65(const std::vector<uint8_t>& secret_key,
                                  const std::vector<uint8_t>& message,
                                  std::string* error_out) {
    OQS_SIG* sig = mldsa65();
    if (!sig) {
        set_error(error_out, "liboqs does not provide ML-DSA-65");
        return {};
    }
    if (secret_key.size() != sig->length_secret_key) {
        set_error(error_out,
                  "secret key is " + std::to_string(secret_key.size()) +
                      " bytes, expected " + std::to_string(sig->length_secret_key));
        return {};
    }

    std::vector<uint8_t> signature(sig->length_signature);
    size_t signature_len = 0;
    if (OQS_SIG_sign(sig, signature.data(), &signature_len, message.data(),
                     message.size(), secret_key.data()) != OQS_SUCCESS) {
        set_error(error_out, "OQS_SIG_sign failed");
        return {};
    }
    signature.resize(signature_len);
    return signature;
}

KeyPair generate_mlkem1024_keypair(const std::vector<uint8_t>& seed) {
    KeyPair result;

    OQS_KEM* kem = mlkem1024();
    if (!kem) {
        result.error = "liboqs does not provide ML-KEM-1024";
        return result;
    }
    if (seed.empty()) {
        result.error = "seed must not be empty";
        return result;
    }

    auto drbg_seed = crypto::shake256_expand(kDrbgSeedSize,
                                             {kDrbgPrefix, kKemKeygenDomain, seed});
    drbg_start(drbg_seed);
    result.public_key.resize(kem->length_public_key);
    result.secret_key.resize(kem->length_secret_key);
    OQS_STATUS status = OQS_KEM_keypair(kem, result.public_key.data(),
                                         result.secret_key.data());
    drbg_stop();

    if (status != OQS_SUCCESS) {
        result.public_key.clear();
        result.secret_key.clear();
        result.error = "OQS_KEM_keypair failed";
    }
    return result;
}

KemResult kem_self_from_seed(const std::vector<uint8_t>& seed) {
    KemResult result;

    OQS_KEM* kem = mlkem1024();
    if (!kem) {
        result.error = "liboqs does not provide ML-KEM-1024";
        return result;
    }
    if (seed.empty()) {
        result.error = "seed must not be empty";
        return result;
    }

    auto drbg_seed = crypto::shake256_expand(kDrbgSeedSize,
                                             {kDrbgPrefix, kKemSelfDomain, seed});
    drbg_start(drbg_seed);
    result.public_key.resize(kem->length_public_key);
    result.secret_key.resize(kem->length_secret_key);
    result.shared_secret.resize(kem->length_shared_secret);

    OQS_STATUS status = OQS_KEM_keypair(kem, result.public_key.data(),
                                        result.secret_key.data());
    if (status == OQS_SUCCESS) {
        result.ciphertext.resize(kem->length_ciphertext);
        // Argument order is (ciphertext, shared_secret, public_key).
        status = OQS_KEM_encaps(kem, result.ciphertext.data(),
                                result.shared_secret.data(),
                                result.public_key.data());
    }
    drbg_stop();

    if (status != OQS_SUCCESS) {
        result.error = "OQS_KEM_keypair or OQS_KEM_encaps failed";
    }
    return result;
}

std::string encode_address(const std::vector<uint8_t>& program, Network network) {
    static const std::string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const std::string hrp = (network == Network::TESTNET) ? HRP_TESTNET : HRP_MAINNET;

    std::vector<uint8_t> words;
    uint32_t accumulator = 0;
    int bits = 0;
    for (uint8_t byte : program) {
        accumulator = (accumulator << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            words.push_back(static_cast<uint8_t>((accumulator >> bits) & 31));
        }
    }
    if (bits) words.push_back(static_cast<uint8_t>((accumulator << (5 - bits)) & 31));

    std::vector<uint8_t> checked;
    for (char c : hrp) checked.push_back(static_cast<uint8_t>(c) >> 5);
    checked.push_back(0);
    for (char c : hrp) checked.push_back(static_cast<uint8_t>(c) & 31);
    checked.insert(checked.end(), words.begin(), words.end());
    checked.insert(checked.end(), 6, 0);

    uint32_t checksum = 1;
    for (uint8_t value : checked) {
        const uint32_t top = checksum >> 25;
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) checksum ^= kBech32Generators[i];
        }
    }
    const uint32_t mod = (checksum ^ kBech32mConstant) & 0xFFFFFFFF;

    std::string out = hrp + "1";
    for (uint8_t word : words) out += charset[word];
    for (int i = 0; i < 6; ++i) {
        out += charset[(mod >> (5 * (5 - i))) & 31];
    }
    return out;
}

DecodedAddress decode_address(const std::string& address) {
    DecodedAddress result;

    const size_t separator = address.rfind('1');
    if (separator == std::string::npos || separator == 0 ||
        separator + 7 > address.size()) {
        result.error = "address has no valid bech32 separator";
        return result;
    }

    const std::string hrp = address.substr(0, separator);
    if (hrp == HRP_MAINNET) {
        result.network = Network::MAINNET;
    } else if (hrp == HRP_TESTNET) {
        result.network = Network::TESTNET;
    } else {
        result.error = "unknown human-readable part '" + hrp + "'";
        return result;
    }

    static const std::string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    std::vector<uint8_t> words;
    for (size_t i = separator + 1; i < address.size(); ++i) {
        const size_t pos = charset.find(address[i]);
        if (pos == std::string::npos || address[i] > 127) {
            result.error = "address contains a character outside the bech32 charset";
            return result;
        }
        words.push_back(static_cast<uint8_t>(pos));
    }
    if (words.size() < 7) {
        result.error = "address is too short to carry a checksum";
        return result;
    }

    std::vector<uint8_t> checked;
    for (char c : hrp) checked.push_back(static_cast<uint8_t>(c) >> 5);
    checked.push_back(0);
    for (char c : hrp) checked.push_back(static_cast<uint8_t>(c) & 31);
    checked.insert(checked.end(), words.begin(), words.end());

    uint32_t checksum = 1;
    for (uint8_t value : checked) {
        const uint32_t top = checksum >> 25;
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) checksum ^= kBech32Generators[i];
        }
    }

    if (checksum == 1) {
        result.error =
            "address uses the bech32 (BIP-173) checksum; QTC requires bech32m "
            "because it has no witness v0";
        return result;
    }
    if (checksum != kBech32mConstant) {
        result.error = "address checksum is invalid";
        return result;
    }
    result.bech32m = true;

    // v1 carries the hash directly, with no version word.
    std::vector<uint8_t> payload(words.begin(), words.end() - 6);
    for (uint8_t word : payload) {
        if (word >> 5) {
            result.error = "address has a malformed program";
            return result;
        }
    }

    uint32_t accumulator = 0;
    int bits = 0;
    for (uint8_t word : payload) {
        accumulator = (accumulator << 5) | word;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            result.program.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xFF));
        }
    }
    if (bits >= 5 || (accumulator << (8 - bits)) & 0xFF) {
        result.error = "address has a malformed program";
        return result;
    }
    if (result.program.size() != WITNESS_PROGRAM_SIZE) {
        result.error = "address program is " + std::to_string(result.program.size()) +
                       " bytes, expected " + std::to_string(WITNESS_PROGRAM_SIZE);
        return result;
    }

    result.witness_version = 0;
    result.valid = true;
    return result;
}

SignatureResult verify_mldsa65(const std::vector<uint8_t>& public_key,
                               const std::vector<uint8_t>& message,
                               const std::vector<uint8_t>& signature) {
    SignatureResult result;

    OQS_SIG* sig = mldsa65();
    if (!sig) {
        result.error = "liboqs does not provide ML-DSA-65";
        return result;
    }
    if (public_key.size() != sig->length_public_key) {
        result.error = "public key is " + std::to_string(public_key.size()) +
                       " bytes, expected " +
                       std::to_string(sig->length_public_key);
        return result;
    }
    if (signature.empty() || signature.size() > sig->length_signature) {
        result.error = "signature length " + std::to_string(signature.size()) +
                       " out of range";
        return result;
    }

    result.valid = OQS_SIG_verify(sig, message.data(), message.size(),
                                  signature.data(), signature.size(),
                                  public_key.data()) == OQS_SUCCESS;
    if (!result.valid && result.error.empty()) {
        result.error = "signature does not verify against this key and message";
    }
    return result;
}

} // namespace pq
} // namespace qtc