#include "chain.h"

#include <cstdio>
#include <cstdlib>
#include <iterator>
#include "crypto.h"
#include "consensus.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace qtc {

Chain::Chain() : network_(Network::REGTEST), initialized_(false) {}

void Chain::init(Network network) {
    if (initialized_) return;
    
    network_ = network;
    
    Block genesis;
    switch (network) {
        case Network::REGTEST:
            genesis = Block::create_regtest_genesis();
            break;
        default:
            genesis = Block::create_regtest_genesis();
            break;
    }
    
    blocks_.clear();
    blocks_.push_back(genesis);
    
    // Rebuild UTXO set from chain
    utxo_set_.rebuild_from_blocks(blocks_);
    
    initialized_ = true;
}

Chain::BlockchainInfo Chain::get_blockchain_info() const {
    BlockchainInfo info;
    info.network = network_;
    info.height = static_cast<uint32_t>(blocks_.size()) - 1;
    info.best_block_hash = blocks_.empty() ? "" : blocks_.back().header.hash_hex();
    info.difficulty_bits = blocks_.empty() ? 0 : blocks_.back().header.difficulty_bits;
    info.chain_work = 0;
    info.initialized = initialized_;
    return info;
}

const Block& Chain::get_block(uint32_t height) const {
    if (height >= blocks_.size()) {
        throw std::out_of_range("Block height " + std::to_string(height) + " out of range");
    }
    return blocks_[height];
}

const Block& Chain::get_genesis() const {
    if (blocks_.empty()) {
        throw std::runtime_error("Chain not initialized");
    }
    return blocks_[0];
}

const Block& Chain::tip() const {
    if (blocks_.empty()) {
        throw std::runtime_error("Chain not initialized");
    }
    return blocks_.back();
}

uint32_t Chain::height() const {
    if (blocks_.empty()) return 0;
    return static_cast<uint32_t>(blocks_.size()) - 1;
}

const std::vector<Block>& Chain::blocks() const {
    return blocks_;
}

bool Chain::add_block(const Block& block) {
    if (blocks_.empty()) {
        return false;
    }
    
    // Reject empty blocks
    if (block.transactions.empty()) {
        std::cerr << "Block rejected: no transactions\n";
        return false;
    }
    
    // Validate: previous hash must match current tip
    const auto& tip = blocks_.back();
    auto tip_hash = tip.header.hash();
    
    if (block.header.prev_block_hash.size() != 32 || tip_hash.size() != 32) {
        return false;
    }
    for (size_t i = 0; i < 32; ++i) {
        if (block.header.prev_block_hash[i] != tip_hash[i]) {
            std::cerr << "Block rejected: previous hash mismatch\n";
            return false;
        }
    }
    
    // Check merkle root
    auto computed_root = block.compute_merkle_root();
    if (computed_root.size() != 32 || block.header.merkle_root.size() != 32) {
        return false;
    }
    for (size_t i = 0; i < 32; ++i) {
        if (block.header.merkle_root[i] != computed_root[i]) {
            std::cerr << "Block rejected: merkle root mismatch\n";
            return false;
        }
    }
    
// Check PoW
    if (!block.validate_pow()) {
        std::cerr << "Block rejected: PoW invalid\n";
        return false;
    }

    // Enforce the block size limit. With a full ML-DSA-65 witness on every
    // transaction this is the only guard against unbounded blocks.
    const size_t block_size = block.serialize().size();
    if (block_size > MAX_BLOCK_SIZE) {
        std::cerr << "Block rejected: " << block_size << " bytes exceeds the "
                  << MAX_BLOCK_SIZE << " byte limit\n";
        return false;
    }
    
    // Validate all transactions in the block against a candidate UTXO set
    // We apply sequentially to catch block-level double spends
    uint32_t new_height = static_cast<uint32_t>(blocks_.size());
    UTXOSet candidate = utxo_set_;
    
    for (size_t i = 0; i < block.transactions.size(); ++i) {
        const auto& tx = block.transactions[i];
        
        // Enforce coinbase position: first tx must be coinbase, no others
        if (i == 0 && !tx.is_coinbase()) {
            std::cerr << "Block rejected: first transaction is not a coinbase\n";
            return false;
        }
        if (i > 0 && tx.is_coinbase()) {
            std::cerr << "Block rejected: coinbase in position " << i << "\n";
            return false;
        }
        
        // Check coinbase subsidy does not exceed allowed amount
        if (tx.is_coinbase() && !tx.outputs.empty()) {
            uint64_t subsidy = get_block_subsidy(new_height);
            uint64_t coinbase_output = tx.total_output();
            if (coinbase_output > subsidy) {
                std::cerr << "Block rejected: coinbase output (" << coinbase_output
                          << ") exceeds subsidy (" << subsidy << ")\n";
                return false;
            }
        }
        
        std::string error;
        if (!candidate.apply_transaction(tx, new_height, error)) {
            std::cerr << "Block rejected: transaction validation failed: " << error << "\n";
            return false;
        }
    }
    
    // Commit the candidate UTXO set
    utxo_set_ = std::move(candidate);
    
    blocks_.push_back(block);
    return true;
}

bool Chain::validate_chain() const {
    if (blocks_.empty()) return false;
    
    // Validate genesis PoW
    if (!blocks_[0].validate_pow()) {
        std::cerr << "Genesis block PoW invalid" << std::endl;
        return false;
    }
    
    // Walk the chain, rebuilding a candidate UTXO set
    UTXOSet utxos;
    
    for (size_t i = 0; i < blocks_.size(); ++i) {
        const auto& curr = blocks_[i];
        uint32_t block_height = static_cast<uint32_t>(i);
        
        // Reject empty blocks
        if (curr.transactions.empty()) {
            std::cerr << "Block " << i << ": no transactions" << std::endl;
            return false;
        }
        
        // Validate PoW for all blocks
        if (!curr.validate_pow()) {
            std::cerr << "Block " << i << ": PoW invalid" << std::endl;
            return false;
        }
        
        // Validate block linkage (skip genesis)
        if (i > 0) {
            const auto& prev = blocks_[i - 1];
            auto prev_hash = prev.header.hash();
            for (size_t j = 0; j < 32 && j < curr.header.prev_block_hash.size(); ++j) {
                if (curr.header.prev_block_hash[j] != prev_hash[j]) {
                    std::cerr << "Block " << i << ": previous hash mismatch" << std::endl;
                    return false;
                }
            }
        }
        
        // Validate merkle root
        auto computed_root = curr.compute_merkle_root();
        for (size_t j = 0; j < 32 && j < curr.header.merkle_root.size(); ++j) {
            if (curr.header.merkle_root[j] != computed_root[j]) {
                std::cerr << "Block " << i << ": merkle root mismatch" << std::endl;
                return false;
            }
        }
        
        // Validate transactions in this block
        for (size_t tx_i = 0; tx_i < curr.transactions.size(); ++tx_i) {
            const auto& tx = curr.transactions[tx_i];
            
            // Enforce coinbase position
            if (tx_i == 0 && !tx.is_coinbase()) {
                std::cerr << "Block " << i << ": first tx is not coinbase" << std::endl;
                return false;
            }
            if (tx_i > 0 && tx.is_coinbase()) {
                std::cerr << "Block " << i << ": coinbase in position " << tx_i << std::endl;
                return false;
            }
            
            // Check coinbase subsidy
            if (tx.is_coinbase() && !tx.outputs.empty()) {
                uint64_t subsidy = get_block_subsidy(block_height);
                uint64_t coinbase_output = tx.total_output();
                if (coinbase_output > subsidy) {
                    std::cerr << "Block " << i << ": coinbase output (" << coinbase_output
                              << ") exceeds subsidy (" << subsidy << ")" << std::endl;
                    return false;
                }
            }
            
            // Validate against candidate UTXO set
            std::string error;
            if (!utxos.validate_transaction(tx, error)) {
                std::cerr << "Block " << i << " tx " << tx_i << ": " << error << std::endl;
                return false;
            }
            
            // Apply transaction to candidate UTXO set
            if (!utxos.apply_transaction(tx, block_height, error)) {
                std::cerr << "Block " << i << " tx " << tx_i << ": apply failed: " << error << std::endl;
                return false;
            }
        }
    }
    
    return true;
}

UTXOSet& Chain::utxo_set() {
    return utxo_set_;
}

const UTXOSet& Chain::utxo_set() const {
    return utxo_set_;
}

std::string Chain::block_path(const std::string& datadir, uint32_t height) {
    char name[32];
    std::snprintf(name, sizeof(name), "blocks/%08u.dat", height);
    return datadir + "/" + name;
}

bool Chain::has_saved_state(const std::string& datadir) {
    std::ifstream in(datadir + "/chainstate");
    return static_cast<bool>(in);
}

bool Chain::save(const std::string& datadir) const {
    if (blocks_.empty()) return false;

    std::string mkdir_cmd = "mkdir -p '" + datadir + "/blocks'";
    if (std::system(mkdir_cmd.c_str()) != 0) return false;

    for (size_t i = 0; i < blocks_.size(); ++i) {
        const auto bytes = blocks_[i].serialize();
        std::ofstream out(block_path(datadir, static_cast<uint32_t>(i)),
                          std::ios::binary);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        if (!out) return false;
    }

    std::ofstream state(datadir + "/chainstate");
    if (!state) return false;
    state << "network=" << static_cast<int>(network_) << "\n";
    state << "height=" << (blocks_.size() - 1) << "\n";
    state << "tip=" << blocks_.back().header.hash_hex() << "\n";
    state << "difficulty_bits=" << blocks_.back().header.difficulty_bits << "\n";
    return true;
}

bool Chain::load(const std::string& datadir) {
    std::ifstream state(datadir + "/chainstate");
    if (!state) return false;

    uint32_t stored_network = 0;
    uint32_t stored_height = 0;
    std::string stored_tip;
    std::string line;
    while (std::getline(state, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        const std::string value = line.substr(eq + 1);
        if (key == "network") stored_network = std::stoul(value);
        else if (key == "height") stored_height = std::stoul(value);
        else if (key == "tip") stored_tip = value;
    }

    if (static_cast<Network>(stored_network) != network_) {
        std::cerr << "Chain state network does not match the requested network\n";
        return false;
    }
    if (blocks_.size() > 1) {
        std::cerr << "Chain already holds blocks; refusing to load over them\n";
        return false;
    }

    std::vector<Block> loaded;
    loaded.reserve(static_cast<size_t>(stored_height) + 1);

    for (uint32_t i = 0; i <= stored_height; ++i) {
        std::ifstream in(block_path(datadir, i), std::ios::binary);
        if (!in) {
            std::cerr << "Missing block file for height " << i << "\n";
            return false;
        }
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());
        try {
            loaded.push_back(Block::deserialize(bytes));
        } catch (const std::exception& e) {
            std::cerr << "Block " << i << " failed to deserialize: " << e.what() << "\n";
            return false;
        }
    }

    if (loaded.empty()) {
        std::cerr << "Chain state contains no blocks\n";
        return false;
    }
    if (loaded.front().header.hash_hex() !=
        Block::create_regtest_genesis().header.hash_hex()) {
        std::cerr << "Stored genesis does not match this network's genesis\n";
        return false;
    }
    if (!stored_tip.empty() && loaded.back().header.hash_hex() != stored_tip) {
        std::cerr << "Stored tip hash does not match the last block\n";
        return false;
    }

    // Re-verify rather than trusting the files, then rebuild the UTXO set.
    for (size_t i = 1; i < loaded.size(); ++i) {
        if (loaded[i].header.prev_block_hash != loaded[i - 1].header.hash()) {
            std::cerr << "Block " << i << " does not link to its predecessor\n";
            return false;
        }
        if (!loaded[i].validate_pow()) {
            std::cerr << "Block " << i << " has invalid proof of work\n";
            return false;
        }
        if (loaded[i].header.merkle_root != loaded[i].compute_merkle_root()) {
            std::cerr << "Block " << i << " merkle root mismatch\n";
            return false;
        }
    }

    blocks_ = std::move(loaded);
    utxo_set_.clear();
    for (size_t i = 0; i < blocks_.size(); ++i) {
        utxo_set_.connect_block(blocks_[i].transactions, static_cast<uint32_t>(i));
    }
    initialized_ = true;
    return true;
}

} // namespace qtc
