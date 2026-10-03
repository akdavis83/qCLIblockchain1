#include "consensus.h"

namespace qtc {

uint64_t get_block_subsidy(uint32_t height) {
    uint64_t subsidy = INITIAL_SUBSIDY;
    uint32_t halvings = height / HALVING_INTERVAL;
    
    // If we've halved enough times, subsidy is 0
    if (halvings >= 64) {
        return 0;
    }
    
    // Right-shift subsidy by halving count
    subsidy >>= halvings;
    
    return subsidy;
}

} // namespace qtc
