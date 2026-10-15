cmake_minimum_required(VERSION 3.10)
project(qtc-protocol VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Warning flags
add_compile_options(-Wall -Wextra -Wpedantic)

# --- PQClean FIPS-202 (SHA3-256 / SHAKE256), from the C reference qtc-core owns ---
set(PQ_REF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/qtc-core/pq/Dilithium C lang/Dilithium C/ref"
    CACHE PATH "Directory holding the fips202 implementation")

if(NOT EXISTS "${PQ_REF_DIR}/fips202.c")
    message(FATAL_ERROR "fips202.c not found in PQ_REF_DIR='${PQ_REF_DIR}'")
endif()

# --- liboqs (ML-DSA-65 / ML-KEM-1024) ---
find_path(OQS_INCLUDE_DIR oqs/oqs.h HINTS /usr/local/include /usr/include)
find_library(OQS_LIBRARY NAMES oqs HINTS /usr/local/lib /usr/lib)

if(NOT OQS_INCLUDE_DIR OR NOT OQS_LIBRARY)
    message(FATAL_ERROR "liboqs not found. Set OQS_INCLUDE_DIR and OQS_LIBRARY.")
endif()

# --- qtc binary ---
add_executable(qtc
    src/main.cpp
    src/consensus.cpp
    src/crypto.cpp
    src/pq_crypto.cpp
    src/transaction.cpp
    src/block.cpp
    src/utxo.cpp
    src/mining.cpp
    src/chain.cpp
    src/mempool.cpp
    src/json.cpp
    src/rpc.cpp
    qtc-core/wallet/wallet.cpp
    "${PQ_REF_DIR}/fips202.c"
)

target_include_directories(qtc PRIVATE include qtc-core "${PQ_REF_DIR}" "${OQS_INCLUDE_DIR}")
target_link_libraries(qtc PRIVATE "${OQS_LIBRARY}")

# Install (optional)
install(TARGETS qtc DESTINATION bin)