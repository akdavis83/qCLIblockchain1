cmake_minimum_required(VERSION 3.10)
project(qtc-protocol VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Warning flags
add_compile_options(-Wall -Wextra -Wpedantic)

# --- qtc binary ---
add_executable(qtc
    src/main.cpp
    src/consensus.cpp
    src/crypto.cpp
    src/transaction.cpp
    src/block.cpp
    src/utxo.cpp
    src/mining.cpp
    src/chain.cpp
)

target_include_directories(qtc PRIVATE include)

# Install (optional)
install(TARGETS qtc DESTINATION bin)
