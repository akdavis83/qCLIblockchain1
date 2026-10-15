# QTC Protocol Makefile
# For systems without CMake, or as a quick build alternative

CXX = g++
CC = gcc
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2 -Iinclude -Iqtc-core
CFLAGS = -O2 -Wall -Wextra

# PQClean FIPS-202 (SHA3-256 / SHAKE256), read from the Dilithium C reference
# implementation that qtc-core owns. Spaces are backslash-escaped so the path
# survives both recipes and prerequisites.
PQ_REF_DIR ?= qtc-core/pq/Dilithium\ C\ lang/Dilithium\ C/ref

SRCS = src/consensus.cpp src/crypto.cpp src/pq_crypto.cpp src/transaction.cpp src/block.cpp src/utxo.cpp src/mining.cpp src/chain.cpp src/main.cpp src/mempool.cpp src/json.cpp src/rpc.cpp qtc-core/wallet/wallet.cpp
OBJS = $(SRCS:.cpp=.o)
VENDOR_OBJS = build/pq_fips202.o
TARGET = qtc

.PHONY: all clean run selftest

all: $(TARGET)

$(TARGET): $(OBJS) $(VENDOR_OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(VENDOR_OBJS) -loqs

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I$(PQ_REF_DIR) -c $< -o $@

build:
	mkdir -p build

build/pq_fips202.o: $(PQ_REF_DIR)/fips202.c | build
	$(CC) $(CFLAGS) -I$(PQ_REF_DIR) -c "$<" -o $@

run: $(TARGET)
	./$(TARGET) init

selftest: $(TARGET)
	./$(TARGET) selftest

clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf build
