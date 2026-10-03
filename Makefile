# QTC Protocol Makefile
# For systems without CMake, or as a quick build alternative

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2 -Iinclude

SRCS = src/consensus.cpp src/crypto.cpp src/transaction.cpp src/block.cpp src/utxo.cpp src/mining.cpp src/chain.cpp src/main.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = qtc

.PHONY: all clean run selftest

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) init

selftest: $(TARGET)
	./$(TARGET) selftest

clean:
	rm -f $(OBJS) $(TARGET)
