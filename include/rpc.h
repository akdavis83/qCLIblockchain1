#pragma once

#include <string>
#include <vector>

#include "chain.h"
#include "mempool.h"

namespace qtc {
namespace rpc {

// Everything a node serves. The mempool lives here rather than in Chain so the
// confirmed set and the pending set can never be confused.
struct Context {
    Chain chain;
    Mempool mempool;
    std::string datadir = "data";

    void load_or_init();
    void persist() const;
    void load_mempool();
    void save_mempool() const;
};

// JSON-RPC error codes used by this server.
constexpr int kParseError = -32700;
constexpr int kInvalidRequest = -32600;
constexpr int kMethodNotFound = -32601;
constexpr int kInvalidParams = -32602;
constexpr int kInternalError = -32603;
constexpr int kApplicationError = -32000;  // rejected by consensus rules

// Handles one JSON-RPC request body and returns the response body. Kept free of
// sockets so it can be exercised directly by the test suite.
std::string handle(Context& context, const std::string& request_body);

// Client helper used by the CLI and by the wallet bridge.
std::string call(const std::string& host, uint16_t port,
                 const std::string& method, const std::string& params_json);

// Runs the HTTP server loop until the process is stopped.
int serve(Context& context, uint16_t port);

} // namespace rpc
} // namespace qtc