#include "rpc.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

#include "crypto.h"
#include "json.h"
#include "mining.h"
#include "transaction.h"

namespace qtc {
namespace rpc {

namespace {

constexpr size_t kMaxRequestBytes = 1 << 20;

const char* network_label(Network network) {
    switch (network) {
        case Network::MAINNET: return "main";
        case Network::TESTNET: return "test";
        default: return "regtest";
    }
}

json::Value make_error(int code, const std::string& message) {
    json::Value error = json::Value::make_object();
    error.set("code", json::Value::number(code));
    error.set("message", json::Value::string(message));
    return error;
}

std::string envelope(const json::Value& id, json::Value result, json::Value error) {
    json::Value out = json::Value::make_object();
    out.set("jsonrpc", json::Value::string("2.0"));
    out.set("id", id);
    out.set("result", std::move(result));
    out.set("error", std::move(error));
    return out.dump();
}

std::string reply_result(const json::Value& id, json::Value result) {
    return envelope(id, std::move(result), json::Value());
}

std::string reply_error(const json::Value& id, int code, const std::string& message) {
    return envelope(id, json::Value(), make_error(code, message));
}

std::string param_at(const json::Value& params, size_t index) {
    if (!params.is_array() || index >= params.items().size()) return {};
    const auto& value = params.items()[index];
    return value.is_string() ? value.as_string() : std::string();
}

// from_hex throws on a non-hex character, so callers handling untrusted input
// must check the shape first.
bool is_hex(const std::string& text) {
    if (text.empty()) return false;
    for (char c : text) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        const bool upper = c >= 'A' && c <= 'F';
        if (!digit && !lower && !upper) return false;
    }
    return true;
}

uint64_t number_at(const json::Value& params, size_t index, uint64_t fallback) {
    if (!params.is_array() || index >= params.items().size()) return fallback;
    const auto& value = params.items()[index];
    if (value.is_number()) return value.as_uint(fallback);
    // Wallets and shell callers often send numbers as strings. Silently using
    // the fallback here would quietly mine 1 block instead of 101, so accept a
    // numeric string instead of ignoring it.
    if (value.is_string()) {
        const std::string& text = value.as_string();
        if (text.empty() ||
            text.find_first_not_of("0123456789") != std::string::npos) {
            return fallback;
        }
        return std::strtoull(text.c_str(), nullptr, 10);
    }
    return fallback;
}

} // namespace

void Context::load_or_init() {
    if (Chain::has_saved_state(datadir)) {
        if (!chain.load(datadir)) {
            std::cerr << "RPC: refusing to start, chain state failed to load\n";
            std::exit(1);
        }
    } else {
        chain.init(Network::REGTEST);
        chain.save(datadir);
    }
    load_mempool();
}

void Context::persist() const {
    chain.save(datadir);
}

void Context::save_mempool() const {
    std::ofstream out(datadir + "/mempool.bin", std::ios::binary);
    if (!out) return;
    for (const auto& entry : mempool.entries()) {
        const auto bytes = entry.tx.serialize();
        const auto length = static_cast<uint32_t>(bytes.size());
        out.write(reinterpret_cast<const char*>(&length), sizeof(length));
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
}

void Context::load_mempool() {
    mempool.clear();
    std::ifstream in(datadir + "/mempool.bin", std::ios::binary);
    if (!in) return;

    while (true) {
        uint32_t length = 0;
        in.read(reinterpret_cast<char*>(&length), sizeof(length));
        if (in.gcount() != static_cast<std::streamsize>(sizeof(length))) break;
        if (length == 0 || length > kMaxRequestBytes) break;

        std::vector<uint8_t> bytes(length);
        in.read(reinterpret_cast<char*>(bytes.data()), length);
        if (in.gcount() != static_cast<std::streamsize>(length)) break;

        try {
            Transaction tx = Transaction::deserialize(bytes);
            std::string error;
            // Re-validate: a transaction admitted before the restart may no
            // longer be valid against the current confirmed set.
            if (!mempool.admit(chain.utxo_set(), tx, error)) break;
        } catch (const std::exception&) {
            break;
        }
    }
}

std::string handle(Context& context, const std::string& request_body) {
    if (request_body.size() > kMaxRequestBytes) {
        return reply_error(json::Value(), kInvalidRequest, "request body too large");
    }

    json::Value request;
    std::string parse_error;
    if (!json::Value::parse(request_body, request, parse_error)) {
        return reply_error(json::Value(), kParseError, "parse error: " + parse_error);
    }
    if (request.is_array()) {
        return reply_error(json::Value(), kInvalidRequest,
                           "batch requests are not supported");
    }
    if (!request.is_object()) {
        return reply_error(json::Value(), kInvalidRequest,
                           "request must be a JSON object");
    }

    const json::Value id = request["id"];

    if (!request["method"].is_string()) {
        return reply_error(id, kInvalidRequest, "missing or non-string 'method'");
    }
    const std::string method = request["method"].as_string();

    json::Value params;
    if (request.has("params")) {
        params = request["params"];
        if (!params.is_array() && !params.is_object()) {
            return reply_error(id, kInvalidParams,
                               "'params' must be an array or an object");
        }
    }

    Chain& chain = context.chain;
    Mempool& mempool = context.mempool;

    if (method == "getblockchaininfo") {
        const auto info = chain.get_blockchain_info();
        json::Value out = json::Value::make_object();
        out.set("network", json::Value::string(network_label(info.network)));
        out.set("height", json::Value::number(info.height));
        out.set("bestblockhash", json::Value::string(info.best_block_hash));
        out.set("difficultybits", json::Value::number(info.difficulty_bits));
        out.set("mempoolsize", json::Value::number(mempool.size()));
        return reply_result(id, out);
    }

    if (method == "getblockcount") {
        return reply_result(id, json::Value::number(chain.height()));
    }

    if (method == "getbestblockhash") {
        return reply_result(id, json::Value::string(chain.tip().header.hash_hex()));
    }

    if (method == "getblock") {
        const uint64_t height = number_at(params, 0, UINT64_MAX);
        if (height == UINT64_MAX || height > chain.height()) {
            return reply_error(id, kInvalidParams, "block height out of range");
        }
        const Block& block = chain.get_block(static_cast<uint32_t>(height));
        json::Value out = json::Value::make_object();
        out.set("height", json::Value::number(height));
        out.set("hash", json::Value::string(block.header.hash_hex()));
        out.set("merkleroot",
                json::Value::string(crypto::to_hex(block.header.merkle_root)));
        out.set("timestamp", json::Value::number(block.header.timestamp));
        out.set("bits", json::Value::number(block.header.difficulty_bits));
        out.set("nonce", json::Value::number(block.header.nonce));
        out.set("txcount", json::Value::number(block.transactions.size()));
        out.set("size", json::Value::number(block.serialize().size()));
        return reply_result(id, out);
    }

    if (method == "getbalance") {
        const std::string address = param_at(params, 0);
        if (address.empty()) {
            return reply_error(id, kInvalidParams, "getbalance requires an address");
        }
        return reply_result(
            id, json::Value::number(
                    chain.utxo_set().get_balance_for_address(address)));
    }

    if (method == "listunspent") {
        const std::string address = param_at(params, 0);
        std::vector<UTXO> coins;
        if (address.empty()) {
            coins = chain.utxo_set().list_unspent_for_script({});
        } else {
            coins = chain.utxo_set().list_unspent_for_address(address);
        }
        json::Value out = json::Value::make_array();
        for (const auto& utxo : coins) {
            json::Value item = json::Value::make_object();
            item.set("txid", json::Value::string(crypto::to_hex(utxo.outpoint.txid)));
            item.set("vout", json::Value::number(utxo.outpoint.vout));
            item.set("amount", json::Value::number(utxo.amount));
            item.set("height", json::Value::number(utxo.height));
            out.push_back(std::move(item));
        }
        return reply_result(id, out);
    }

    if (method == "getrawmempool") {
        json::Value out = json::Value::make_array();
        for (const auto& tx : mempool.by_fee_rate()) {
            out.push_back(json::Value::string(crypto::to_hex(tx.txid())));
        }
        return reply_result(id, out);
    }

    if (method == "getmempoolinfo") {
        json::Value out = json::Value::make_object();
        out.set("size", json::Value::number(mempool.size()));
        out.set("totalfees", json::Value::number(mempool.total_fees()));
        out.set("averagfeerate", json::Value::number(mempool.average_fee_rate()));
        out.set("minfee", json::Value::number(MIN_TX_FEE));
        out.set("maxmempool", json::Value::number(MEMPOOL_MAX_TRANSACTIONS));
        return reply_result(id, out);
    }

    if (method == "sendrawtransaction") {
        const std::string hex = param_at(params, 0);
        if (hex.empty()) {
            return reply_error(id, kInvalidParams,
                               "sendrawtransaction requires a transaction hex");
        }
        if (!is_hex(hex)) {
            return reply_error(id, kInvalidParams, "transaction hex is malformed");
        }
        const auto bytes = crypto::from_hex(hex);
        if (bytes.empty()) {
            return reply_error(id, kInvalidParams, "transaction hex is empty");
        }

        Transaction tx;
        try {
            tx = Transaction::deserialize(bytes);
        } catch (const std::exception& e) {
            return reply_error(id, kApplicationError,
                               std::string("transaction does not deserialize: ") +
                                   e.what());
        }

        std::string error;
        if (!mempool.admit(chain.utxo_set(), tx, error)) {
            return reply_error(id, kApplicationError, error);
        }
        context.save_mempool();
        return reply_result(id, json::Value::string(crypto::to_hex(tx.txid())));
    }

    if (method == "generate") {
        const uint64_t count = number_at(params, 0, 1);
        std::string address = param_at(params, 1);
        if (address.empty()) address = "Miner";
        if (count < 1 || count > 1000) {
            return reply_error(id, kInvalidParams,
                               "generate count must be between 1 and 1000");
        }

        const std::vector<Transaction> pending = mempool.by_fee_rate();
        json::Value hashes = json::Value::make_array();
        for (uint64_t i = 0; i < count; ++i) {
            Block block = create_block_template(chain, address, pending);
            auto mined = mine_block(block);
            if (!mined.found || !chain.add_block(block)) {
                return reply_error(id, kInternalError,
                                   "failed to mine or add a block at height " +
                                       std::to_string(chain.height()));
            }
            mempool.remove_confirmed(block.transactions, chain.utxo_set());
            hashes.push_back(json::Value::string(block.header.hash_hex()));
        }
        context.persist();
        context.save_mempool();
        return reply_result(id, hashes);
    }

    if (method == "submitblock") {
        const std::string hex = param_at(params, 0);
        if (!is_hex(hex)) {
            return reply_error(id, kInvalidParams, "block hex is malformed");
        }
        const auto bytes = crypto::from_hex(hex);
        if (bytes.empty()) {
            return reply_error(id, kInvalidParams, "block hex is empty");
        }
        Block block;
        try {
            block = Block::deserialize(bytes);
        } catch (const std::exception& e) {
            return reply_error(id, kApplicationError,
                               std::string("block does not deserialize: ") + e.what());
        }
        if (!chain.add_block(block)) {
            return reply_error(id, kApplicationError, "block rejected by consensus");
        }
        mempool.remove_confirmed(block.transactions, chain.utxo_set());
        context.persist();
        context.save_mempool();
        return reply_result(id, json::Value::string(block.header.hash_hex()));
    }

    if (method == "stop") {
        context.persist();
        context.save_mempool();
        return reply_result(id, json::Value::string("QTC Core stopping"));
    }

    return reply_error(id, kMethodNotFound, "method not found: " + method);
}

namespace {

std::string http_response(const std::string& body) {
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: application/json\r\n"
           "Content-Length: " + std::to_string(body.size()) + "\r\n"
           "Connection: close\r\n"
           "\r\n" + body;
}

bool read_request(int fd, std::string& body) {
    std::string data;
    char buffer[4096];
    size_t header_end = std::string::npos;

    while (data.size() < kMaxRequestBytes) {
        const ssize_t got = ::recv(fd, buffer, sizeof(buffer), 0);
        if (got <= 0) break;
        data.append(buffer, static_cast<size_t>(got));
        header_end = data.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
    }
    if (header_end == std::string::npos) return false;

    size_t content_length = 0;
    const std::string headers = data.substr(0, header_end);
    const size_t marker = headers.find("Content-Length:");
    if (marker != std::string::npos) {
        content_length = static_cast<size_t>(
            std::strtoul(headers.c_str() + marker + 15, nullptr, 10));
    }
    if (content_length > kMaxRequestBytes) return false;

    while (data.size() < header_end + 4 + content_length) {
        const ssize_t got = ::recv(fd, buffer, sizeof(buffer), 0);
        if (got <= 0) break;
        data.append(buffer, static_cast<size_t>(got));
    }
    body = data.substr(header_end + 4, content_length);
    return true;
}

bool is_stop_reply(const std::string& response) {
    json::Value parsed;
    std::string ignored;
    if (!json::Value::parse(response, parsed, ignored)) return false;
    const auto& result = parsed["result"];
    return result.is_string() && result.as_string() == "QTC Core stopping";
}

} // namespace

int serve(Context& context, uint16_t port) {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        std::cerr << "RPC: cannot create socket\n";
        return 1;
    }

    int reuse = 1;
    ::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);

    if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        std::cerr << "RPC: cannot bind 127.0.0.1:" << port
                  << " — is another node already running?\n";
        ::close(listener);
        return 1;
    }
    if (::listen(listener, 16) < 0) {
        std::cerr << "RPC: cannot listen\n";
        ::close(listener);
        return 1;
    }

    std::cout << "QTC Core RPC listening on 127.0.0.1:" << port
              << " (loopback only, no authentication)\n"
              << "Chain height " << context.chain.height() << ", "
              << context.mempool.size() << " pending transaction(s)\n"
              << "Call 'stop' or press Ctrl-C to shut down.\n";
    std::cout.flush();

    bool running = true;
    while (running) {
        const int client = ::accept(listener, nullptr, nullptr);
        if (client < 0) continue;

        std::string body;
        if (!read_request(client, body)) body = "{}";
        const std::string response = handle(context, body);
        if (is_stop_reply(response)) running = false;

        const std::string reply = http_response(response);
        size_t sent = 0;
        while (sent < reply.size()) {
            const ssize_t wrote =
                ::send(client, reply.data() + sent, reply.size() - sent, 0);
            if (wrote <= 0) break;
            sent += static_cast<size_t>(wrote);
        }
        ::close(client);
    }

    ::close(listener);
    std::cout << "QTC Core RPC stopped.\n";
    return 0;
}

std::string call(const std::string& host, uint16_t port, const std::string& method,
                 const std::string& params_json) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return {};

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        ::close(fd);
        return {};
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        ::close(fd);
        return {};
    }

    const std::string request =
        std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"") + method +
        "\",\"params\":" + (params_json.empty() ? "[]" : params_json) + "}";
    const std::string http =
        "POST / HTTP/1.1\r\nHost: " + host +
        "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(request.size()) + "\r\nConnection: close\r\n\r\n" + request;

    size_t sent = 0;
    while (sent < http.size()) {
        const ssize_t wrote = ::send(fd, http.data() + sent, http.size() - sent, 0);
        if (wrote <= 0) break;
        sent += static_cast<size_t>(wrote);
    }

    std::string response;
    char buffer[4096];
    while (true) {
        const ssize_t got = ::recv(fd, buffer, sizeof(buffer), 0);
        if (got <= 0) break;
        response.append(buffer, static_cast<size_t>(got));
    }
    ::close(fd);

    const size_t body_start = response.find("\r\n\r\n");
    return body_start == std::string::npos ? std::string()
                                           : response.substr(body_start + 4);
}

} // namespace rpc
} // namespace qtc