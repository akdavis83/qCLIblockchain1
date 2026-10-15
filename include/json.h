#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace qtc {
namespace json {

// Minimal JSON reader/writer. QTC Core carries no external dependencies, and the
// only JSON it needs is the JSON-RPC 2.0 envelope.
class Value {
public:
    enum class Type { NUL, BOOL, NUMBER, STRING, ARRAY, OBJECT };

    Value() = default;
    static Value make_object();
    static Value make_array();
    static Value number(double value);
    static Value string(std::string value);
    static Value boolean(bool value);

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::NUL; }
    bool is_bool() const { return type_ == Type::BOOL; }
    bool is_number() const { return type_ == Type::NUMBER; }
    bool is_string() const { return type_ == Type::STRING; }
    bool is_array() const { return type_ == Type::ARRAY; }
    bool is_object() const { return type_ == Type::OBJECT; }

    bool as_bool(bool fallback = false) const { return is_bool() ? bool_ : fallback; }
    double as_number(double fallback = 0) const { return is_number() ? number_ : fallback; }
    uint64_t as_uint(uint64_t fallback = 0) const;
    const std::string& as_string() const { return string_; }

    const std::vector<Value>& items() const { return array_; }
    // Missing keys return a null Value rather than throwing, so a malformed
    // request produces a JSON-RPC error instead of a crash.
    const Value& operator[](const std::string& key) const;
    bool has(const std::string& key) const;

    void push_back(Value value);
    void set(const std::string& key, Value value);

    std::string dump() const;

    // Returns false and fills `error` on malformed input.
    static bool parse(const std::string& text, Value& out, std::string& error);

private:
    Type type_ = Type::NUL;
    bool bool_ = false;
    double number_ = 0;
    std::string string_;
    std::vector<Value> array_;
    std::map<std::string, Value> object_;

    static void dump_into(const Value& value, std::string& out);
    static bool parse_value(const std::string& text, size_t& pos, Value& out,
                            std::string& error, int depth);
};

} // namespace json
} // namespace qtc