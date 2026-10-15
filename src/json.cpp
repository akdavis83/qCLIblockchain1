#include "json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace qtc {
namespace json {

namespace {
const Value kNull;
constexpr int kMaxDepth = 32;
} // namespace

Value Value::make_object() {
    Value v;
    v.type_ = Type::OBJECT;
    return v;
}

Value Value::make_array() {
    Value v;
    v.type_ = Type::ARRAY;
    return v;
}

Value Value::number(double value) {
    Value v;
    v.type_ = Type::NUMBER;
    v.number_ = value;
    return v;
}

Value Value::string(std::string value) {
    Value v;
    v.type_ = Type::STRING;
    v.string_ = std::move(value);
    return v;
}

Value Value::boolean(bool value) {
    Value v;
    v.type_ = Type::BOOL;
    v.bool_ = value;
    return v;
}

uint64_t Value::as_uint(uint64_t fallback) const {
    if (!is_number() || number_ < 0) return fallback;
    return static_cast<uint64_t>(number_);
}

const Value& Value::operator[](const std::string& key) const {
    auto it = object_.find(key);
    return it == object_.end() ? kNull : it->second;
}

bool Value::has(const std::string& key) const {
    return object_.find(key) != object_.end();
}

void Value::push_back(Value value) {
    type_ = Type::ARRAY;
    array_.push_back(std::move(value));
}

void Value::set(const std::string& key, Value value) {
    type_ = Type::OBJECT;
    object_[key] = std::move(value);
}

namespace {

void escape_into(const std::string& text, std::string& out) {
    out += '"';
    for (unsigned char c : text) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
}

void number_into(double value, std::string& out) {
    // Integers must serialise without a decimal point, or Bitcoin-style clients
    // reject satoshi amounts as floats.
    if (value == std::floor(value) && std::fabs(value) < 9.2e18) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld",
                      static_cast<long long>(value));
        out += buf;
        return;
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%.17g", value);
    out += buf;
}

void skip_space(const std::string& text, size_t& pos) {
    while (pos < text.size() &&
           (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\n' ||
            text[pos] == '\r')) {
        ++pos;
    }
}

bool parse_string(const std::string& text, size_t& pos, std::string& out,
                  std::string& error) {
    if (pos >= text.size() || text[pos] != '"') {
        error = "expected a string";
        return false;
    }
    ++pos;
    out.clear();
    while (pos < text.size()) {
        const char c = text[pos++];
        if (c == '"') return true;
        if (c != '\\') {
            out += c;
            continue;
        }
        if (pos >= text.size()) break;
        const char esc = text[pos++];
        switch (esc) {
            case '"':  out += '"';  break;
            case '\\': out += '\\'; break;
            case '/':  out += '/';  break;
            case 'b':  out += '\b'; break;
            case 'f':  out += '\f'; break;
            case 'n':  out += '\n'; break;
            case 'r':  out += '\r'; break;
            case 't':  out += '\t'; break;
            case 'u': {
                if (pos + 4 > text.size()) {
                    error = "truncated \\u escape";
                    return false;
                }
                const std::string hex = text.substr(pos, 4);
                pos += 4;
                const unsigned long code = std::strtoul(hex.c_str(), nullptr, 16);
                // Encode as UTF-8. Surrogate pairs are passed through as-is.
                if (code < 0x80) {
                    out += static_cast<char>(code);
                } else if (code < 0x800) {
                    out += static_cast<char>(0xC0 | (code >> 6));
                    out += static_cast<char>(0x80 | (code & 0x3F));
                } else {
                    out += static_cast<char>(0xE0 | (code >> 12));
                    out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                    out += static_cast<char>(0x80 | (code & 0x3F));
                }
                break;
            }
            default:
                error = "unknown escape sequence";
                return false;
        }
    }
    error = "unterminated string";
    return false;
}

} // namespace

void Value::dump_into(const Value& value, std::string& out) {
    switch (value.type_) {
        case Type::NUL:    out += "null"; break;
        case Type::BOOL:   out += value.bool_ ? "true" : "false"; break;
        case Type::NUMBER: number_into(value.number_, out); break;
        case Type::STRING: escape_into(value.string_, out); break;
        case Type::ARRAY:
            out += '[';
            for (size_t i = 0; i < value.array_.size(); ++i) {
                if (i) out += ',';
                dump_into(value.array_[i], out);
            }
            out += ']';
            break;
        case Type::OBJECT:
            out += '{';
            {
                bool first = true;
                for (const auto& entry : value.object_) {
                    if (!first) out += ',';
                    first = false;
                    escape_into(entry.first, out);
                    out += ':';
                    dump_into(entry.second, out);
                }
            }
            out += '}';
            break;
    }
}

std::string Value::dump() const {
    std::string out;
    dump_into(*this, out);
    return out;
}

bool Value::parse_value(const std::string& text, size_t& pos, Value& out,
                        std::string& error, int depth) {
    if (depth > kMaxDepth) {
        error = "nesting too deep";
        return false;
    }
    skip_space(text, pos);
    if (pos >= text.size()) {
        error = "unexpected end of input";
        return false;
    }

    const char c = text[pos];
    if (c == '{') {
        ++pos;
        out = Value::make_object();
        skip_space(text, pos);
        if (pos < text.size() && text[pos] == '}') {
            ++pos;
            return true;
        }
        while (true) {
            skip_space(text, pos);
            std::string key;
            if (!parse_string(text, pos, key, error)) return false;
            skip_space(text, pos);
            if (pos >= text.size() || text[pos] != ':') {
                error = "expected ':' after object key";
                return false;
            }
            ++pos;
            Value child;
            if (!parse_value(text, pos, child, error, depth + 1)) return false;
            out.set(key, std::move(child));
            skip_space(text, pos);
            if (pos < text.size() && text[pos] == ',') {
                ++pos;
                continue;
            }
            if (pos < text.size() && text[pos] == '}') {
                ++pos;
                return true;
            }
            error = "expected ',' or '}' in object";
            return false;
        }
    }

    if (c == '[') {
        ++pos;
        out = Value::make_array();
        skip_space(text, pos);
        if (pos < text.size() && text[pos] == ']') {
            ++pos;
            return true;
        }
        while (true) {
            Value child;
            if (!parse_value(text, pos, child, error, depth + 1)) return false;
            out.push_back(std::move(child));
            skip_space(text, pos);
            if (pos < text.size() && text[pos] == ',') {
                ++pos;
                continue;
            }
            if (pos < text.size() && text[pos] == ']') {
                ++pos;
                return true;
            }
            error = "expected ',' or ']' in array";
            return false;
        }
    }

    if (c == '"') {
        std::string parsed;
        if (!parse_string(text, pos, parsed, error)) return false;
        out = Value::string(std::move(parsed));
        return true;
    }

    if (text.compare(pos, 4, "true") == 0) {
        pos += 4;
        out = Value::boolean(true);
        return true;
    }
    if (text.compare(pos, 5, "false") == 0) {
        pos += 5;
        out = Value::boolean(false);
        return true;
    }
    if (text.compare(pos, 4, "null") == 0) {
        pos += 4;
        out = Value();
        return true;
    }

    // Number
    const size_t start = pos;
    if (pos < text.size() && (text[pos] == '-' || text[pos] == '+')) ++pos;
    bool digits = false;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        ++pos;
        digits = true;
    }
    if (pos < text.size() && text[pos] == '.') {
        ++pos;
        while (pos < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[pos]))) {
            ++pos;
            digits = true;
        }
    }
    if (digits && pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
        ++pos;
        if (pos < text.size() && (text[pos] == '-' || text[pos] == '+')) ++pos;
        while (pos < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[pos]))) {
            ++pos;
        }
    }
    if (!digits) {
        error = "unexpected character";
        return false;
    }
    out = Value::number(std::strtod(text.substr(start, pos - start).c_str(), nullptr));
    return true;
}

bool Value::parse(const std::string& text, Value& out, std::string& error) {
    size_t pos = 0;
    Value parsed;
    if (!parse_value(text, pos, parsed, error, 0)) return false;
    skip_space(text, pos);
    if (pos != text.size()) {
        error = "trailing characters after the value";
        return false;
    }
    out = std::move(parsed);
    return true;
}

} // namespace json
} // namespace qtc