// pes6pkg_core.cpp: JSON restringido, versiones, rutas, firmas minisign, estado, índice y manifiesto.
// Sin Windows: se prueba entero con los vectores de tool/pes6pkg (client/tests).
#include "pes6pkg_client.h"

#include <stdio.h>
#include <string.h>

#include <algorithm>

extern "C" {
#include "monocypher.h"
#include "optional/monocypher-ed25519.h"
}

namespace pes6pkg {

const char* error_name(Error e) {
    static const char* const N[E_COUNT] = {
        "OK", "E_NETWORK", "E_HTTP", "E_TOO_BIG", "E_URL_NOT_ALLOWED",
        "E_SIG_FORMAT", "E_SIG_ALGORITHM", "E_UNKNOWN_KEY", "E_REVOKED_KEY", "E_BAD_SIGNATURE", "E_BAD_GLOBAL_SIGNATURE",
        "E_JSON", "E_TYPE", "E_SCHEMA", "E_FIELD", "E_BAD_COMMENT", "E_LIFETIME", "E_EXPIRED", "E_ROLLBACK",
        "E_SAME_SERIAL", "E_HASH", "E_SIZE", "E_PATH", "E_PATH_NOT_ALLOWED", "E_WRONG_PACKAGE", "E_WRONG_VERSION",
        "E_NOT_NEWER", "E_REQUIRES", "E_ZIP", "E_ZIP_EXTRA", "E_ZIP_MISSING", "E_ZIP_BOMB", "E_CRC", "E_IO",
    };
    return (e >= 0 && e < E_COUNT) ? N[e] : "E_?";
}

const char* const INDEX_URL = "https://raw.githubusercontent.com/angelballay/pes6-package-pc/main/index/index.json";
const char* const DEFAULT_URL_PREFIXES[] = {
    "https://raw.githubusercontent.com/angelballay/pes6-package-pc/",
    "https://github.com/angelballay/pes6-hd-text/releases/download/",
    "https://github.com/angelballay/pes6xlife-translations/releases/download/",
};
const size_t DEFAULT_URL_PREFIX_COUNT = sizeof(DEFAULT_URL_PREFIXES) / sizeof(DEFAULT_URL_PREFIXES[0]);

namespace {

const uint64_t MAX_INT = 9007199254740992ull;  // 2^53
const int64_t DAY = 86400;
const int64_t MAX_LIFETIME = 180 * DAY;

bool starts_with(const std::string& s, const char* p) { return s.compare(0, strlen(p), p) == 0; }
bool ends_with(const std::string& s, const char* p) {
    const size_t n = strlen(p);
    return s.size() >= n && s.compare(s.size() - n, n, p) == 0;
}
std::string lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}
std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    size_t p = 0;
    for (;;) {
        const size_t q = s.find(sep, p);
        out.push_back(s.substr(p, q == std::string::npos ? std::string::npos : q - p));
        if (q == std::string::npos) return out;
        p = q + 1;
    }
}
bool is_digit(char c) { return c >= '0' && c <= '9'; }
size_t utf8_length(const std::string& s) {
    size_t n = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80) ++n;
    return n;
}
bool hex_decode(const std::string& s, uint8_t* out, size_t n) {
    if (s.size() != 2 * n) return false;
    for (size_t i = 0; i < 2 * n; ++i) {
        const char c = s[i];
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else return false;  // solo minúsculas, como pes6pkg
        if (i % 2 == 0) out[i / 2] = uint8_t(v << 4);
        else out[i / 2] |= uint8_t(v);
    }
    return true;
}

// ---------------------------------------------------------------- UTF-8 estricto
bool valid_utf8(const uint8_t* p, size_t n) {
    size_t i = 0;
    while (i < n) {
        const uint8_t c = p[i];
        if (c < 0x80) { ++i; continue; }
        size_t len;
        uint32_t cp;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}
void put_utf8(std::string& s, uint32_t cp) {
    if (cp < 0x80) s += char(cp);
    else if (cp < 0x800) { s += char(0xC0 | (cp >> 6)); s += char(0x80 | (cp & 0x3F)); }
    else { s += char(0xE0 | (cp >> 12)); s += char(0x80 | ((cp >> 6) & 0x3F)); s += char(0x80 | (cp & 0x3F)); }
}

// ---------------------------------------------------------------- JSON restringido
struct Parser {
    const char* s;
    size_t n, i;
    int max_depth;
    bool fail;

    void ws() {
        while (i < n && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t')) ++i;
    }
    bool lit(const char* t) {
        const size_t k = strlen(t);
        if (n - i >= k && memcmp(s + i, t, k) == 0) { i += k; return true; }
        return false;
    }
    bool string(std::string& out) {
        ++i;  // "
        out.clear();
        while (i < n) {
            const unsigned char c = (unsigned char)s[i];
            if (c == '"') { ++i; return true; }
            if (c < 0x20) return false;
            if (c == '\\') {
                if (i + 1 >= n) return false;
                const char e = s[i + 1];
                if (e == '"' || e == '\\' || e == '/') { out += e; i += 2; }
                else if (e == 'n') { out += '\n'; i += 2; }
                else if (e == 't') { out += '\t'; i += 2; }
                else if (e == 'u') {
                    if (i + 6 > n) return false;
                    uint32_t cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = s[i + 2 + k];
                        int v;
                        if (h >= '0' && h <= '9') v = h - '0';
                        else if (h >= 'a' && h <= 'f') v = h - 'a' + 10;
                        else if (h >= 'A' && h <= 'F') v = h - 'A' + 10;
                        else return false;
                        cp = cp * 16 + uint32_t(v);
                    }
                    if (cp >= 0xD800 && cp <= 0xDFFF) return false;
                    put_utf8(out, cp);
                    i += 6;
                } else return false;
            } else { out += char(c); ++i; }
        }
        return false;
    }
    bool value(Json& v, int depth) {
        ws();
        if (i >= n) return false;
        const char c = s[i];
        if (c == '{') {
            if (depth + 1 > max_depth) return false;
            ++i;
            v.kind = Json::OBJECT;
            ws();
            if (i < n && s[i] == '}') { ++i; return true; }
            for (;;) {
                ws();
                if (i >= n || s[i] != '"') return false;
                std::string k;
                if (!string(k)) return false;
                for (const auto& kv : v.obj)
                    if (kv.first == k) return false;  // clave repetida
                ws();
                if (i >= n || s[i] != ':') return false;
                ++i;
                v.obj.emplace_back(k, Json());
                if (!value(v.obj.back().second, depth + 1)) return false;
                ws();
                if (i < n && s[i] == ',') { ++i; continue; }
                if (i < n && s[i] == '}') { ++i; return true; }
                return false;
            }
        }
        if (c == '[') {
            if (depth + 1 > max_depth) return false;
            ++i;
            v.kind = Json::ARRAY;
            ws();
            if (i < n && s[i] == ']') { ++i; return true; }
            for (;;) {
                v.arr.emplace_back();
                if (!value(v.arr.back(), depth + 1)) return false;
                ws();
                if (i < n && s[i] == ',') { ++i; continue; }
                if (i < n && s[i] == ']') { ++i; return true; }
                return false;
            }
        }
        if (c == '"') { v.kind = Json::STRING; return string(v.str); }
        if (is_digit(c)) {
            const size_t j = i;
            while (i < n && is_digit(s[i])) ++i;
            if (i - j > 1 && s[j] == '0') return false;
            if (i < n && (s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '-' || s[i] == '+')) return false;
            if (i - j > 16) return false;
            uint64_t x = 0;
            for (size_t k = j; k < i; ++k) x = x * 10 + uint64_t(s[k] - '0');
            if (x > MAX_INT) return false;
            v.kind = Json::INT;
            v.num = x;
            return true;
        }
        if (lit("true")) { v.kind = Json::BOOL; v.b = true; return true; }
        if (lit("false")) { v.kind = Json::BOOL; v.b = false; return true; }
        return false;
    }
};

// ---------------------------------------------------------------- base64 estricto
int b64v(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
bool b64_decode(std::string s, std::vector<uint8_t>& out) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t')) ++a;
    s = s.substr(a);
    if (s.empty() || s.size() % 4) return false;
    size_t pad = 0;
    if (s.back() == '=') { ++pad; if (s[s.size() - 2] == '=') ++pad; }
    out.clear();
    uint32_t acc = 0;
    for (size_t i = 0; i < s.size() - pad; ++i) {
        const int v = b64v(s[i]);
        if (v < 0) return false;
        acc = (acc << 6) | uint32_t(v);
        if (i % 4 == 3) {
            out.push_back(uint8_t(acc >> 16));
            out.push_back(uint8_t(acc >> 8));
            out.push_back(uint8_t(acc));
            acc = 0;
        }
    }
    if (pad == 1) { acc <<= 6; out.push_back(uint8_t(acc >> 16)); out.push_back(uint8_t(acc >> 8)); }
    if (pad == 2) { acc <<= 12; out.push_back(uint8_t(acc >> 16)); }
    return true;
}

// ---------------------------------------------------------------- fechas (días civiles, sin la hora local)
int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = unsigned(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + int64_t(doe) - 719468;
}
bool digits(const std::string& s, size_t at, size_t n, unsigned& out) {
    out = 0;
    for (size_t k = 0; k < n; ++k) {
        if (at + k >= s.size() || !is_digit(s[at + k])) return false;
        out = out * 10 + unsigned(s[at + k] - '0');
    }
    return true;
}
bool date_ok(unsigned y, unsigned m, unsigned d) {
    static const unsigned ML[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m < 1 || m > 12 || d < 1 || y < 1) return false;
    const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    return d <= ML[m - 1] + ((m == 2 && leap) ? 1u : 0u);
}

// ---------------------------------------------------------------- campos
const Json* need(const Json& o, const char* key, Json::Kind kind) {
    const Json* v = o.get(key);
    return (v && v->kind == kind) ? v : nullptr;
}
bool package_id_ok(const std::string& p) {
    if (p.empty() || p.size() > 40) return false;
    for (size_t i = 0; i < p.size(); ++i) {
        const char c = p[i];
        const bool ok = (c >= 'a' && c <= 'z') || is_digit(c) || (c == '-' && i > 0);
        if (!ok) return false;
    }
    return true;
}
bool hex64_ok(const std::string& s, uint8_t out[32]) { return hex_decode(s, out, 32); }
bool fileref(const Json* o, FileRef& out) {
    if (!o || o->kind != Json::OBJECT) return false;
    const Json* u = need(*o, "url", Json::STRING);
    const Json* z = need(*o, "size", Json::INT);
    const Json* h = need(*o, "sha256", Json::STRING);
    if (!u || !valid_url(u->str) || !z || !h || !hex64_ok(h->str, out.sha256)) return false;
    out.url = u->str;
    out.size = z->num;
    return true;
}
Error head(const Json& doc, const char* type) {
    if (doc.kind != Json::OBJECT) return E_TYPE;
    const Json* t = doc.get("type");
    if (!t || t->kind != Json::STRING || t->str != type) return E_TYPE;
    const Json* s = doc.get("schema");
    if (!s || s->kind != Json::INT || s->num != 1) return E_SCHEMA;
    return OK;
}
bool lang_code_ok(const std::string& c) {
    // [a-z]{2,3}(-[a-z]{2,4})?
    const size_t dash = c.find('-');
    const std::string a = c.substr(0, dash);
    auto letters = [](const std::string& x, size_t lo, size_t hi) {
        if (x.size() < lo || x.size() > hi) return false;
        for (char ch : x)
            if (ch < 'a' || ch > 'z') return false;
        return true;
    };
    if (!letters(a, 2, 3)) return false;
    return dash == std::string::npos || letters(c.substr(dash + 1), 2, 4);
}
bool glob_part(const std::string& s, const std::string& p) {  // "*" no cruza "/"; sin distinguir mayúsculas
    size_t si = 0, pi = 0, star = std::string::npos, mark = 0;
    while (si < s.size()) {
        if (pi < p.size() && p[pi] == '*') { star = pi++; mark = si; }
        else if (pi < p.size() && p[pi] == s[si]) { ++pi; ++si; }
        else if (star != std::string::npos) { pi = star + 1; si = ++mark; }
        else return false;
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}
bool doc_name_ok(const std::string& p) {  // README.txt, LEEME.txt, CHANGELOG.md…: solo en la raíz del zip
    if (p.find('/') != std::string::npos || p.size() > 64) return false;
    if (!(ends_with(p, ".txt") || ends_with(p, ".md"))) return false;
    const size_t stem = p.size() - (ends_with(p, ".txt") ? 4 : 3);
    if (stem < 1) return false;
    for (char c : p)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || is_digit(c) || c == '.' || c == '_' || c == ' ' || c == '-'))
            return false;
    return true;
}

Error signed_doc(const uint8_t* data, size_t n, const char* sig, size_t sig_len, const PublicKey* keys,
                 size_t key_count, const std::vector<KeyId>& revoked, size_t max, int& key_index,
                 std::string& comment, Json& doc) {
    if (n > max) return E_TOO_BIG;
    const Error e = verify_minisig(data, n, sig, sig_len, keys, key_count, revoked, key_index, comment);
    if (e != OK) return e;
    return parse_json(data, n, 4, doc) ? OK : E_JSON;
}

}  // namespace

// ---------------------------------------------------------------- JSON
const Json* Json::get(const char* key) const {
    if (kind != OBJECT) return nullptr;
    for (const auto& kv : obj)
        if (kv.first == key) return &kv.second;
    return nullptr;
}

bool parse_json(const uint8_t* p, size_t n, int max_depth, Json& out) {
    out = Json();
    if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) return false;  // BOM
    if (memchr(p, '\r', n)) return false;
    if (!valid_utf8(p, n)) return false;
    Parser ps{(const char*)p, n, 0, max_depth, false};
    if (!ps.value(out, 0)) return false;
    ps.ws();
    return ps.i == n;
}

// ---------------------------------------------------------------- versiones y fechas
bool parse_version(const std::string& s, Version& out) {
    const auto parts = split(s, '.');
    if (parts.empty() || parts.size() > 4) return false;
    for (size_t i = 0; i < 4; ++i) out.v[i] = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
        const std::string& x = parts[i];
        if (x.empty() || x.size() > 5 || (x.size() > 1 && x[0] == '0')) return false;
        unsigned v = 0;
        for (char c : x) {
            if (!is_digit(c)) return false;
            v = v * 10 + unsigned(c - '0');
        }
        if (v > 65535) return false;
        out.v[i] = uint16_t(v);
    }
    return true;
}

int compare_versions(const Version& a, const Version& b) {
    for (int i = 0; i < 4; ++i)
        if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
    return 0;
}

bool valid_date(const std::string& s) {
    unsigned y, m, d;
    return s.size() == 10 && s[4] == '-' && s[7] == '-' && digits(s, 0, 4, y) && digits(s, 5, 2, m) &&
           digits(s, 8, 2, d) && date_ok(y, m, d);
}

bool parse_utc(const std::string& s, int64_t& t) {
    unsigned y, mo, d, h, mi, se;
    if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z')
        return false;
    if (!digits(s, 0, 4, y) || !digits(s, 5, 2, mo) || !digits(s, 8, 2, d) || !digits(s, 11, 2, h) ||
        !digits(s, 14, 2, mi) || !digits(s, 17, 2, se))
        return false;
    if (!date_ok(y, mo, d) || h > 23 || mi > 59 || se > 59) return false;
    t = days_from_civil(y, mo, d) * DAY + int64_t(h) * 3600 + int64_t(mi) * 60 + se;
    return true;
}

std::string format_utc(int64_t t) {
    int64_t z = (t >= 0 ? t / DAY : (t - DAY + 1) / DAY) + 719468;
    const int64_t secs = t - (z - 719468) * DAY;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = unsigned(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    const int64_t y = int64_t(yoe) + era * 400 + (m <= 2);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02u-%02uT%02d:%02d:%02dZ", int(y), m, d, int(secs / 3600), int(secs / 60 % 60),
             int(secs % 60));
    return buf;
}

// ---------------------------------------------------------------- rutas y direcciones
bool valid_path(const std::string& path) {
    if (path.empty() || path.size() > 260 || path[0] == '/') return false;
    if (path.find('\\') != std::string::npos || path.find(':') != std::string::npos) return false;
    static const char* const RESERVED[] = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
                                           "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
                                           "LPT6", "LPT7", "LPT8", "LPT9"};
    for (const auto& part : split(path, '/')) {
        if (part.empty() || part.size() > 64 || part == "." || part == "..") return false;
        for (char c : part)
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || is_digit(c) || c == '.' || c == '_' ||
                  c == ' ' || c == '-'))
                return false;
        if (part.back() == '.' || part.back() == ' ') return false;
        std::string stem = part.substr(0, part.find('.'));
        for (auto& c : stem)
            if (c >= 'a' && c <= 'z') c = char(c - 'a' + 'A');
        for (const char* r : RESERVED)
            if (stem == r) return false;
    }
    return true;
}

// Documentos (install: false): en la raíz del zip, o en Docs/<id del paquete>/ (un nivel, solo la carpeta del
// paquete), así no chocan los de dos paquetes que van en un mismo zip.
bool doc_path_ok(const std::string& package, const std::string& path) {
    const auto parts = split(path, '/');
    if (parts.size() == 1) return doc_name_ok(path);
    return parts.size() == 3 && lower(parts[0]) == "docs" && lower(parts[1]) == package && doc_name_ok(parts[2]);
}

bool path_allowed(const std::string& package, const std::string& path, bool install) {
    if (!valid_path(path)) return false;
    if (!install) return doc_path_ok(package, path);
    const std::string low = lower(path);
    if (starts_with(low, "kitserver/pes6pkg/")) return false;  // lo escribe solo el instalador
    if (starts_with(package, "translation-")) {
        const std::string code = package.substr(strlen("translation-"));
        if (lang_code_ok(code)) return low == "dat/" + code + "_text.afs";
    }
    struct Rule { const char* package; const char* pattern; };
    static const Rule RULES[] = {
        {"hdtext", "kitserver/pes6_hd_text.dll"},
        {"hdtext", "kitserver/hdtext.exe"},
        {"hdtext", "kitserver/gdb/fonts/hd_*.bin"},
        {"hdtext", "kitserver/gdb/fonts/font_licenses.txt"},
        {"hdtext", "kitserver/gdb/fonts/licenses/*.txt"},
        {"translations", "kitserver/translations.dll"},
        // provisorio hasta M-2 (design §5.5, §12)
        {"pes6xlife-mods", "kitserver/pes6xlife_mods.dll"},
        {"pes6xlife-mods", "kitserver/pes6xlife_mods.ini"},
    };
    const auto pp = split(low, '/');
    for (const auto& r : RULES) {
        if (package != r.package) continue;
        const auto rp = split(r.pattern, '/');
        if (rp.size() != pp.size()) continue;
        bool ok = true;
        for (size_t i = 0; ok && i < rp.size(); ++i) ok = glob_part(pp[i], rp[i]);
        if (ok) return true;
    }
    return false;
}

bool valid_url(const std::string& u) {
    if (!starts_with(u, "https://") || u.size() > 512) return false;
    if (u.find_first_of("?# ") != std::string::npos) return false;
    const size_t host_end = u.find('/', 8);
    const std::string host = u.substr(8, host_end == std::string::npos ? std::string::npos : host_end - 8);
    return host.find('@') == std::string::npos;
}

bool url_allowed(const std::string& url, const char* const* prefixes, size_t count) {
    if (!valid_url(url)) return false;
    for (size_t i = 0; i < count; ++i)
        if (starts_with(url, prefixes[i])) return true;
    return false;
}

// ---------------------------------------------------------------- minisign
Error parse_minisig(const char* text, size_t n, Minisig& out) {
    if (n > MAX_SIG) return E_TOO_BIG;
    std::string s(text, n);
    std::vector<std::string> lines = split(s, '\n');
    if (!lines.empty() && lines.back().empty()) lines.pop_back();
    for (auto& ln : lines)
        if (!ln.empty() && ln.back() == '\r') ln.pop_back();
    if (lines.size() != 4) return E_SIG_FORMAT;
    if (!starts_with(lines[0], "untrusted comment: ") || !starts_with(lines[2], "trusted comment: ")) return E_SIG_FORMAT;
    std::vector<uint8_t> a, g;
    if (!b64_decode(lines[1], a) || a.size() != 74 || !b64_decode(lines[3], g) || g.size() != 64) return E_SIG_FORMAT;
    memcpy(out.algorithm, a.data(), 2);
    memcpy(out.key_id, a.data() + 2, 8);
    memcpy(out.sig, a.data() + 10, 64);
    memcpy(out.global_sig, g.data(), 64);
    out.trusted_comment = lines[2].substr(strlen("trusted comment: "));
    return OK;
}

Error verify_minisig(const uint8_t* data, size_t n, const char* sig, size_t sig_len, const PublicKey* keys,
                     size_t key_count, const std::vector<KeyId>& revoked, int& key_index, std::string& comment) {
    Minisig m;
    const Error e = parse_minisig(sig, sig_len, m);
    if (e != OK) return e;
    if (m.algorithm[0] != 'E' || m.algorithm[1] != 'D') return E_SIG_ALGORITHM;  // solo "ED" (con prehash)
    key_index = -1;
    for (size_t i = 0; i < key_count; ++i)
        if (memcmp(keys[i].id, m.key_id, 8) == 0) { key_index = int(i); break; }
    if (key_index < 0) return E_UNKNOWN_KEY;
    for (const auto& r : revoked)
        if (memcmp(r.b, m.key_id, 8) == 0) return E_REVOKED_KEY;
    uint8_t h[64];
    crypto_blake2b(h, 64, data, n);
    // El prehash de minisign NO es Ed25519ph: es Ed25519 común sobre los 64 bytes de BLAKE2b (design §4.2).
    if (crypto_ed25519_check(m.sig, keys[key_index].key, h, 64) != 0) return E_BAD_SIGNATURE;
    std::vector<uint8_t> g(m.sig, m.sig + 64);
    g.insert(g.end(), m.trusted_comment.begin(), m.trusted_comment.end());
    if (crypto_ed25519_check(m.global_sig, keys[key_index].key, g.data(), g.size()) != 0) return E_BAD_GLOBAL_SIGNATURE;
    comment = m.trusted_comment;
    return OK;
}

void blake2b512(const uint8_t* p, size_t n, uint8_t out[64]) { crypto_blake2b(out, 64, p, n); }

std::string to_hex(const uint8_t* p, size_t n) {
    static const char* const H = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += H[p[i] >> 4]; s += H[p[i] & 15]; }
    return s;
}

// ---------------------------------------------------------------- estado
bool State::is_revoked(const uint8_t id[8]) const {
    for (const auto& r : revoked)
        if (memcmp(r.b, id, 8) == 0) return true;
    return false;
}

bool parse_state(const uint8_t* p, size_t n, State& out) {
    out = State();
    Json d;
    if (!parse_json(p, n, 4, d) || d.kind != Json::OBJECT) return false;
    const Json* s = need(d, "schema", Json::INT);
    if (!s || s->num != 1) return false;
    if (const Json* v = need(d, "index_serial", Json::INT)) out.index_serial = v->num;
    if (const Json* v = need(d, "index_blake2b", Json::STRING)) out.index_blake2b = v->str;
    if (const Json* v = need(d, "last_check", Json::STRING)) out.last_check = v->str;
    if (const Json* v = need(d, "revoked_keys", Json::ARRAY))
        for (const auto& x : v->arr) {
            KeyId k;
            if (x.kind != Json::STRING || !hex_decode(x.str, k.b, 8)) return false;
            out.revoked.push_back(k);
        }
    for (int pass = 0; pass < 2; ++pass) {
        const Json* v = need(d, pass ? "skip_notice" : "announced", Json::ARRAY);
        if (!v) continue;
        for (const auto& x : v->arr) {
            const Json* pk = x.kind == Json::OBJECT ? need(x, "package", Json::STRING) : nullptr;
            const Json* ve = x.kind == Json::OBJECT ? need(x, "version", Json::STRING) : nullptr;
            if (!pk || !ve) return false;
            (pass ? out.skip_notice : out.announced).push_back({pk->str, ve->str});
        }
    }
    return true;
}

namespace {
std::string jstr(const std::string& s) {  // las cadenas del estado son ASCII (ids, versiones, fechas, hex)
    std::string o = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') o += '\\';
        if ((unsigned char)c >= 0x20) o += c;
    }
    return o + "\"";
}
void list_pv(std::string& o, const char* key, const std::vector<PackageVersion>& v, bool last) {
    o += std::string("  \"") + key + "\": [";
    for (size_t i = 0; i < v.size(); ++i)
        o += (i ? ", " : "") + std::string("{\"package\": ") + jstr(v[i].package) + ", \"version\": " + jstr(v[i].version) + "}";
    o += last ? "]\n" : "],\n";
}
}  // namespace

std::string serialize_state(const State& s) {
    std::string o = "{\n  \"schema\": 1,\n";
    o += "  \"index_serial\": " + std::to_string(s.index_serial) + ",\n";
    o += "  \"index_blake2b\": " + jstr(s.index_blake2b) + ",\n";
    o += "  \"revoked_keys\": [";
    for (size_t i = 0; i < s.revoked.size(); ++i) o += (i ? ", " : "") + jstr(to_hex(s.revoked[i].b, 8));
    o += "],\n  \"last_check\": " + jstr(s.last_check) + ",\n";
    list_pv(o, "announced", s.announced, false);
    list_pv(o, "skip_notice", s.skip_notice, true);
    return o + "}\n";
}

void merge_state(State& into, const State& o) {
    if (o.index_serial > into.index_serial) {
        into.index_serial = o.index_serial;
        into.index_blake2b = o.index_blake2b;
        into.announced = o.announced;
    }
    for (const auto& r : o.revoked)
        if (!into.is_revoked(r.b)) into.revoked.push_back(r);
    if (o.last_check > into.last_check) into.last_check = o.last_check;  // mismo formato: se comparan como texto
    for (const auto& sk : o.skip_notice) {
        bool have = false;
        for (const auto& x : into.skip_notice) have = have || (x.package == sk.package && x.version == sk.version);
        if (!have) into.skip_notice.push_back(sk);
    }
}

// ---------------------------------------------------------------- índice
const IndexEntry* Index::find(const std::string& package) const {
    for (const auto& e : packages)
        if (e.package == package) return &e;
    return nullptr;
}

Error check_index(const uint8_t* data, size_t n, const char* sig, size_t sig_len, const PublicKey* keys,
                  size_t key_count, State& state, int64_t now, uint64_t min_serial, Index& out) {
    out = Index();
    int key_index = -1;
    std::string comment;
    Json d;
    Error e = signed_doc(data, n, sig, sig_len, keys, key_count, state.revoked, MAX_INDEX, key_index, comment, d);
    if (e != OK) return e;
    if ((e = head(d, "pes6pkg-index")) != OK) return e;
    const Json* serial = need(d, "serial", Json::INT);
    if (!serial || serial->num < 1) return E_FIELD;
    const Json* issued = need(d, "issued", Json::STRING);
    const Json* expires = need(d, "expires", Json::STRING);
    int64_t ti, te;
    if (!issued || !expires || !parse_utc(issued->str, ti) || !parse_utc(expires->str, te)) return E_FIELD;
    const Json* pk = need(d, "packages", Json::ARRAY);
    if (!pk || pk->arr.size() > 64) return E_FIELD;
    for (const auto& x : pk->arr) {
        if (x.kind != Json::OBJECT) return E_FIELD;
        IndexEntry en;
        const Json* p = need(x, "package", Json::STRING);
        if (!p || !package_id_ok(p->str) || out.find(p->str)) return E_FIELD;
        en.package = p->str;
        const Json* nm = need(x, "name", Json::STRING);
        if (!nm || utf8_length(nm->str) > 64) return E_FIELD;
        en.name = nm->str;
        const Json* v = need(x, "version", Json::STRING);
        Version vv;
        if (!v || !parse_version(v->str, vv)) return E_FIELD;
        en.version = v->str;
        const Json* r = need(x, "released", Json::STRING);
        if (!r || !valid_date(r->str)) return E_FIELD;
        en.released = r->str;
        const Json* no = need(x, "notes", Json::STRING);
        if (!no || !valid_url(no->str)) return E_FIELD;
        en.notes = no->str;
        if (!fileref(x.get("manifest"), en.manifest) || !fileref(x.get("archive"), en.archive)) return E_FIELD;
        out.packages.push_back(en);
    }
    if (comment != "pes6pkg index " + std::to_string(serial->num)) return E_BAD_COMMENT;
    if (!(ti < te) || te - ti > MAX_LIFETIME) return E_LIFETIME;
    if (now >= te) return E_EXPIRED;
    uint8_t h[64];
    blake2b512(data, n, h);
    const std::string hex = to_hex(h, 64);
    const uint64_t floor = std::max(state.index_serial, min_serial);
    if (serial->num < floor) return E_ROLLBACK;
    if (serial->num == state.index_serial && !state.index_blake2b.empty() && hex != state.index_blake2b)
        return E_SAME_SERIAL;
    // VER-6: la firma de una clave revoca a las que están antes en la lista embebida
    for (int i = 0; i < key_index; ++i)
        if (!state.is_revoked(keys[i].id)) {
            KeyId k;
            memcpy(k.b, keys[i].id, 8);
            state.revoked.push_back(k);
        }
    state.index_serial = serial->num;
    state.index_blake2b = hex;
    state.announced.clear();
    for (const auto& en : out.packages) state.announced.push_back({en.package, en.version});
    out.serial = serial->num;
    out.issued = issued->str;
    out.expires = expires->str;
    out.expires_unix = te;
    out.key_index = key_index;
    return OK;
}

// ---------------------------------------------------------------- manifiesto
Error check_manifest(const uint8_t* data, size_t n, const char* sig, size_t sig_len, const PublicKey* keys,
                     size_t key_count, const State& state, const ManifestExpect& ex, Manifest& out) {
    out = Manifest();
    int key_index = -1;
    std::string comment;
    Json d;
    Error e = signed_doc(data, n, sig, sig_len, keys, key_count, state.revoked, MAX_MANIFEST, key_index, comment, d);
    if (e != OK) return e;
    if ((e = head(d, "pes6pkg-manifest")) != OK) return e;
    const Json* p = need(d, "package", Json::STRING);
    if (!p || !package_id_ok(p->str)) return E_FIELD;
    out.package = p->str;
    const Json* nm = need(d, "name", Json::STRING);
    if (!nm || utf8_length(nm->str) > 64) return E_FIELD;
    out.name = nm->str;
    const Json* v = need(d, "version", Json::STRING);
    Version mv;
    if (!v || !parse_version(v->str, mv)) return E_FIELD;
    out.version = v->str;
    const Json* r = need(d, "released", Json::STRING);
    if (!r || !valid_date(r->str)) return E_FIELD;
    out.released = r->str;
    const Json* rq = need(d, "requires", Json::ARRAY);
    if (!rq) return E_FIELD;
    for (const auto& x : rq->arr) {
        const Json* a = x.kind == Json::OBJECT ? need(x, "package", Json::STRING) : nullptr;
        const Json* b = x.kind == Json::OBJECT ? need(x, "min", Json::STRING) : nullptr;
        Version tmp;
        if (!a || !package_id_ok(a->str) || !b || !parse_version(b->str, tmp)) return E_FIELD;
        out.requires.push_back({a->str, b->str});
    }
    const Json* fs = need(d, "files", Json::ARRAY);
    if (!fs || fs->arr.size() > 2000) return E_FIELD;
    std::vector<std::string> seen;
    for (const auto& x : fs->arr) {
        if (x.kind != Json::OBJECT) return E_FIELD;
        ManifestFile f;
        const Json* fp = need(x, "path", Json::STRING);
        if (!fp) return E_FIELD;
        const Json* fz = need(x, "size", Json::INT);
        if (!fz) return E_FIELD;
        const Json* fh = need(x, "sha256", Json::STRING);
        if (!fh || !hex64_ok(fh->str, f.sha256)) return E_FIELD;
        const Json* fi = need(x, "install", Json::BOOL);
        if (!fi) return E_FIELD;
        if (const Json* fm = x.get("mode")) {
            if (fm->kind != Json::STRING || (fm->str != "replace" && fm->str != "if-absent")) return E_FIELD;
            f.if_absent = fm->str == "if-absent";
        }
        const std::string low = lower(fp->str);
        if (!valid_path(fp->str) || std::find(seen.begin(), seen.end(), low) != seen.end()) return E_PATH;
        seen.push_back(low);
        f.path = fp->str;
        f.size = fz->num;
        f.install = fi->b;
        out.files.push_back(f);
    }
    for (const auto& f : out.files)
        if (!path_allowed(out.package, f.path, f.install)) return E_PATH_NOT_ALLOWED;
    if (comment != "pes6pkg manifest " + out.package + " " + out.version) return E_BAD_COMMENT;
    if (ex.package && out.package != ex.package) return E_WRONG_PACKAGE;
    if (ex.packages_allowed) {
        bool ok = false;
        for (size_t i = 0; i < ex.packages_allowed_count && !ok; ++i) {
            const std::string pat = ex.packages_allowed[i];
            ok = pat == out.package ||
                 (!pat.empty() && pat.back() == '*' && starts_with(out.package, pat.substr(0, pat.size() - 1).c_str()));
        }
        if (!ok) return E_WRONG_PACKAGE;
    }
    if (ex.version && out.version != ex.version) return E_WRONG_VERSION;
    if (ex.installed) {
        Version iv;
        if (!parse_version(ex.installed, iv)) return E_NOT_NEWER;
        const int c = compare_versions(mv, iv);
        if (c < 0 || (c == 0 && !ex.allow_equal)) return E_NOT_NEWER;
    }
    return OK;
}

Error check_requires(const Manifest& m, const std::vector<PackageVersion>& installed) {
    for (const auto& r : m.requires) {
        const PackageVersion* have = nullptr;
        for (const auto& i : installed)
            if (i.package == r.package) have = &i;
        Version a, b;
        if (!have || !parse_version(have->version, a) || !parse_version(r.min, b) || compare_versions(a, b) < 0)
            return E_REQUIRES;
    }
    return OK;
}

Error check_bytes(const uint8_t* data, size_t n, const FileRef& ref) {
    if (n != ref.size) return E_SIZE;
    uint8_t h[32];
    if (!sha256(data, n, h)) return E_IO;
    return memcmp(h, ref.sha256, 32) == 0 ? OK : E_HASH;
}

}  // namespace pes6pkg
