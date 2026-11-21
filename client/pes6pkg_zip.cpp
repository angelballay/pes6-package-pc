// pes6pkg_zip.cpp: zip estricto (design §5.4), deflate crudo (RFC 1951) y CRC-32.
// El descompresor sigue la estructura de puff.c de Mark Adler: decodifica bit a bit, sin tablas rápidas. Es más lento
// que zlib, pero corto y fácil de revisar, y nunca escribe fuera del búfer: si el resultado no entra, es un "zip bomba".
#include "pes6pkg_client.h"

#include <string.h>

#include <algorithm>

namespace pes6pkg {

// ---------------------------------------------------------------- CRC-32
uint32_t crc32(const uint8_t* p, size_t n) {
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        ready = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------- inflate
namespace {

const int MAXBITS = 15;
const int MAXLCODES = 286, MAXDCODES = 30, FIXLCODES = 288;
enum { R_OK = 0, R_INPUT = 1, R_BOMB = 2, R_BAD = 3 };

struct Inflater {
    const uint8_t* in;
    size_t inlen, incnt;
    uint8_t* out;
    size_t outlen, outcnt;
    uint32_t bitbuf;
    int bitcnt;
    int err;

    int bits(int need) {
        uint32_t val = bitbuf;
        while (bitcnt < need) {
            if (incnt == inlen) { err = R_INPUT; return 0; }
            val |= uint32_t(in[incnt++]) << bitcnt;
            bitcnt += 8;
        }
        bitbuf = val >> need;
        bitcnt -= need;
        return int(val & ((1u << need) - 1));
    }
    bool put(uint8_t b) {
        if (outcnt == outlen) { err = R_BOMB; return false; }
        out[outcnt++] = b;
        return true;
    }
};

struct Huffman {
    short count[MAXBITS + 1];
    short symbol[FIXLCODES];
};

int decode(Inflater& s, const Huffman& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= MAXBITS; ++len) {
        code |= s.bits(1);
        if (s.err) return -1;
        const int count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    s.err = R_BAD;  // se acabaron los códigos
    return -1;
}

int construct(Huffman& h, const short* length, int n) {
    for (int len = 0; len <= MAXBITS; ++len) h.count[len] = 0;
    for (int sym = 0; sym < n; ++sym) h.count[length[sym]]++;
    if (h.count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= MAXBITS; ++len) {
        left <<= 1;
        left -= h.count[len];
        if (left < 0) return left;  // demasiados códigos
    }
    short offs[MAXBITS + 1];
    offs[1] = 0;
    for (int len = 1; len < MAXBITS; ++len) offs[len + 1] = short(offs[len] + h.count[len]);
    for (int sym = 0; sym < n; ++sym)
        if (length[sym] != 0) h.symbol[offs[length[sym]]++] = short(sym);
    return left;
}

bool stored(Inflater& s) {
    s.bitbuf = 0;
    s.bitcnt = 0;
    if (s.incnt + 4 > s.inlen) { s.err = R_INPUT; return false; }
    unsigned len = s.in[s.incnt] | (unsigned(s.in[s.incnt + 1]) << 8);
    const unsigned nlen = s.in[s.incnt + 2] | (unsigned(s.in[s.incnt + 3]) << 8);
    s.incnt += 4;
    if (len != (~nlen & 0xFFFF)) { s.err = R_BAD; return false; }
    if (s.incnt + len > s.inlen) { s.err = R_INPUT; return false; }
    while (len--)
        if (!s.put(s.in[s.incnt++])) return false;
    return true;
}

bool codes(Inflater& s, const Huffman& lencode, const Huffman& distcode) {
    static const short LENS[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
                                   67, 83, 99, 115, 131, 163, 195, 227, 258};
    static const short LEXT[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    static const short DISTS[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    static const short DEXT[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
                                   9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    for (;;) {
        int sym = decode(s, lencode);
        if (s.err) return false;
        if (sym < 256) {
            if (!s.put(uint8_t(sym))) return false;
        } else if (sym == 256) {
            return true;
        } else {
            sym -= 257;
            if (sym >= 29) { s.err = R_BAD; return false; }
            const int len = LENS[sym] + s.bits(LEXT[sym]);
            if (s.err) return false;
            const int ds = decode(s, distcode);
            if (s.err) return false;
            if (ds >= 30) { s.err = R_BAD; return false; }
            const size_t dist = size_t(DISTS[ds] + s.bits(DEXT[ds]));
            if (s.err) return false;
            if (dist > s.outcnt) { s.err = R_BAD; return false; }  // distancia antes del principio
            for (int k = 0; k < len; ++k)
                if (!s.put(s.out[s.outcnt - dist])) return false;
        }
    }
}

bool fixed(Inflater& s) {
    static Huffman lencode, distcode;
    static bool ready = false;
    if (!ready) {
        short lengths[FIXLCODES];
        int sym = 0;
        for (; sym < 144; ++sym) lengths[sym] = 8;
        for (; sym < 256; ++sym) lengths[sym] = 9;
        for (; sym < 280; ++sym) lengths[sym] = 7;
        for (; sym < FIXLCODES; ++sym) lengths[sym] = 8;
        construct(lencode, lengths, FIXLCODES);
        for (sym = 0; sym < MAXDCODES; ++sym) lengths[sym] = 5;
        construct(distcode, lengths, MAXDCODES);
        ready = true;
    }
    return codes(s, lencode, distcode);
}

bool dynamic(Inflater& s) {
    static const short ORDER[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    short lengths[MAXLCODES + MAXDCODES];
    const int nlen = s.bits(5) + 257;
    const int ndist = s.bits(5) + 1;
    const int ncode = s.bits(4) + 4;
    if (s.err) return false;
    if (nlen > MAXLCODES || ndist > MAXDCODES) { s.err = R_BAD; return false; }
    int index = 0;
    for (; index < ncode; ++index) lengths[ORDER[index]] = short(s.bits(3));
    for (; index < 19; ++index) lengths[ORDER[index]] = 0;
    if (s.err) return false;
    Huffman lencode, distcode;
    if (construct(lencode, lengths, 19) != 0) { s.err = R_BAD; return false; }  // tiene que ser completo
    index = 0;
    while (index < nlen + ndist) {
        int sym = decode(s, lencode);
        if (s.err) return false;
        if (sym < 16) {
            lengths[index++] = short(sym);
        } else {
            short len = 0;
            if (sym == 16) {
                if (index == 0) { s.err = R_BAD; return false; }
                len = lengths[index - 1];
                sym = 3 + s.bits(2);
            } else if (sym == 17) {
                sym = 3 + s.bits(3);
            } else {
                sym = 11 + s.bits(7);
            }
            if (s.err) return false;
            if (index + sym > nlen + ndist) { s.err = R_BAD; return false; }
            while (sym--) lengths[index++] = len;
        }
    }
    if (lengths[256] == 0) { s.err = R_BAD; return false; }  // sin código de fin
    int e = construct(lencode, lengths, nlen);
    if (e < 0 || (e > 0 && nlen - lencode.count[0] != 1)) { s.err = R_BAD; return false; }
    e = construct(distcode, lengths + nlen, ndist);
    if (e < 0 || (e > 0 && ndist - distcode.count[0] != 1)) { s.err = R_BAD; return false; }
    return codes(s, lencode, distcode);
}

}  // namespace

Error inflate_raw(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap, size_t& out_len) {
    Inflater s{in, in_len, 0, out, out_cap, 0, 0, 0, R_OK};
    int last;
    do {
        last = s.bits(1);
        const int type = s.bits(2);
        if (s.err) break;
        bool ok;
        if (type == 0) ok = stored(s);
        else if (type == 1) ok = fixed(s);
        else if (type == 2) ok = dynamic(s);
        else { s.err = R_BAD; ok = false; }
        if (!ok) break;
    } while (!last);
    out_len = s.outcnt;
    if (s.err == R_BOMB) return E_ZIP_BOMB;
    return s.err ? E_ZIP : OK;
}

// ---------------------------------------------------------------- zip
namespace {

uint16_t u16(const uint8_t* p) { return uint16_t(p[0] | (p[1] << 8)); }
uint32_t u32(const uint8_t* p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
std::string lower(std::string s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}
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
bool valid_utf8_name(const std::string& s, bool utf8) {
    if (utf8) return valid_utf8((const uint8_t*)s.data(), s.size());
    for (unsigned char c : s)
        if (c >= 0x80) return false;  // sin la marca UTF-8, solo ASCII (como pes6pkg)
    return true;
}

}  // namespace

Error open_zip(const uint8_t* d, size_t n, std::vector<ZipEntry>& out) {
    out.clear();
    if (n > MAX_ARCHIVE) return E_TOO_BIG;
    if (n < 22) return E_ZIP;
    size_t end = size_t(-1);
    const size_t lo = n > 65557 ? n - 65557 : 0;
    for (size_t i = n - 4 + 1; i-- > lo;)
        if (d[i] == 'P' && d[i + 1] == 'K' && d[i + 2] == 5 && d[i + 3] == 6) { end = i; break; }
    if (end == size_t(-1) || end + 22 > n) return E_ZIP;
    const uint16_t disk = u16(d + end + 4), cd_disk = u16(d + end + 6), n_disk = u16(d + end + 8), cnt = u16(d + end + 10);
    const uint32_t cd_size = u32(d + end + 12), cd_off = u32(d + end + 16);
    const uint16_t clen = u16(d + end + 20);
    if (disk || cd_disk || n_disk != cnt || end + 22 + clen != n) return E_ZIP;
    if (cnt > 2000 || cnt == 0xFFFF || cd_off == 0xFFFFFFFFu) return E_ZIP;
    if (uint64_t(cd_off) + cd_size != end) return E_ZIP;
    std::vector<std::pair<size_t, size_t>> spans;
    std::vector<std::string> seen;
    size_t p = cd_off;
    for (unsigned k = 0; k < cnt; ++k) {
        if (p + 46 > end || u32(d + p) != 0x02014b50u) return E_ZIP;
        const uint16_t flags = u16(d + p + 8), method = u16(d + p + 10);
        const uint32_t crc = u32(d + p + 16), csize = u32(d + p + 20), usize = u32(d + p + 24);
        const uint16_t nlen = u16(d + p + 28), xlen = u16(d + p + 30), mlen = u16(d + p + 32), dstart = u16(d + p + 34);
        const uint32_t loff = u32(d + p + 42);
        const size_t name_at = p + 46;
        p += 46 + size_t(nlen) + xlen + mlen;
        if (p > end) return E_ZIP;
        if ((flags & 1) || dstart) return E_ZIP;  // cifrada o en otro disco
        if (csize == 0xFFFFFFFFu || usize == 0xFFFFFFFFu || loff == 0xFFFFFFFFu) return E_ZIP;  // zip64
        if (method != 0 && method != 8) return E_ZIP;
        const std::string name((const char*)d + name_at, nlen);
        if (!valid_utf8_name(name, (flags & 0x800) != 0)) return E_ZIP;
        if (uint64_t(loff) + 30 > cd_off || u32(d + loff) != 0x04034b50u) return E_ZIP;
        const uint16_t lnlen = u16(d + loff + 26), lxlen = u16(d + loff + 28);
        if (uint64_t(loff) + 30 + lnlen > n || lnlen != nlen || memcmp(d + loff + 30, d + name_at, nlen) != 0) return E_ZIP;
        const size_t doff = size_t(loff) + 30 + lnlen + lxlen;
        if (uint64_t(doff) + csize > cd_off) return E_ZIP;
        spans.emplace_back(size_t(loff), doff + csize);
        if (!name.empty() && name.back() == '/') {
            if (usize || csize > 2) return E_ZIP;
            continue;
        }
        if (!valid_path(name)) return E_PATH;
        const std::string low = lower(name);
        if (std::find(seen.begin(), seen.end(), low) != seen.end()) return E_ZIP;
        seen.push_back(low);
        if (method == 0 && csize != usize) return E_ZIP;
        ZipEntry e;
        e.name = name;
        e.method = method;
        e.crc = crc;
        e.csize = csize;
        e.usize = usize;
        e.data_offset = doff;
        out.push_back(e);
    }
    std::sort(spans.begin(), spans.end());
    for (size_t i = 1; i < spans.size(); ++i)
        if (spans[i].first < spans[i - 1].second) return E_ZIP;  // entradas superpuestas
    return OK;
}

Error read_zip_entry(const uint8_t* d, size_t n, const ZipEntry& e, uint64_t expected, std::vector<uint8_t>& out) {
    out.clear();
    if (e.usize != expected) return E_SIZE;
    if (e.data_offset + e.csize > n) return E_ZIP;
    const uint8_t* raw = d + e.data_offset;
    if (e.method == 0) {
        out.assign(raw, raw + e.csize);
    } else {
        out.resize(size_t(expected));
        size_t got = 0;
        const Error r = inflate_raw(raw, e.csize, out.data(), out.size(), got);
        if (r != OK) return r;
        out.resize(got);
    }
    if (out.size() != expected) return E_SIZE;
    if (crc32(out.data(), out.size()) != e.crc) return E_CRC;
    return OK;
}

Error check_zip(const uint8_t* d, size_t n, const PublicKey* keys, size_t key_count, const State& state,
                const char* const* allowed, size_t allowed_count, const std::vector<PackageVersion>& installed,
                std::vector<ZipPackage>& out) {
    out.clear();
    std::vector<ZipEntry> entries;
    Error e = open_zip(d, n, entries);
    if (e != OK) return e;
    auto find = [&](const std::string& low) -> const ZipEntry* {
        for (const auto& z : entries)
            if (lower(z.name) == low) return &z;
        return nullptr;
    };
    static const char PREFIX[] = "kitserver/pes6pkg/installed/";
    const size_t plen = sizeof(PREFIX) - 1;
    std::vector<const ZipEntry*> manifests;
    for (const auto& z : entries) {
        const std::string low = lower(z.name);
        if (low.compare(0, plen, PREFIX) == 0 && low.size() >= plen + 5 && low.compare(low.size() - 5, 5, ".json") == 0)
            manifests.push_back(&z);
    }
    if (manifests.empty()) return E_ZIP_MISSING;
    std::vector<std::string> used;
    for (const ZipEntry* me : manifests) {
        const ZipEntry* se = find(lower(me->name) + ".minisig");
        if (!se) return E_SIG_FORMAT;
        if (me->usize > MAX_MANIFEST || se->usize > MAX_SIG) return E_TOO_BIG;
        ZipPackage pkg;
        if ((e = read_zip_entry(d, n, *me, me->usize, pkg.manifest_bytes)) != OK) return e;
        if ((e = read_zip_entry(d, n, *se, se->usize, pkg.manifest_sig)) != OK) return e;
        if (!valid_utf8(pkg.manifest_sig.data(), pkg.manifest_sig.size())) return E_SIG_FORMAT;
        const std::string from_name = me->name.substr(plen, me->name.size() - plen - 5);
        const char* inst = nullptr;
        for (const auto& i : installed)
            if (i.package == from_name) inst = i.version.c_str();
        ManifestExpect ex;
        ex.package = from_name.c_str();
        ex.installed = inst;
        ex.allow_equal = true;
        ex.packages_allowed = allowed;
        ex.packages_allowed_count = allowed_count;
        e = check_manifest(pkg.manifest_bytes.data(), pkg.manifest_bytes.size(), (const char*)pkg.manifest_sig.data(),
                           pkg.manifest_sig.size(), keys, key_count, state, ex, pkg.manifest);
        if (e != OK) return e;
        used.push_back(lower(me->name));
        used.push_back(lower(se->name));
        for (const auto& f : pkg.manifest.files) {
            const std::string low = lower(f.path);
            const ZipEntry* ze = find(low);
            if (!ze) return E_ZIP_MISSING;
            if (std::find(used.begin(), used.end(), low) != used.end()) return E_ZIP;
            used.push_back(low);
            std::vector<uint8_t> content;
            if ((e = read_zip_entry(d, n, *ze, f.size, content)) != OK) return e;
            uint8_t h[32];
            if (!sha256(content.data(), content.size(), h)) return E_IO;
            if (memcmp(h, f.sha256, 32) != 0) return E_HASH;
            pkg.contents.push_back(std::move(content));
        }
        out.push_back(std::move(pkg));
    }
    for (const auto& z : entries)
        if (std::find(used.begin(), used.end(), lower(z.name)) == used.end()) return E_ZIP_EXTRA;
    return OK;
}

}  // namespace pes6pkg
