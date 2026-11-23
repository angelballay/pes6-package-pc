// Pruebas del verificador común: unidades + los vectores de tool/pes6pkg (los mismos que pasa el verificador de Python).
//   python -I tool\run.py --test-keys vectors --out build\vectors
//   test_client.exe build\vectors
#include "pes6pkg_client.h"

#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

using namespace pes6pkg;

static int g_fail = 0, g_ok = 0;

static void check(bool cond, const std::string& what) {
    if (cond) ++g_ok;
    else { ++g_fail; printf("FALLA: %s\n", what.c_str()); }
}

static bool slurp(const std::string& path, std::vector<uint8_t>& out) {
    out.clear();
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") || !f) return false;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
    fclose(f);
    return true;
}

static bool unhex(const std::string& s, uint8_t* out, size_t n) {
    if (s.size() != 2 * n) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned v = 0;
        if (sscanf_s(s.c_str() + 2 * i, "%2x", &v) != 1) return false;
        out[i] = uint8_t(v);
    }
    return true;
}

static std::string str(const Json& o, const char* k, const char* def = "") {
    const Json* v = o.get(k);
    return v && v->kind == Json::STRING ? v->str : def;
}
static uint64_t num(const Json& o, const char* k) {
    const Json* v = o.get(k);
    return v && v->kind == Json::INT ? v->num : 0;
}

// ---------------------------------------------------------------- unidades
static void unit_tests() {
    const uint8_t abc[] = {'a', 'b', 'c'};
    const uint8_t nine[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    check(crc32(nine, 9) == 0xCBF43926u, "crc32 de 123456789");
    uint8_t h[64];
    check(sha256(abc, 3, h) && to_hex(h, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256 de abc");
    blake2b512(abc, 3, h);
    check(to_hex(h, 64) == "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                           "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
          "blake2b-512 de abc");

    const char* good[] = {"{\"a\": [1, true, \"x\\n\\u00e9\"], \"b\": {}}", "[]", "0", "\"\"", "{\"\\/\": false}"};
    for (const char* g : good) {
        Json j;
        check(parse_json((const uint8_t*)g, strlen(g), 4, j), std::string("JSON aceptado: ") + g);
    }
    const char* bad[] = {"{\"a\": null}", "{\"a\": 1.5}", "{\"a\": -1}", "{\"a\": 1e3}", "{\"a\": 1, \"a\": 2}",
                         "\xef\xbb\xbf{}", "{}\r\n", "{\"a\": 01}", "{\"a\": \"\\x\"}", "{\"a\": \"\\ud800\"}", "{} {}",
                         "[[[[[1]]]]]", "{\"a\": \"\x01\"}", "", "{\"a\": 9007199254740993}", "{\"a\": \"\xc0\xaf\"}",
                         "{\"a\": \"\xd9\xa3\"", "{\"a\": \xd9\xa3}"};
    for (const char* b : bad) {
        Json j;
        check(!parse_json((const uint8_t*)b, strlen(b), 4, j), std::string("JSON rechazado: ") + b);
    }

    Version a, b;
    check(parse_version("1.0.2", a) && parse_version("1.0.2.0", b) && compare_versions(a, b) == 0, "1.0.2 = 1.0.2.0");
    check(parse_version("1.0.1.2", a) && parse_version("1.0.2", b) && compare_versions(a, b) < 0, "1.0.1.2 < 1.0.2");
    for (const char* v : {"1.02", "1.0.2.3.4", "", "v1", "1.65536", "1..2"})
        check(!parse_version(v, a), std::string("versión inválida: ") + v);

    for (const char* p : {"Kitserver/hdtext.exe", "dat/ru_text.afs", "README.txt"})
        check(valid_path(p), std::string("ruta válida: ") + p);
    for (const char* p : {"Kitserver/../x", "/x", "C:/x", "a\\b", "Kitserver/NUL.dll", "Kitserver/x.", "Kitserver/x ",
                          "a//b", "Kitserver/com1"})
        check(!valid_path(p), std::string("ruta inválida: ") + p);
    check(path_allowed("hdtext", "Kitserver/GDB/fonts/HD_teko.bin", true), "hdtext: fuente HD");
    check(path_allowed("hdtext", "kitserver/hdtext.EXE", true), "hdtext: mayúsculas");
    check(!path_allowed("hdtext", "Kitserver/kload.cfg", true), "hdtext: kload.cfg no");
    check(!path_allowed("hdtext", "Kitserver/hdtext.cfg", true), "hdtext: hdtext.cfg no");
    check(!path_allowed("hdtext", "Kitserver/GDB/fonts/backup/HD_x.bin", true), "hdtext: backup no");
    check(path_allowed("translation-pt-br", "dat/pt-br_text.afs", true), "pt-br");
    check(!path_allowed("translation-ru", "dat/e_text.afs", true), "ru no pisa e_text");
    check(!path_allowed("translation-ru", "Kitserver/translations.dll", true), "idioma sin la DLL");
    check(!path_allowed("hdtext", "Kitserver/pes6pkg/installed/hdtext.json", true), "pes6pkg/ solo el instalador");
    check(path_allowed("hdtext", "README.txt", false), "documento en la raíz");
    check(path_allowed("translation-ru", "Docs/translation-ru/LEEME.txt", false), "documento en su carpeta");
    check(path_allowed("translations", "docs/TRANSLATIONS/README.md", false), "Docs sin distinguir mayúsculas");
    check(!path_allowed("translation-ru", "Docs/translations/README.txt", false), "documento en otra carpeta no");
    check(!path_allowed("translation-ru", "Docs/translation-ru/sub/README.txt", false), "Docs: un solo nivel");
    check(!path_allowed("translation-ru", "Docs/translation-ru/x.dll", false), "Docs: solo .txt y .md");
    check(!path_allowed("translation-ru", "Docs/translation-ru/README.txt", true), "Docs no se instala");
    check(!path_allowed("translation-ru", "Kitserver/README.txt", false), "documento en otra carpeta del juego no");
    check(path_allowed("hdtext", "README.txt", false) && !path_allowed("hdtext", "Kitserver/README.txt", false), "docs");

    const char* const* P = DEFAULT_URL_PREFIXES;
    check(url_allowed("https://github.com/angelballay/pes6-hd-text/releases/download/v1/x.zip", P, DEFAULT_URL_PREFIX_COUNT),
          "dirección permitida");
    check(url_allowed("https://github.com/angelballay/pes6xlife-releases/releases/download/v0.1.0/x.zip", P,
                      DEFAULT_URL_PREFIX_COUNT),
          "releases de pes6xlife-mods");
    for (const char* u : {"https://example.com/x.zip", "http://github.com/angelballay/pes6-hd-text/releases/download/x",
                          "https://github.com/angelballay/pes6xlife-releases/archive/x.zip",
                          "https://github.com/angelballay/pes6-hd-text/releases/download/x.zip?y=1",
                          "https://user@github.com/angelballay/pes6-hd-text/releases/download/x"})
        check(!url_allowed(u, P, DEFAULT_URL_PREFIX_COUNT), std::string("dirección no permitida: ") + u);

    int64_t t;
    check(parse_utc("2027-03-05T21:30:00Z", t) && format_utc(t) == "2027-03-05T21:30:00Z", "fecha ida y vuelta");
    check(parse_utc("1970-01-01T00:00:00Z", t) && t == 0, "época");
    check(!parse_utc("2027-02-29T00:00:00Z", t) && parse_utc("2028-02-29T00:00:00Z", t), "bisiesto");
    check(!valid_date("2026-13-01") && valid_date("2026-12-05"), "fechas");

    State s;
    s.index_serial = 7;
    s.index_blake2b = std::string(128, 'a');
    KeyId k = {{1, 2, 3, 4, 5, 6, 7, 8}};
    s.revoked.push_back(k);
    s.last_check = "2026-12-06T18:02:11Z";
    s.announced.push_back({"hdtext", "1.0.2"});
    s.skip_notice.push_back({"hdtext", "1.0.3"});
    const std::string text = serialize_state(s);
    State r;
    check(parse_state((const uint8_t*)text.data(), text.size(), r) && r.index_serial == 7 && r.revoked.size() == 1 &&
              r.announced.size() == 1 && r.skip_notice[0].version == "1.0.3" && r.last_check == s.last_check,
          "estado ida y vuelta");
    State older;
    older.index_serial = 9;
    older.index_blake2b = std::string(128, 'b');
    merge_state(r, older);
    check(r.index_serial == 9 && r.index_blake2b == older.index_blake2b && r.revoked.size() == 1, "combinar estados");
    check(!parse_state((const uint8_t*)"{roto", 5, r), "estado roto");

    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    const std::wstring f = std::wstring(tmp) + L"pes6pkg-prueba\\sub\\estado.json";
    check(write_file_atomic(f, text.data(), text.size()), "escritura atómica");
    std::vector<uint8_t> back;
    check(read_file(f, 1 << 20, back) && std::string(back.begin(), back.end()) == text, "lectura");
    DeleteFileW(f.c_str());
}

// ---------------------------------------------------------------- red (opcional: --red)
static void network_tests() {
    static const char* const PREFIX[] = {"https://raw.githubusercontent.com/jedisct1/minisign/"};
    HttpOptions opt;
    opt.user_agent = L"pes6pkg-tests";
    opt.prefixes = PREFIX;
    opt.prefix_count = 1;
    std::vector<uint8_t> out;
    const std::string readme = "https://raw.githubusercontent.com/jedisct1/minisign/master/README.md";
    Error e = http_get(readme, 1 << 20, opt, out);
    check(e == OK && out.size() > 100, std::string("red: bajar un archivo público: ") + error_name(e));
    e = http_get(readme, 10, opt, out);
    check(e == E_TOO_BIG, std::string("red: tope de tamaño: ") + error_name(e));
    e = http_get("https://example.com/x", 1 << 20, opt, out);
    check(e == E_URL_NOT_ALLOWED, std::string("red: dirección no permitida: ") + error_name(e));
    e = http_get("https://raw.githubusercontent.com/jedisct1/minisign/master/no-existe-pes6pkg", 1 << 20, opt, out);
    check(e == E_HTTP, std::string("red: 404: ") + error_name(e));
}

// ---------------------------------------------------------------- vectores
static std::vector<PublicKey> keyring(const Json& keys, const std::string& name) {
    std::vector<PublicKey> out;
    const Json* list = keys.get(name.c_str());
    if (!list) return out;
    for (const auto& k : list->arr) {
        PublicKey pk;
        unhex(str(k, "id"), pk.id, 8);
        unhex(str(k, "key"), pk.key, 32);
        out.push_back(pk);
    }
    return out;
}

static std::vector<PackageVersion> versions(const Json& c, const char* key) {
    std::vector<PackageVersion> out;
    if (const Json* v = c.get(key))
        for (const auto& x : v->arr) out.push_back({str(x, "package"), str(x, "version")});
    return out;
}

static std::string run_case(const Json& c, const std::string& dir, const Json& keys) {
    const auto ring = keyring(keys, str(c, "keyring", "default"));
    std::vector<uint8_t> data, sig;
    const std::string file = dir + "\\" + str(c, "file");
    if (!slurp(file, data)) return "NO_FILE";
    const std::string kind = str(c, "kind");
    if (kind != "zip" && !slurp(file + ".minisig", sig)) return "NO_SIG";
    State st;
    st.index_serial = num(c, "state_serial");
    st.index_blake2b = str(c, "state_hash");
    if (const Json* rv = c.get("state_revoked"))
        for (const auto& x : rv->arr) {
            KeyId k;
            unhex(x.str, k.b, 8);
            st.revoked.push_back(k);
        }
    int64_t now = 0;
    parse_utc(str(c, "now"), now);
    Error e;
    if (kind == "index") {
        Index idx;
        e = check_index(data.data(), data.size(), (const char*)sig.data(), sig.size(), ring.data(), ring.size(), st, now,
                        num(c, "min_serial"), idx);
        if (e == OK) {
            if (const Json* er = c.get("expect_revoked")) {
                if (er->arr.size() != st.revoked.size()) return "REVOKED_MISMATCH";
                for (size_t i = 0; i < er->arr.size(); ++i)
                    if (to_hex(st.revoked[i].b, 8) != er->arr[i].str) return "REVOKED_MISMATCH";
            }
            if (c.get("expect_serial") && idx.serial != num(c, "expect_serial")) return "SERIAL_MISMATCH";
        }
    } else if (kind == "manifest" || kind == "requires") {
        ManifestExpect ex;
        const std::string pkg = str(c, "package"), ver = str(c, "version"), inst = str(c, "installed");
        if (c.get("package")) ex.package = pkg.c_str();
        if (c.get("version")) ex.version = ver.c_str();
        if (c.get("installed")) ex.installed = inst.c_str();
        if (const Json* ae = c.get("allow_equal")) ex.allow_equal = ae->b;
        Manifest m;
        e = check_manifest(data.data(), data.size(), (const char*)sig.data(), sig.size(), ring.data(), ring.size(), st, ex, m);
        if (e == OK && kind == "requires") e = check_requires(m, versions(c, "installed_versions"));
    } else if (kind == "zip") {
        std::vector<std::string> pats;
        if (const Json* al = c.get("allowed"))
            for (const auto& x : al->arr) pats.push_back(x.str);
        std::vector<const char*> pp;
        for (const auto& p : pats) pp.push_back(p.c_str());
        std::vector<ZipPackage> pkgs;
        e = check_zip(data.data(), data.size(), ring.data(), ring.size(), st, pp.data(), pp.size(),
                      versions(c, "installed_versions"), pkgs);
    } else if (kind == "signature") {
        int ki;
        std::string comment;
        e = verify_minisig(data.data(), data.size(), (const char*)sig.data(), sig.size(), ring.data(), ring.size(),
                           st.revoked, ki, comment);
        if (e == OK && comment != str(c, "expect_comment")) return "COMMENT_MISMATCH";
    } else {
        return "UNKNOWN_KIND";
    }
    return error_name(e);
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    unit_tests();
    const int units = g_ok + g_fail;
    if (argc < 2) {
        printf("Uso: test_client <carpeta de vectores>\n");
        return 2;
    }
    const std::string dir = argv[1];
    std::vector<uint8_t> raw_cases, raw_keys;
    Json cases, keys;
    if (!slurp(dir + "\\cases.json", raw_cases) || !slurp(dir + "\\keys.json", raw_keys) ||
        !parse_json(raw_cases.data(), raw_cases.size(), 8, cases) || !parse_json(raw_keys.data(), raw_keys.size(), 8, keys)) {
        printf("No pude leer los vectores de %s (pes6pkg --test-keys vectors --out ...)\n", dir.c_str());
        return 2;
    }
    const Json* list = cases.get("cases");
    size_t n = 0;
    for (const auto& c : list->arr) {
        const std::string got = run_case(c, dir, keys), want = str(c, "expect");
        check(got == want, str(c, "name") + ": esperado " + want + ", dio " + got);
        ++n;
    }
    if (argc > 2 && strcmp(argv[2], "--red") == 0) network_tests();
    printf("%d pruebas unitarias, %zu vectores: %d bien, %d fallas\n", units, n, g_ok, g_fail);
    return g_fail ? 1 : 0;
}
