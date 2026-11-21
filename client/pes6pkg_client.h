// pes6pkg_client: verificador común de los paquetes firmados de los mods de PES6 (design §5, §6, §13).
//
// Lo copian los clientes (HD Text: la DLL y hdtext.exe; después pes6xlife_mods). C++14, sin excepciones hacia afuera,
// Win32 (x86) y x64. Dependencias: Monocypher 4.0.2 (vendor/, BLAKE2b y Ed25519), WinHTTP y CNG (bcrypt) de Windows.
//
// Reglas (las mismas que tool/pes6pkg, comprobadas con los mismos vectores):
// - firma minisign "ED": Ed25519 sobre BLAKE2b-512 de los bytes tal cual, más la firma global del comentario confiable;
// - el JSON se lee recién después de comprobar la firma, y es JSON restringido (FMT-5);
// - índice: serial que solo sube, vencimiento, y la firma de una clave revoca a las anteriores (VER-4, VER-5, VER-6);
// - manifiesto: paquete, versión, rutas válidas y permitidas por paquete (FMT-8, VER-9);
// - zip: lectura estricta, cada entrada contra un manifiesto (VER-8, VER-11).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

namespace pes6pkg {

// Los nombres coinciden con los códigos de tool/pes6pkg (cases.json).
enum Error {
    OK = 0,
    E_NETWORK, E_HTTP, E_TOO_BIG, E_URL_NOT_ALLOWED,
    E_SIG_FORMAT, E_SIG_ALGORITHM, E_UNKNOWN_KEY, E_REVOKED_KEY, E_BAD_SIGNATURE, E_BAD_GLOBAL_SIGNATURE,
    E_JSON, E_TYPE, E_SCHEMA, E_FIELD, E_BAD_COMMENT, E_LIFETIME, E_EXPIRED, E_ROLLBACK, E_SAME_SERIAL,
    E_HASH, E_SIZE, E_PATH, E_PATH_NOT_ALLOWED, E_WRONG_PACKAGE, E_WRONG_VERSION, E_NOT_NEWER, E_REQUIRES,
    E_ZIP, E_ZIP_EXTRA, E_ZIP_MISSING, E_ZIP_BOMB, E_CRC, E_IO,
    E_COUNT
};
const char* error_name(Error e);

// Topes (VER-2).
const size_t MAX_INDEX = 256 * 1024;
const size_t MAX_SIG = 4 * 1024;
const size_t MAX_MANIFEST = 256 * 1024;
const size_t MAX_ARCHIVE = 256u * 1024 * 1024;

struct PublicKey {
    uint8_t id[8];  // como en el archivo de minisign
    uint8_t key[32];
};
struct KeyId {
    uint8_t b[8];
};

// ---------------------------------------------------------------- JSON restringido (FMT-5)
struct Json {
    enum Kind { NONE, OBJECT, ARRAY, STRING, INT, BOOL };
    Kind kind = NONE;
    std::string str;  // UTF-8
    uint64_t num = 0;
    bool b = false;
    std::vector<std::pair<std::string, Json>> obj;
    std::vector<Json> arr;
    const Json* get(const char* key) const;  // nullptr si no está (o no es un objeto)
};
bool parse_json(const uint8_t* p, size_t n, int max_depth, Json& out);

// ---------------------------------------------------------------- versiones, fechas, rutas, direcciones
struct Version {
    uint16_t v[4];
};
bool parse_version(const std::string& s, Version& out);  // FMT-6
int compare_versions(const Version& a, const Version& b);
bool parse_utc(const std::string& s, int64_t& unix_seconds);  // AAAA-MM-DDTHH:MM:SSZ
std::string format_utc(int64_t unix_seconds);
bool valid_date(const std::string& s);                         // AAAA-MM-DD
bool valid_path(const std::string& path);                      // FMT-8
bool path_allowed(const std::string& package, const std::string& path, bool install);  // VER-9
bool valid_url(const std::string& url);
bool url_allowed(const std::string& url, const char* const* prefixes, size_t count);  // VER-1
extern const char* const INDEX_URL;
extern const char* const DEFAULT_URL_PREFIXES[];
extern const size_t DEFAULT_URL_PREFIX_COUNT;

// ---------------------------------------------------------------- firmas minisign (FMT-1, VER-3)
struct Minisig {
    uint8_t algorithm[2];
    uint8_t key_id[8];
    uint8_t sig[64];
    std::string trusted_comment;
    uint8_t global_sig[64];
};
Error parse_minisig(const char* text, size_t n, Minisig& out);
// Comprueba `data` con su `.minisig` contra las claves embebidas no revocadas. Devuelve la posición de la clave.
Error verify_minisig(const uint8_t* data, size_t n, const char* sig, size_t sig_len, const PublicKey* keys,
                     size_t key_count, const std::vector<KeyId>& revoked, int& key_index, std::string& trusted_comment);

// ---------------------------------------------------------------- estado local (design §6, VER-10)
struct PackageVersion {
    std::string package, version;
};
struct State {
    uint64_t index_serial = 0;
    std::string index_blake2b;  // 128 hex
    std::vector<KeyId> revoked;
    std::string last_check;  // AAAA-MM-DDTHH:MM:SSZ
    std::vector<PackageVersion> announced;
    std::vector<PackageVersion> skip_notice;
    bool is_revoked(const uint8_t id[8]) const;
};
bool parse_state(const uint8_t* p, size_t n, State& out);  // false si está roto (se toma vacío)
std::string serialize_state(const State& s);
void merge_state(State& into, const State& other);  // mayor serial (con su hash), unión de revocadas, última consulta

// ---------------------------------------------------------------- índice (FMT-2, design §5.1)
struct FileRef {
    std::string url;
    uint64_t size = 0;
    uint8_t sha256[32] = {};
};
struct IndexEntry {
    std::string package, name, version, released, notes;
    FileRef manifest, archive;
};
struct Index {
    uint64_t serial = 0;
    std::string issued, expires;
    int64_t expires_unix = 0;
    std::vector<IndexEntry> packages;
    int key_index = -1;
    const IndexEntry* find(const std::string& package) const;
};
// Si da OK, `state` queda con el serial, el hash y las revocadas nuevas (hay que guardarlo con save_state).
Error check_index(const uint8_t* data, size_t n, const char* sig, size_t sig_len, const PublicKey* keys,
                  size_t key_count, State& state, int64_t now, uint64_t min_serial, Index& out);

// ---------------------------------------------------------------- manifiesto (FMT-3, VER-7)
struct ManifestFile {
    std::string path;
    uint64_t size = 0;
    uint8_t sha256[32] = {};
    bool install = true;
    bool if_absent = false;
};
struct Requirement {
    std::string package, min;
};
struct Manifest {
    std::string package, name, version, released;
    std::vector<Requirement> requires;
    std::vector<ManifestFile> files;
};
struct ManifestExpect {
    const char* package = nullptr;    // el que pidió el índice (nullptr = cualquiera)
    const char* version = nullptr;    // la que pidió el índice
    const char* installed = nullptr;  // versión instalada (nullptr = ninguna)
    bool allow_equal = false;         // igual = reparar (vía de archivo)
    const char* const* packages_allowed = nullptr;  // patrones ("translations", "translation-*"); nullptr = todos
    size_t packages_allowed_count = 0;
};
Error check_manifest(const uint8_t* data, size_t n, const char* sig, size_t sig_len, const PublicKey* keys,
                     size_t key_count, const State& state, const ManifestExpect& expect, Manifest& out);
Error check_requires(const Manifest& m, const std::vector<PackageVersion>& installed);
Error check_bytes(const uint8_t* data, size_t n, const FileRef& ref);  // tamaño y SHA-256

// ---------------------------------------------------------------- zip estricto (design §5.4)
struct ZipEntry {
    std::string name;
    uint16_t method = 0;
    uint32_t crc = 0, csize = 0, usize = 0;
    size_t data_offset = 0;
};
Error open_zip(const uint8_t* data, size_t n, std::vector<ZipEntry>& out);
Error read_zip_entry(const uint8_t* data, size_t n, const ZipEntry& e, uint64_t expected_size, std::vector<uint8_t>& out);
struct ZipPackage {
    Manifest manifest;
    std::vector<uint8_t> manifest_bytes, manifest_sig;
    std::vector<std::vector<uint8_t>> contents;  // contenido de cada manifest.files[i], comprobado
};
// Un zip con uno o varios paquetes: primero los manifiestos de Kitserver/pes6pkg/installed/ y sus firmas, después cada
// entrada. `installed`: versiones instaladas (para no bajar de versión; igual = reparar).
Error check_zip(const uint8_t* data, size_t n, const PublicKey* keys, size_t key_count, const State& state,
                const char* const* packages_allowed, size_t allowed_count, const std::vector<PackageVersion>& installed,
                std::vector<ZipPackage>& out);

// ---------------------------------------------------------------- deflate, CRC-32 y hashes
// Deflate crudo (RFC 1951). E_ZIP_BOMB si el resultado no entra en `out_cap`; E_ZIP si está roto.
Error inflate_raw(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap, size_t& out_len);
uint32_t crc32(const uint8_t* p, size_t n);
void blake2b512(const uint8_t* p, size_t n, uint8_t out[64]);
bool sha256(const uint8_t* p, size_t n, uint8_t out[32]);  // CNG (pes6pkg_win.cpp)
std::string to_hex(const uint8_t* p, size_t n);

// ---------------------------------------------------------------- Windows (pes6pkg_win.cpp)
struct HttpOptions {
    const wchar_t* user_agent = L"pes6pkg";
    uint32_t resolve_ms = 5000, connect_ms = 5000, send_ms = 5000, receive_ms = 10000, total_ms = 20000;
    const char* const* prefixes = DEFAULT_URL_PREFIXES;
    size_t prefix_count = DEFAULT_URL_PREFIX_COUNT;
};
Error http_get(const std::string& url, uint64_t max_size, const HttpOptions& opt, std::vector<uint8_t>& out);
int64_t now_utc();
std::wstring state_path();  // %LOCALAPPDATA%\pes6pkg\state.json
bool read_file(const std::wstring& path, size_t max_size, std::vector<uint8_t>& out);
bool write_file_atomic(const std::wstring& path, const void* data, size_t n);  // temporal + MoveFileExW
void load_state(State& out);         // ausente o roto = vacío
bool save_state(const State& s);     // relee, combina (merge_state) y escribe atómico

// Consulta completa del índice (design §5.1): estado, descarga, comprobación y estado nuevo guardado.
struct CheckConfig {
    const PublicKey* keys = nullptr;
    size_t key_count = 0;
    uint64_t min_serial = 0;  // el piso compilado (PRODUCTION_MIN_SERIAL)
    HttpOptions http;
    const char* index_url = INDEX_URL;
};
Error fetch_index(const CheckConfig& cfg, Index& out);

}  // namespace pes6pkg
