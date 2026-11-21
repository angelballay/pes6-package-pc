// pes6pkg_win.cpp: lo que usa Windows. SHA-256 con CNG (bcrypt.dll), descarga con WinHTTP (winhttp.dll), reloj UTC,
// archivos con escritura atómica y el estado en %LOCALAPPDATA%\pes6pkg\state.json (design §6, §13).
//
// En la DLL del juego conviene cargar winhttp.dll y bcrypt.dll diferidas (/DELAYLOAD:winhttp.dll /DELAYLOAD:bcrypt.dll
// delayimp.lib): si no hay consulta, ni se cargan (HDU-4).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>

#include "pes6pkg_client.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4  // Windows 8.1 o más nuevo
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

namespace pes6pkg {

bool sha256(const uint8_t* p, size_t n, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0) {
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) >= 0) {
            ok = true;
            while (ok && n > 0) {
                const ULONG k = n > 0x40000000u ? 0x40000000u : ULONG(n);
                ok = BCryptHashData(h, const_cast<PUCHAR>(p), k, 0) >= 0;
                p += k;
                n -= k;
            }
            ok = ok && BCryptFinishHash(h, out, 32, 0) >= 0;
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

int64_t now_utc() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const uint64_t t = (uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return int64_t((t - 116444736000000000ull) / 10000000ull);
}

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), int(s.size()), &w[0], n);
    return w;
}

struct Handle {
    HINTERNET h = nullptr;
    ~Handle() {
        if (h) WinHttpCloseHandle(h);
    }
};

void ensure_parent(const std::wstring& path) {
    for (size_t p = path.find(L'\\', 3); p != std::wstring::npos; p = path.find(L'\\', p + 1))
        CreateDirectoryW(path.substr(0, p).c_str(), nullptr);  // las que ya existen fallan sin importar
}

}  // namespace

Error http_get(const std::string& url, uint64_t max_size, const HttpOptions& opt, std::vector<uint8_t>& out) {
    out.clear();
    if (!url_allowed(url, opt.prefixes, opt.prefix_count)) return E_URL_NOT_ALLOWED;
    const std::wstring wurl = widen(url);
    wchar_t host[256] = {}, path[2048] = {};
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2047;
    if (wurl.empty() || !WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc) || uc.nScheme != INTERNET_SCHEME_HTTPS)
        return E_URL_NOT_ALLOWED;
    const ULONGLONG start = GetTickCount64();
    Handle s, c, r;
    s.h = WinHttpOpen(opt.user_agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s.h)  // anterior a Windows 8.1
        s.h = WinHttpOpen(opt.user_agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s.h) return E_NETWORK;
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if (!WinHttpSetOption(s.h, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
        protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;  // sistemas sin TLS 1.3
        WinHttpSetOption(s.h, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    }
    WinHttpSetTimeouts(s.h, int(opt.resolve_ms), int(opt.connect_ms), int(opt.send_ms), int(opt.receive_ms));
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(s.h, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));
    DWORD maxr = 5;
    WinHttpSetOption(s.h, WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS, &maxr, sizeof(maxr));
    c.h = WinHttpConnect(s.h, host, uc.nPort, 0);
    if (!c.h) return E_NETWORK;
    r.h = WinHttpOpenRequest(c.h, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                             WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH);
    if (!r.h) return E_NETWORK;
    DWORD features = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    WinHttpSetOption(r.h, WINHTTP_OPTION_DISABLE_FEATURE, &features, sizeof(features));
    DWORD logon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    WinHttpSetOption(r.h, WINHTTP_OPTION_AUTOLOGON_POLICY, &logon, sizeof(logon));
    if (!WinHttpSendRequest(r.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(r.h, nullptr))
        return E_NETWORK;
    DWORD status = 0, len = sizeof(status);
    if (!WinHttpQueryHeaders(r.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                             &status, &len, WINHTTP_NO_HEADER_INDEX))
        return E_HTTP;
    if (status != 200) return E_HTTP;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(r.h, &avail)) return E_NETWORK;
        if (avail == 0) break;
        if (out.size() + avail > max_size) return E_TOO_BIG;
        const size_t at = out.size();
        out.resize(at + avail);
        DWORD got = 0;
        if (!WinHttpReadData(r.h, out.data() + at, avail, &got)) return E_NETWORK;
        out.resize(at + got);
        if (GetTickCount64() - start > opt.total_ms) return E_NETWORK;  // VER-2: tope total
    }
    return OK;
}

std::wstring state_path() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    std::wstring base;
    if (n > 0 && n < MAX_PATH) {
        base = buf;
    } else {
        n = GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return std::wstring();
        base = std::wstring(buf) + L"\\AppData\\Local";
    }
    return base + L"\\pes6pkg\\state.json";
}

bool read_file(const std::wstring& path, size_t max_size, std::vector<uint8_t>& out) {
    out.clear();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size;
    bool ok = GetFileSizeEx(h, &size) && uint64_t(size.QuadPart) <= max_size;
    if (ok) {
        out.resize(size_t(size.QuadPart));
        DWORD got = 0;
        ok = out.empty() || (ReadFile(h, out.data(), DWORD(out.size()), &got, nullptr) && got == out.size());
    }
    CloseHandle(h);
    if (!ok) out.clear();
    return ok;
}

bool write_file_atomic(const std::wstring& path, const void* data, size_t n) {
    ensure_parent(path);
    const std::wstring tmp = path + L".tmp" + std::to_wstring(GetCurrentProcessId());
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    bool ok = WriteFile(h, data, DWORD(n), &w, nullptr) && w == n && FlushFileBuffers(h);
    CloseHandle(h);
    ok = ok && MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok) DeleteFileW(tmp.c_str());
    return ok;
}

void load_state(State& out) {
    std::vector<uint8_t> raw;
    const std::wstring p = state_path();
    if (p.empty() || !read_file(p, 64 * 1024, raw) || !parse_state(raw.data(), raw.size(), out)) out = State();
}

bool save_state(const State& s) {
    State cur;
    load_state(cur);  // otro cliente pudo escribir mientras tanto: se combinan (VER-10)
    merge_state(cur, s);
    const std::string text = serialize_state(cur);
    const std::wstring p = state_path();
    return !p.empty() && write_file_atomic(p, text.data(), text.size());
}

Error fetch_index(const CheckConfig& cfg, Index& out) {
    State st;
    load_state(st);
    const int64_t now = now_utc();
    st.last_check = format_utc(now);
    std::vector<uint8_t> data, sig;
    Error e = http_get(cfg.index_url, MAX_INDEX, cfg.http, data);
    if (e == OK) e = http_get(std::string(cfg.index_url) + ".minisig", MAX_SIG, cfg.http, sig);
    if (e == OK)
        e = check_index(data.data(), data.size(), (const char*)sig.data(), sig.size(), cfg.keys, cfg.key_count, st, now,
                        cfg.min_serial, out);
    // check_index solo cambia `st` si da OK; ante una falla se guarda solo la hora de la consulta (VER-12)
    save_state(st);
    return e;
}

}  // namespace pes6pkg
