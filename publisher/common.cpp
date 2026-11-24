#include "common.h"

#include <bcrypt.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdarg>
#include <cstring>
#include <cwchar>
#include <random>

namespace wtu {

// ===========================================================================
// Error
// ===========================================================================
static std::string SafeUtf8(const std::wstring& text) {
    if (text.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), (int)text.size(), out.data(), n, nullptr, nullptr);
    return out;
}

Error::Error(std::wstring msg, std::string code_, std::wstring advice_, std::string debug_)
    : std::runtime_error(SafeUtf8(msg)),
      message(std::move(msg)),
      advice(std::move(advice_)),
      code(std::move(code_)),
      debug(std::move(debug_)) {}

std::wstring Error::full_text() const {
    if (advice.empty()) return message;
    return message + L"\n" + advice;
}

// ===========================================================================
// 字符串
// ===========================================================================
std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), nullptr, 0);
    if (n <= 0) n = MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), out.data(), n);
    return out;
}

std::string WideToUtf8(const std::wstring& text) { return SafeUtf8(text); }

static bool IsSpace(wchar_t ch) {
    return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n' || ch == L'\f' || ch == L'\v';
}

std::wstring Trim(const std::wstring& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && IsSpace(text[begin])) ++begin;
    while (end > begin && IsSpace(text[end - 1])) --end;
    return text.substr(begin, end - begin);
}

std::string Trim(const std::string& text) {
    size_t begin = 0;
    size_t end = text.size();
    auto space = [](unsigned char ch) { return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' || ch == '\v'; };
    while (begin < end && space((unsigned char)text[begin])) ++begin;
    while (end > begin && space((unsigned char)text[end - 1])) --end;
    return text.substr(begin, end - begin);
}

std::wstring ToLower(std::wstring text) {
    if (!text.empty()) CharLowerBuffW(text.data(), (DWORD)text.size());
    return text;
}

std::string ToLower(std::string text) {
    for (char& ch : text) {
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
    }
    return text;
}

bool IEquals(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), (int)a.size(), b.c_str(), (int)b.size(), TRUE) == CSTR_EQUAL;
}

bool StartsWithI(const std::wstring& text, const std::wstring& prefix) {
    if (prefix.size() > text.size()) return false;
    return CompareStringOrdinal(text.c_str(), (int)prefix.size(), prefix.c_str(), (int)prefix.size(), TRUE) == CSTR_EQUAL;
}

bool EndsWithI(const std::wstring& text, const std::wstring& suffix) {
    if (suffix.size() > text.size()) return false;
    return CompareStringOrdinal(text.c_str() + (text.size() - suffix.size()), (int)suffix.size(),
                                suffix.c_str(), (int)suffix.size(), TRUE) == CSTR_EQUAL;
}

bool ContainsI(const std::wstring& text, const std::wstring& needle) {
    if (needle.empty()) return true;
    std::wstring hay = ToLower(text);
    std::wstring pin = ToLower(needle);
    return hay.find(pin) != std::wstring::npos;
}

std::vector<std::wstring> SplitLines(const std::wstring& text) {
    std::vector<std::wstring> lines;
    std::wstring current;
    for (wchar_t ch : text) {
        if (ch == L'\n') {
            if (!current.empty() && current.back() == L'\r') current.pop_back();
            lines.push_back(current);
            current.clear();
        } else if (ch == L'\r') {
            // \r 单独出现：等下一个 \n 处理
        } else {
            current.push_back(ch);
        }
    }
    if (!current.empty()) lines.push_back(current);
    return lines;
}

std::wstring Join(const std::vector<std::wstring>& parts, const std::wstring& sep) {
    std::wstring out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string HexLower(const std::vector<uint8_t>& data) { return HexLower(data.data(), data.size()); }

std::string HexLower(const uint8_t* data, size_t size) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

std::string RandomHex8() {
    static std::mt19937_64 rng(std::random_device{}() ^ (uint64_t)GetTickCount64());
    uint64_t value = rng();
    static const char* kHex = "0123456789abcdef";
    std::string out(8, '0');
    for (int i = 0; i < 8; ++i) {
        out[i] = kHex[(value >> (i * 4)) & 0x0F];
    }
    return out;
}

// ===========================================================================
// 路径
// ===========================================================================
std::wstring GetEnv(const wchar_t* name) {
    DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) return std::wstring();
    std::wstring value(size, L'\0');
    DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    if (written == 0) return std::wstring();
    value.resize(written);
    return value;
}

std::wstring AppDataDir() {
    std::wstring base = GetEnv(L"APPDATA");
    if (base.empty()) base = GetEnv(L"LOCALAPPDATA");
    if (base.empty()) base = L".";
    return JoinPath(base, Utf8ToWide(kAppId));
}

std::wstring ConfigPath() { return JoinPath(AppDataDir(), L"config.json"); }
std::wstring LogsDir() { return JoinPath(AppDataDir(), L"logs"); }
std::wstring LogPath() { return JoinPath(LogsDir(), L"updater.log"); }
std::wstring LastRunLogPath() { return JoinPath(LogsDir(), L"last_run.log"); }

std::wstring TempRoot() {
    std::wstring base = GetEnv(L"TEMP");
    if (base.empty()) base = GetEnv(L"TMP");
    if (base.empty()) base = L".";
    return JoinPath(base, Utf8ToWide(kAppId));
}

std::wstring ExePath() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, buffer.data(), (DWORD)buffer.size());
        if (n == 0) return std::wstring();
        if (n < buffer.size()) {
            buffer.resize(n);
            return AbsolutePath(buffer);
        }
        buffer.resize(buffer.size() * 2);
    }
}

std::wstring ExeDir() {
    std::wstring exe = ExePath();
    size_t pos = exe.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : exe.substr(0, pos);
}

std::wstring AbsolutePath(const std::wstring& path) {
    if (path.empty()) return std::wstring();
    DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0) return path;
    std::wstring out(needed, L'\0');
    DWORD written = GetFullPathNameW(path.c_str(), needed, out.data(), nullptr);
    if (written == 0) return path;
    out.resize(written);
    return out;
}

std::wstring LongPath(const std::wstring& path) {
    std::wstring absolute = AbsolutePath(path);
    if (absolute.empty()) return absolute;
    if (absolute.rfind(L"\\\\?\\", 0) == 0) return absolute;
    if (absolute.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + absolute.substr(2);
    if (absolute.size() >= 240) return L"\\\\?\\" + absolute;
    return absolute;
}

std::wstring NormalizePath(const std::wstring& path) {
    std::wstring raw = Trim(path);
    if (raw.size() >= 2 && ((raw.front() == L'"' && raw.back() == L'"') ||
                            (raw.front() == L'\'' && raw.back() == L'\''))) {
        raw = raw.substr(1, raw.size() - 2);
    }
    if (raw.empty()) return std::wstring();

    DWORD needed = ExpandEnvironmentStringsW(raw.c_str(), nullptr, 0);
    if (needed > 1) {
        std::wstring expanded(needed, L'\0');
        DWORD written = ExpandEnvironmentStringsW(raw.c_str(), expanded.data(), needed);
        if (written > 0 && written <= needed) {
            expanded.resize(written - 1);
            raw = expanded;
        }
    }

    std::wstring resolved = AbsolutePath(raw);
    if (resolved.empty()) resolved = raw;
    std::replace(resolved.begin(), resolved.end(), L'/', L'\\');
    if (resolved.size() > 3) {
        while (!resolved.empty() && resolved.back() == L'\\') resolved.pop_back();
    }
    return ToLower(resolved);
}

bool SamePath(const std::wstring& a, const std::wstring& b) {
    if (a.empty() || b.empty()) return false;
    return NormalizePath(a) == NormalizePath(b);
}

bool IsSubPath(const std::wstring& child, const std::wstring& parent) {
    std::wstring c = NormalizePath(child);
    std::wstring p = NormalizePath(parent);
    if (c.empty() || p.empty()) return false;
    if (c == p) return true;
    if (p.back() != L'\\') p.push_back(L'\\');
    return c.rfind(p, 0) == 0;
}

std::wstring JoinPath(const std::wstring& base, const std::wstring& name) {
    if (base.empty()) return name;
    if (name.empty()) return base;
    std::wstring out = base;
    if (out.back() != L'\\' && out.back() != L'/') out.push_back(L'\\');
    size_t begin = 0;
    while (begin < name.size() && (name[begin] == L'\\' || name[begin] == L'/')) ++begin;
    out += name.substr(begin);
    return out;
}

// ===========================================================================
// 文件系统
// ===========================================================================
bool PathExists(const std::wstring& path) {
    return GetFileAttributesW(LongPath(path).c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool IsDirectory(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(LongPath(path).c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool IsFile(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(LongPath(path).c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

void EnsureDir(const std::wstring& path) {
    std::wstring absolute = AbsolutePath(path);
    if (absolute.empty()) return;
    std::wstring current;
    for (size_t i = 0; i < absolute.size(); ++i) {
        wchar_t ch = absolute[i];
        current.push_back(ch);
        bool boundary = (ch == L'\\' || ch == L'/');
        if (!boundary && i + 1 != absolute.size()) continue;
        if (boundary && current.size() <= 3) continue;  // 盘符根，例如 "C:" + 分隔符
        std::wstring directory = current;
        while (!directory.empty() && (directory.back() == L'\\' || directory.back() == L'/')) {
            directory.pop_back();
        }
        if (directory.empty()) continue;
        CreateDirectoryW(directory.c_str(), nullptr);
    }
}

uint64_t FileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(LongPath(path).c_str(), GetFileExInfoStandard, &data)) return 0;
    return ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
}

uint64_t FreeSpace(const std::wstring& path) {
    std::wstring probe = AbsolutePath(path);
    for (;;) {
        ULARGE_INTEGER free_bytes{};
        if (GetDiskFreeSpaceExW(probe.c_str(), &free_bytes, nullptr, nullptr)) return free_bytes.QuadPart;
        size_t pos = probe.find_last_of(L"\\/");
        if (pos == std::wstring::npos) return 0;
        if (pos <= 2) probe = probe.substr(0, 3);
        else probe = probe.substr(0, pos);
        if (probe.size() <= 3 && probe.back() == L'\\') break;
    }
    return 0;
}

bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
    out.clear();
    HANDLE handle = CreateFileW(LongPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size)) {
        CloseHandle(handle);
        return false;
    }
    out.resize((size_t)size.QuadPart);
    size_t done = 0;
    while (done < out.size()) {
        DWORD chunk = (DWORD)std::min<size_t>(out.size() - done, 4u * 1024u * 1024u);
        DWORD read = 0;
        if (!ReadFile(handle, out.data() + done, chunk, &read, nullptr) || read == 0) {
            CloseHandle(handle);
            out.clear();
            return false;
        }
        done += read;
    }
    CloseHandle(handle);
    return true;
}

bool ReadFileUtf8(const std::wstring& path, std::string& out) {
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(path, bytes)) return false;
    out.assign(bytes.begin(), bytes.end());
    if (out.size() >= 3 && (unsigned char)out[0] == 0xEF && (unsigned char)out[1] == 0xBB &&
        (unsigned char)out[2] == 0xBF) {
        out.erase(0, 3);
    }
    return true;
}

static Error MapWriteError(DWORD code, const std::wstring& phase, const std::wstring& path) {
    std::string detail = WideToUtf8(phase) + " failed: " + std::to_string(code) + " path=" + WideToUtf8(path);
    switch (code) {
        case 5:
            return MakeError(L"没有权限写入目标文件。", "PERMISSION_DENIED",
                             L"可尝试以管理员身份运行本程序，或把游戏安装到有写入权限的目录。", detail);
        case 32:
        case 33:
            return MakeError(L"文件正被其它程序占用。", "FILE_LOCKED",
                             L"请关闭 War Thunder、杀毒软件或其它占用该文件的程序后重试。", detail);
        case 112:
            return MakeError(L"磁盘空间不足。", "NO_SPACE", L"请清理磁盘空间后重试。", detail);
        default:
            return MakeError(L"无法写入文件。", "INSTALL", L"请检查目录权限后重试。", detail);
    }
}

void WriteFileBytesAtomic(const std::wstring& path, const void* data, size_t size) {
    std::wstring absolute = AbsolutePath(path);
    std::wstring temp = absolute + L".wtu-tmp";
    EnsureDir(absolute.substr(0, absolute.find_last_of(L'\\')));
    HANDLE handle = CreateFileW(LongPath(temp).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw MapWriteError(GetLastError(), L"CreateFile", temp);
    }
    size_t done = 0;
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    while (done < size) {
        DWORD chunk = (DWORD)std::min<size_t>(size - done, 1u << 20);
        DWORD written = 0;
        if (!WriteFile(handle, bytes + done, chunk, &written, nullptr) || written == 0) {
            DWORD err = GetLastError();
            CloseHandle(handle);
            DeleteFileW(LongPath(temp).c_str());
            throw MapWriteError(err, L"WriteFile", temp);
        }
        done += written;
    }
    FlushFileBuffers(handle);
    CloseHandle(handle);
    if (!MoveFileExW(LongPath(temp).c_str(), LongPath(absolute).c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD err = GetLastError();
        DeleteFileW(LongPath(temp).c_str());
        throw MapWriteError(err, L"MoveFileEx", absolute);
    }
}

void WriteFileUtf8Atomic(const std::wstring& path, const std::string& text) {
    WriteFileBytesAtomic(path, text.data(), text.size());
}

void CopyFileAtomic(const std::wstring& src, const std::wstring& dst) {
    std::vector<uint8_t> data;
    if (!ReadFileBytes(src, data)) {
        throw Error(L"无法读取源文件。", "INSTALL", L"请重新执行一次更新。",
                    "read failed: " + WideToUtf8(src));
    }
    WriteFileBytesAtomic(dst, data.data(), data.size());
}

bool RemoveFile(const std::wstring& path) {
    ClearReadonly(path);
    return DeleteFileW(LongPath(path).c_str()) != 0 || !PathExists(path);
}

static void RemoveTreeInner(const std::wstring& dir) {
    std::wstring pattern = JoinPath(dir, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE handle = FindFirstFileW(LongPath(pattern).c_str(), &data);
    if (handle == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") continue;
        std::wstring child = JoinPath(dir, name);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                ClearReadonly(child);
                RemoveDirectoryW(LongPath(child).c_str());
            } else {
                RemoveTreeInner(child);
            }
        } else {
            ClearReadonly(child);
            DeleteFileW(LongPath(child).c_str());
        }
    } while (FindNextFileW(handle, &data));
    FindClose(handle);
    SetFileAttributesW(LongPath(dir).c_str(), FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(LongPath(dir).c_str());
}

void RemoveTree(const std::wstring& path) {
    if (!PathExists(path)) return;
    RemoveTreeInner(path);
}

void ClearReadonly(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(LongPath(path).c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return;
    if (attrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
        SetFileAttributesW(LongPath(path).c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
    }
}

std::string Sha256File(const std::wstring& path) {
    HANDLE handle = CreateFileW(LongPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return std::string();
    Sha256 hash;
    std::vector<uint8_t> buffer(1 << 20);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(handle, buffer.data(), (DWORD)buffer.size(), &read, nullptr)) {
            CloseHandle(handle);
            return std::string();
        }
        if (read == 0) break;
        hash.Update(buffer.data(), read);
    }
    CloseHandle(handle);
    return hash.FinalHex();
}

std::string Sha256Hex(const void* data, size_t size) {
    Sha256 hash;
    hash.Update(data, size);
    return hash.FinalHex();
}

std::wstring HumanSize(uint64_t bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double value = (double)bytes;
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    wchar_t buffer[64];
    if (unit == 0) {
        swprintf(buffer, 64, L"%llu B", (unsigned long long)bytes);
    } else {
        swprintf(buffer, 64, L"%.1f %ls", value, units[unit]);
    }
    return buffer;
}

static bool CollectFilesInner(const std::wstring& root, const std::wstring& dir,
                              std::vector<std::wstring>& prefix, std::vector<FileEntry>& out) {
    std::wstring pattern = JoinPath(dir, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE handle = FindFirstFileW(LongPath(pattern).c_str(), &data);
    if (handle == INVALID_HANDLE_VALUE) return true;
    std::vector<WIN32_FIND_DATAW> entries;
    do {
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") continue;
        entries.push_back(data);
    } while (FindNextFileW(handle, &data));
    FindClose(handle);

    std::sort(entries.begin(), entries.end(), [](const WIN32_FIND_DATAW& a, const WIN32_FIND_DATAW& b) {
        return std::wstring(a.cFileName) < std::wstring(b.cFileName);
    });

    for (const auto& entry : entries) {
        std::wstring name = entry.cFileName;
        std::wstring full = JoinPath(dir, name);
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;  // 不跟随目录符号链接
            prefix.push_back(name);
            if (!CollectFilesInner(root, full, prefix, out)) return false;
            prefix.pop_back();
        } else {
            FileEntry file;
            file.parts = prefix;
            file.parts.push_back(name);
            file.full_path = full;
            out.push_back(std::move(file));
        }
    }
    return true;
}

std::vector<FileEntry> CollectFiles(const std::wstring& root) {
    std::vector<FileEntry> out;
    std::vector<std::wstring> prefix;
    CollectFilesInner(root, root, prefix, out);
    return out;
}

// ===========================================================================
// 时间
// ===========================================================================
std::wstring FormatTimestampLocal() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t buffer[64];
    swprintf(buffer, 64, L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
             st.wSecond);
    return buffer;
}

std::string NowIsoLocal() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    TIME_ZONE_INFORMATION tz{};
    DWORD zone = GetTimeZoneInformation(&tz);
    LONG bias = tz.Bias;
    if (zone == TIME_ZONE_ID_DAYLIGHT) bias += tz.DaylightBias;
    else if (zone == TIME_ZONE_ID_STANDARD) bias += tz.StandardBias;
    int offset_minutes = -(int)bias;
    char sign = offset_minutes >= 0 ? '+' : '-';
    int abs_minutes = offset_minutes >= 0 ? offset_minutes : -offset_minutes;
    char buffer[64];
    sprintf_s(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d%c%02d:%02d", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, sign, abs_minutes / 60, abs_minutes % 60);
    return buffer;
}

std::wstring FormatIsoLocalShort(const std::string& iso_utc) {
    if (iso_utc.size() < 19) return Utf8ToWide(iso_utc);
    SYSTEMTIME st{};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (sscanf_s(iso_utc.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d", &year, &month, &day, &hour, &minute, &second) != 6) {
        return Utf8ToWide(iso_utc);
    }
    st.wYear = (WORD)year;
    st.wMonth = (WORD)month;
    st.wDay = (WORD)day;
    st.wHour = (WORD)hour;
    st.wMinute = (WORD)minute;
    st.wSecond = (WORD)second;
    FILETIME ft{};
    if (!SystemTimeToFileTime(&st, &ft)) return Utf8ToWide(iso_utc);
    FILETIME local{};
    if (!FileTimeToLocalFileTime(&ft, &local)) return Utf8ToWide(iso_utc);
    SYSTEMTIME out{};
    if (!FileTimeToSystemTime(&local, &out)) return Utf8ToWide(iso_utc);
    wchar_t buffer[64];
    swprintf(buffer, 64, L"%04d-%02d-%02d %02d:%02d", out.wYear, out.wMonth, out.wDay, out.wHour, out.wMinute);
    return buffer;
}

// ===========================================================================
// SHA-256
// ===========================================================================
static const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t RotR(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

Sha256::Sha256() : bit_count_(0), buffer_size_(0) {
    state_[0] = 0x6a09e667;
    state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372;
    state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f;
    state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab;
    state_[7] = 0x5be0cd19;
}

void Sha256::Transform(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = RotR(w[i - 15], 7) ^ RotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = RotR(w[i - 2], 17) ^ RotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
        uint32_t s0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::Update(const void* data, size_t size) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    bit_count_ += (uint64_t)size * 8;
    while (size > 0) {
        size_t take = std::min<size_t>(64 - buffer_size_, size);
        memcpy(buffer_ + buffer_size_, bytes, take);
        buffer_size_ += take;
        bytes += take;
        size -= take;
        if (buffer_size_ == 64) {
            Transform(buffer_);
            buffer_size_ = 0;
        }
    }
}

std::string Sha256::FinalHex() {
    uint64_t bits = bit_count_;
    uint8_t padding = 0x80;
    Update(&padding, 1);
    uint8_t zero = 0;
    while (buffer_size_ != 56) Update(&zero, 1);
    uint8_t length[8];
    for (int i = 0; i < 8; ++i) length[i] = (uint8_t)(bits >> (56 - i * 8));
    Update(length, 8);
    std::vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = (uint8_t)(state_[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state_[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state_[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)state_[i];
    }
    return HexLower(digest);
}

// ===========================================================================
// JSON
// ===========================================================================
Json::Json(bool value) : type_(Type::Bool), bool_(value) {}
Json::Json(int value) : type_(Type::Number), int_(value) {}
Json::Json(int64_t value) : type_(Type::Number), int_(value) {}
Json::Json(double value) : type_(Type::Number), is_integer_(false), double_(value) {}
Json::Json(const char* value) : type_(Type::String), string_(value ? value : "") {}
Json::Json(std::string value) : type_(Type::String), string_(std::move(value)) {}

Json Json::MakeObject() {
    Json value;
    value.type_ = Type::Object;
    return value;
}

Json Json::MakeArray() {
    Json value;
    value.type_ = Type::Array;
    return value;
}

bool Json::has(const std::string& key) const { return type_ == Type::Object && object_.count(key) > 0; }

const Json* Json::find(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    auto it = object_.find(key);
    return it == object_.end() ? nullptr : &it->second;
}

const Json& Json::at(const std::string& key) const {
    static const Json kNull;
    const Json* found = find(key);
    return found ? *found : kNull;
}

Json& Json::operator[](const std::string& key) {
    if (type_ != Type::Object) {
        type_ = Type::Object;
    }
    return object_[key];
}

const Json& Json::operator[](const std::string& key) const { return at(key); }

void Json::set(const std::string& key, Json value) {
    type_ = Type::Object;
    object_[key] = std::move(value);
}

void Json::push(Json value) {
    type_ = Type::Array;
    array_.push_back(std::move(value));
}

size_t Json::size() const {
    if (type_ == Type::Array) return array_.size();
    if (type_ == Type::Object) return object_.size();
    return 0;
}

std::string Json::as_string(const std::string& def) const { return type_ == Type::String ? string_ : def; }

std::wstring Json::as_wstring(const std::wstring& def) const {
    return type_ == Type::String ? Utf8ToWide(string_) : def;
}

int64_t Json::as_int(int64_t def) const {
    if (type_ != Type::Number) return def;
    return is_integer_ ? int_ : (int64_t)double_;
}

int Json::as_int32(int def) const { return (int)as_int(def); }

double Json::as_double(double def) const {
    if (type_ != Type::Number) return def;
    return is_integer_ ? (double)int_ : double_;
}

bool Json::as_bool(bool def) const { return type_ == Type::Bool ? bool_ : def; }

static void DumpString(const std::string& text, std::string& out) {
    out.push_back('"');
    for (unsigned char ch : text) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buffer[8];
                    sprintf_s(buffer, sizeof(buffer), "\\u%04x", ch);
                    out += buffer;
                } else {
                    out.push_back((char)ch);
                }
        }
    }
    out.push_back('"');
}

static void DumpValue(const Json& value, bool pretty, int depth, std::string& out) {
    auto newline = [&](int indent) {
        if (!pretty) return;
        out.push_back('\n');
        out.append((size_t)indent * 2, ' ');
    };
    switch (value.type()) {
        case Json::Type::Null: out += "null"; break;
        case Json::Type::Bool: out += value.as_bool() ? "true" : "false"; break;
        case Json::Type::Number: {
            if (value.as_double() == (double)value.as_int()) {
                out += std::to_string(value.as_int());
            } else {
                char buffer[64];
                sprintf_s(buffer, sizeof(buffer), "%.17g", value.as_double());
                out += buffer;
            }
            break;
        }
        case Json::Type::String: DumpString(value.as_string(), out); break;
        case Json::Type::Array: {
            out.push_back('[');
            const auto& items = value.items();
            for (size_t i = 0; i < items.size(); ++i) {
                if (i) out.push_back(',');
                newline(depth + 1);
                DumpValue(items[i], pretty, depth + 1, out);
            }
            if (!items.empty()) newline(depth);
            out.push_back(']');
            break;
        }
        case Json::Type::Object: {
            out.push_back('{');
            bool first = true;
            for (const auto& [key, item] : value.fields()) {
                if (!first) out.push_back(',');
                first = false;
                newline(depth + 1);
                DumpString(key, out);
                out += pretty ? ": " : ":";
                DumpValue(item, pretty, depth + 1, out);
            }
            if (!value.fields().empty()) newline(depth);
            out.push_back('}');
            break;
        }
    }
}

std::string Json::dump(bool pretty) const {
    std::string out;
    DumpValue(*this, pretty, 0, out);
    return out;
}

namespace {

struct JsonParser {
    const std::string& text;
    size_t index = 0;
    std::string error;

    explicit JsonParser(const std::string& input) : text(input) {}

    void SkipWhitespace() {
        while (index < text.size()) {
            char ch = text[index];
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') ++index;
            else break;
        }
    }

    bool Fail(const char* reason) {
        if (error.empty()) error = std::string(reason) + " at offset " + std::to_string(index);
        return false;
    }

    bool ParseValue(Json& out) {
        SkipWhitespace();
        if (index >= text.size()) return Fail("unexpected end");
        char ch = text[index];
        if (ch == '{') return ParseObject(out);
        if (ch == '[') return ParseArray(out);
        if (ch == '"') {
            std::string value;
            if (!ParseString(value)) return false;
            out = Json(std::move(value));
            return true;
        }
        if (ch == 't') {
            if (text.compare(index, 4, "true") != 0) return Fail("invalid literal");
            index += 4;
            out = Json(true);
            return true;
        }
        if (ch == 'f') {
            if (text.compare(index, 5, "false") != 0) return Fail("invalid literal");
            index += 5;
            out = Json(false);
            return true;
        }
        if (ch == 'n') {
            if (text.compare(index, 4, "null") != 0) return Fail("invalid literal");
            index += 4;
            out = Json();
            return true;
        }
        return ParseNumber(out);
    }

    bool ParseObject(Json& out) {
        ++index;  // {
        out = Json::MakeObject();
        SkipWhitespace();
        if (index < text.size() && text[index] == '}') {
            ++index;
            return true;
        }
        for (;;) {
            SkipWhitespace();
            if (index >= text.size() || text[index] != '"') return Fail("expected object key");
            std::string key;
            if (!ParseString(key)) return false;
            SkipWhitespace();
            if (index >= text.size() || text[index] != ':') return Fail("expected ':'");
            ++index;
            Json value;
            if (!ParseValue(value)) return false;
            out.set(key, std::move(value));
            SkipWhitespace();
            if (index < text.size() && text[index] == ',') {
                ++index;
                continue;
            }
            if (index < text.size() && text[index] == '}') {
                ++index;
                return true;
            }
            return Fail("expected ',' or '}'");
        }
    }

    bool ParseArray(Json& out) {
        ++index;  // [
        out = Json::MakeArray();
        SkipWhitespace();
        if (index < text.size() && text[index] == ']') {
            ++index;
            return true;
        }
        for (;;) {
            Json value;
            if (!ParseValue(value)) return false;
            out.push(std::move(value));
            SkipWhitespace();
            if (index < text.size() && text[index] == ',') {
                ++index;
                continue;
            }
            if (index < text.size() && text[index] == ']') {
                ++index;
                return true;
            }
            return Fail("expected ',' or ']'");
        }
    }

    static void AppendUtf8(std::string& out, uint32_t cp) {
        if (cp <= 0x7F) {
            out.push_back((char)cp);
        } else if (cp <= 0x7FF) {
            out.push_back((char)(0xC0 | (cp >> 6)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            out.push_back((char)(0xE0 | (cp >> 12)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        } else {
            out.push_back((char)(0xF0 | (cp >> 18)));
            out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
        }
    }

    bool ParseHex4(uint32_t& value) {
        if (index + 4 > text.size()) return Fail("bad \\u escape");
        value = 0;
        for (int i = 0; i < 4; ++i) {
            char ch = text[index + i];
            uint32_t digit = 0;
            if (ch >= '0' && ch <= '9') digit = (uint32_t)(ch - '0');
            else if (ch >= 'a' && ch <= 'f') digit = (uint32_t)(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') digit = (uint32_t)(ch - 'A' + 10);
            else return Fail("bad \\u escape");
            value = (value << 4) | digit;
        }
        index += 4;
        return true;
    }

    bool ParseString(std::string& out) {
        ++index;  // "
        out.clear();
        while (index < text.size()) {
            unsigned char ch = (unsigned char)text[index];
            if (ch == '"') {
                ++index;
                return true;
            }
            if (ch == '\\') {
                ++index;
                if (index >= text.size()) return Fail("bad escape");
                char esc = text[index++];
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint32_t cp = 0;
                        if (!ParseHex4(cp)) return false;
                        if (cp >= 0xD800 && cp <= 0xDBFF && index + 6 <= text.size() && text[index] == '\\' &&
                            text[index + 1] == 'u') {
                            size_t save = index;
                            index += 2;
                            uint32_t low = 0;
                            if (!ParseHex4(low)) return false;
                            if (low >= 0xDC00 && low <= 0xDFFF) {
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            } else {
                                index = save;
                            }
                        }
                        AppendUtf8(out, cp);
                        break;
                    }
                    default: return Fail("bad escape");
                }
                continue;
            }
            if (ch < 0x20) return Fail("control character in string");
            out.push_back((char)ch);
            ++index;
        }
        return Fail("unterminated string");
    }

    bool ParseNumber(Json& out) {
        size_t begin = index;
        if (index < text.size() && (text[index] == '-' || text[index] == '+')) ++index;
        while (index < text.size() && text[index] >= '0' && text[index] <= '9') ++index;
        bool is_float = false;
        if (index < text.size() && text[index] == '.') {
            is_float = true;
            ++index;
            while (index < text.size() && text[index] >= '0' && text[index] <= '9') ++index;
        }
        if (index < text.size() && (text[index] == 'e' || text[index] == 'E')) {
            is_float = true;
            ++index;
            if (index < text.size() && (text[index] == '+' || text[index] == '-')) ++index;
            while (index < text.size() && text[index] >= '0' && text[index] <= '9') ++index;
        }
        if (index == begin) return Fail("expected value");
        std::string token = text.substr(begin, index - begin);
        try {
            if (!is_float) {
                out = Json((int64_t)std::stoll(token));
            } else {
                out = Json(std::stod(token));
            }
        } catch (...) {
            return Fail("invalid number");
        }
        return true;
    }
};

}  // namespace

Json Json::parse(const std::string& text, std::string* error) {
    JsonParser parser(text);
    Json value;
    if (!parser.ParseValue(value)) {
        if (error) *error = parser.error;
        return Json();
    }
    parser.SkipWhitespace();
    if (parser.index != text.size()) {
        if (error) *error = "trailing characters at offset " + std::to_string(parser.index);
        return Json();
    }
    return value;
}

// ===========================================================================
// 日志
// ===========================================================================
const wchar_t* LevelName(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return L"DEBUG";
        case LogLevel::Info: return L"INFO";
        case LogLevel::Warning: return L"WARNING";
        case LogLevel::Error: return L"ERROR";
    }
    return L"INFO";
}

Logger& Logger::Instance() {
    static Logger logger;
    return logger;
}

void Logger::Init(LogLevel level, const std::wstring& log_dir, bool to_console) {
    if (!lock_ready_) {
        InitializeCriticalSection(&lock_);
        lock_ready_ = true;
    }
    EnterCriticalSection(&lock_);
    level_ = level;
    console_ = to_console;
    dir_ = log_dir;
    if (!initialized_) {
        try {
            OpenFiles(log_dir);
        } catch (...) {
            file_ = nullptr;
        }
        initialized_ = true;
    }
    LeaveCriticalSection(&lock_);
}

void Logger::SetLevel(LogLevel level) {
    EnterCriticalSection(&lock_);
    level_ = level;
    LeaveCriticalSection(&lock_);
}

void Logger::OpenFiles(const std::wstring& dir) {
    EnsureDir(dir);
    RotateIfNeeded();

    std::wstring path = LogPath();
    _wfopen_s(&file_, LongPath(path).c_str(), L"ab");
    if (file_) {
        // 让 C 运行库不缓冲，崩溃时也能留下日志
        setvbuf(file_, nullptr, _IONBF, 0);
    }
    _wfopen_s(&last_, LongPath(LastRunLogPath()).c_str(), L"wb");
    if (last_) setvbuf(last_, nullptr, _IONBF, 0);
}

void Logger::RotateIfNeeded() {
    std::wstring path = LogPath();
    uint64_t size = FileSize(path);
    if (size < 1024ull * 1024ull) return;
    std::wstring fifth = path + L".5";
    DeleteFileW(LongPath(fifth).c_str());
    for (int i = 4; i >= 1; --i) {
        std::wstring from = path + L"." + std::to_wstring(i);
        std::wstring to = path + L"." + std::to_wstring(i + 1);
        MoveFileExW(LongPath(from).c_str(), LongPath(to).c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    MoveFileExW(LongPath(path).c_str(), LongPath(path + L".1").c_str(), MOVEFILE_REPLACE_EXISTING);
}

void Logger::Write(LogLevel level, const std::wstring& message) {
    if (!lock_ready_) {
        OutputDebugStringW(message.c_str());
        return;
    }
    EnterCriticalSection(&lock_);
    std::wstring line = L"[" + FormatTimestampLocal() + L"] " + message;
    if (level >= LogLevel::Warning) line += L"  <" + std::wstring(LevelName(level)) + L">";

    if (file_) {
        std::string utf8 = WideToUtf8(line) + "\n";
        fwrite(utf8.data(), 1, utf8.size(), file_);
    }
    if (last_) {
        std::string utf8 = WideToUtf8(line) + "\n";
        fwrite(utf8.data(), 1, utf8.size(), last_);
    }
    if (console_ && level >= level_) {
        HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
        DWORD mode = 0;
        if (handle && GetConsoleMode(handle, &mode)) {
            std::wstring text = line + L"\n";
            DWORD written = 0;
            WriteConsoleW(handle, text.c_str(), (DWORD)text.size(), &written, nullptr);
        } else if (handle) {
            std::string utf8 = WideToUtf8(line) + "\r\n";
            DWORD written = 0;
            WriteFile(handle, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
        }
    }
    LeaveCriticalSection(&lock_);
}

void Logger::WriteUtf8(LogLevel level, const std::string& message) { Write(level, Utf8ToWide(message)); }

void Logger::Close() {
    if (!lock_ready_) return;
    EnterCriticalSection(&lock_);
    if (file_) {
        fclose(file_);
        file_ = nullptr;
    }
    if (last_) {
        fclose(last_);
        last_ = nullptr;
    }
    LeaveCriticalSection(&lock_);
}

void InitLogging(LogLevel level, const std::wstring& log_dir, bool to_console) {
    Logger::Instance().Init(level, log_dir, to_console);
}

void LogMessage(LogLevel level, const std::wstring& message) { Logger::Instance().Write(level, message); }

void LogUtf8(LogLevel level, const std::string& message) { Logger::Instance().WriteUtf8(level, message); }

void LogFormat(LogLevel level, const wchar_t* fmt, ...) {
    wchar_t buffer[4096];
    va_list args;
    va_start(args, fmt);
    vswprintf(buffer, 4096, fmt, args);
    va_end(args);
    Logger::Instance().Write(level, buffer);
}

}  // namespace wtu
