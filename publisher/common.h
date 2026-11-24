// 公共基础层：字符串、错误、路径、文件、JSON、SHA-256、日志。
//
// 设计原则与 Python 来源保持一致：
//  * 所有面向用户的错误都携带中文消息 + 建议 + 稳定错误码；
//  * 文件写入一律先写临时文件再原子替换；
//  * 日志写入 %APPDATA%\WarThunderChineseModUpdater\logs；
//  * 不依赖任何第三方运行库，只使用 Windows 自带 API。
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace wtu {

// ---------------------------------------------------------------------------
// 常量（与 Python 版 wtu/__init__.py 对齐）
// ---------------------------------------------------------------------------
inline constexpr const wchar_t* kAppName = L"WTCNUP 汉化 Mod 更新器";
inline constexpr const char* kAppId = "WTCNUP";
inline constexpr const char* kVersion = "1.1.C+";
inline constexpr const wchar_t* kRepoOwner = L"1095368180";
inline constexpr const wchar_t* kRepoName = L"warthunder-improved-chinese-localisation";
inline constexpr const wchar_t* kSteamAppId = L"236390";

inline constexpr const char* kAutostartValueName = "WTCNUP";

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------
struct Error : std::runtime_error {
    std::wstring message;   // 面向用户的一句话
    std::wstring advice;    // 下一步建议
    std::string code;       // 稳定错误码
    std::string debug;      // 只写日志的技术细节

    explicit Error(std::wstring msg, std::string code_ = "UNKNOWN",
                   std::wstring advice_ = L"", std::string debug_ = std::string());

    std::wstring full_text() const;
};

// 便捷构造：带建议
inline Error MakeError(std::wstring msg, std::string code, std::wstring advice = L"",
                       std::string debug = std::string()) {
    return Error(std::move(msg), std::move(code), std::move(advice), std::move(debug));
}

// ---------------------------------------------------------------------------
// 字符串
// ---------------------------------------------------------------------------
std::wstring Utf8ToWide(const std::string& text);
std::string WideToUtf8(const std::wstring& text);

std::wstring Trim(const std::wstring& text);
std::string Trim(const std::string& text);
std::wstring ToLower(std::wstring text);
std::string ToLower(std::string text);
bool IEquals(const std::wstring& a, const std::wstring& b);
bool StartsWithI(const std::wstring& text, const std::wstring& prefix);
bool EndsWithI(const std::wstring& text, const std::wstring& suffix);
bool ContainsI(const std::wstring& text, const std::wstring& needle);
std::vector<std::wstring> SplitLines(const std::wstring& text);
std::wstring Join(const std::vector<std::wstring>& parts, const std::wstring& sep);

// 32 位十六进制小写
std::string HexLower(const std::vector<uint8_t>& data);
std::string HexLower(const uint8_t* data, size_t size);

// 8 位随机十六进制串（工作区名用）
std::string RandomHex8();

// ---------------------------------------------------------------------------
// 路径
// ---------------------------------------------------------------------------
std::wstring GetEnv(const wchar_t* name);
std::wstring AppDataDir();      // %APPDATA%\WarThunderChineseModUpdater
std::wstring ConfigPath();      // ...\config.json
std::wstring LogsDir();         // ...\logs
std::wstring LogPath();         // ...\logs\updater.log
std::wstring LastRunLogPath();  // ...\logs\last_run.log
std::wstring TempRoot();        // %TEMP%\WarThunderChineseModUpdater
std::wstring ExePath();         // 当前 EXE 绝对路径
std::wstring ExeDir();

std::wstring AbsolutePath(const std::wstring& path);
std::wstring LongPath(const std::wstring& path);
// 规范化：绝对路径、反斜杠、去尾部分隔符、小写（Windows 比较语义）
std::wstring NormalizePath(const std::wstring& path);
bool SamePath(const std::wstring& a, const std::wstring& b);
bool IsSubPath(const std::wstring& child, const std::wstring& parent);
std::wstring JoinPath(const std::wstring& base, const std::wstring& name);

// ---------------------------------------------------------------------------
// 文件系统
// ---------------------------------------------------------------------------
bool PathExists(const std::wstring& path);
bool IsDirectory(const std::wstring& path);
bool IsFile(const std::wstring& path);
void EnsureDir(const std::wstring& path);
uint64_t FileSize(const std::wstring& path);
uint64_t FreeSpace(const std::wstring& path);

bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out);
bool ReadFileUtf8(const std::wstring& path, std::string& out);
void WriteFileBytesAtomic(const std::wstring& path, const void* data, size_t size);
void WriteFileUtf8Atomic(const std::wstring& path, const std::string& text);
void CopyFileAtomic(const std::wstring& src, const std::wstring& dst);
bool RemoveFile(const std::wstring& path);
void RemoveTree(const std::wstring& path);
void ClearReadonly(const std::wstring& path);

std::string Sha256File(const std::wstring& path);
std::string Sha256Hex(const void* data, size_t size);
std::wstring HumanSize(uint64_t bytes);

// 递归枚举文件（相对路径，顺序稳定：目录/文件名排序）
struct FileEntry {
    std::vector<std::wstring> parts;  // 相对路径分量
    std::wstring full_path;
};
std::vector<FileEntry> CollectFiles(const std::wstring& root);

// ---------------------------------------------------------------------------
// 时间
// ---------------------------------------------------------------------------
std::wstring FormatTimestampLocal();     // 2026-11-16 20:41:19
std::string NowIsoLocal();               // 2026-11-16T20:41:19+08:00
std::wstring FormatIsoLocalShort(const std::string& iso_utc);  // 2026-09-16 19:51

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------
enum class LogLevel { Debug = 0, Info = 1, Warning = 2, Error = 3 };

const wchar_t* LevelName(LogLevel level);

class Logger {
public:
    static Logger& Instance();

    void Init(LogLevel level, const std::wstring& log_dir, bool to_console);
    void SetLevel(LogLevel level);
    bool initialized() const { return initialized_; }
    void Write(LogLevel level, const std::wstring& message);
    void WriteUtf8(LogLevel level, const std::string& message);
    void Close();

private:
    Logger() = default;
    void OpenFiles(const std::wstring& dir);
    void RotateIfNeeded();
    void WriteLine(const std::wstring& line, LogLevel level, bool to_file);

    CRITICAL_SECTION lock_{};
    bool lock_ready_ = false;
    bool initialized_ = false;
    bool console_ = false;
    LogLevel level_ = LogLevel::Info;
    std::wstring dir_;
    FILE* file_ = nullptr;
    FILE* last_ = nullptr;
};

void InitLogging(LogLevel level, const std::wstring& log_dir, bool to_console);
void LogMessage(LogLevel level, const std::wstring& message);
void LogUtf8(LogLevel level, const std::string& message);
void LogFormat(LogLevel level, const wchar_t* fmt, ...);

// ---------------------------------------------------------------------------
// JSON（最小实现：对象/数组/字符串/数字/布尔/null）
// ---------------------------------------------------------------------------
class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json() = default;
    Json(bool value);
    Json(int value);
    Json(int64_t value);
    Json(double value);
    Json(const char* value);
    Json(std::string value);

    static Json MakeObject();
    static Json MakeArray();

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_string() const { return type_ == Type::String; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_bool() const { return type_ == Type::Bool; }

    bool has(const std::string& key) const;
    const Json* find(const std::string& key) const;
    const Json& at(const std::string& key) const;
    Json& operator[](const std::string& key);
    const Json& operator[](const std::string& key) const;

    void set(const std::string& key, Json value);
    void push(Json value);

    size_t size() const;
    const std::vector<Json>& items() const { return array_; }
    const std::map<std::string, Json>& fields() const { return object_; }

    std::string as_string(const std::string& def = std::string()) const;
    std::wstring as_wstring(const std::wstring& def = L"") const;
    int64_t as_int(int64_t def = 0) const;
    int as_int32(int def = 0) const;
    double as_double(double def = 0.0) const;
    bool as_bool(bool def = false) const;

    std::string dump(bool pretty = true) const;
    static Json parse(const std::string& text, std::string* error = nullptr);

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    bool is_integer_ = true;
    int64_t int_ = 0;
    double double_ = 0.0;
    std::string string_;
    std::vector<Json> array_;
    std::map<std::string, Json> object_;
};

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
class Sha256 {
public:
    Sha256();
    void Update(const void* data, size_t size);
    std::string FinalHex();

private:
    void Transform(const uint8_t block[64]);

    uint32_t state_[8];
    uint64_t bit_count_;
    uint8_t buffer_[64];
    size_t buffer_size_;
};

}  // namespace wtu
