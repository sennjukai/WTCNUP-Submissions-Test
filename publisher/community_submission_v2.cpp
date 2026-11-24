#include "community_submission_v2.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <ctime>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <unistd.h>
#endif

namespace wtu::v2 {
namespace {

constexpr uint64_t kMaxFileBytes = 10ull * 1024 * 1024;
constexpr uint64_t kMaxTotalBytes = 50ull * 1024 * 1024;
constexpr size_t kMaxFiles = 300;
constexpr size_t kMaxPathUnits = 240;
constexpr size_t kMaxSegmentUnits = 120;
constexpr size_t kMaxDepth = 10;
constexpr int kMaxAuthor = 100;
constexpr int kMaxProjectName = 200;
constexpr int kMaxVersion = 100;
constexpr int kMaxChangelog = 10000;

// ---------------------------------------------------------------------------
// SHA-256 (portable; isolated so this core does not pull in common.cpp/Win32)
// ---------------------------------------------------------------------------
constexpr uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t RotR(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

class Sha256 {
public:
    Sha256() : bit_count_(0), buffer_size_(0) {
        state_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    }

    void Update(const void* data, size_t size) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        bit_count_ += static_cast<uint64_t>(size) * 8;
        while (size > 0) {
            const size_t take = std::min<size_t>(64 - buffer_size_, size);
            std::memcpy(buffer_ + buffer_size_, bytes, take);
            buffer_size_ += take;
            bytes += take;
            size -= take;
            if (buffer_size_ == 64) {
                Transform(buffer_);
                buffer_size_ = 0;
            }
        }
    }

    std::string FinalHex() {
        const uint64_t bits = bit_count_;
        uint8_t padding = 0x80;
        Update(&padding, 1);
        uint8_t zero = 0;
        while (buffer_size_ != 56) Update(&zero, 1);
        uint8_t length[8];
        for (int i = 0; i < 8; ++i) length[i] = static_cast<uint8_t>(bits >> (56 - i * 8));
        Update(length, 8);
        std::string result;
        static const char* hex = "0123456789abcdef";
        for (uint32_t word : state_) {
            for (int shift = 28; shift >= 0; shift -= 4) {
                result.push_back(hex[(word >> shift) & 0x0f]);
            }
        }
        return result;
    }

private:
    void Transform(const uint8_t block[64]) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = RotR(w[i - 15], 7) ^ RotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = RotR(w[i - 2], 17) ^ RotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t s1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
            const uint32_t s0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = s0 + maj;
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

    std::array<uint32_t, 8> state_{};
    uint64_t bit_count_ = 0;
    uint8_t buffer_[64]{};
    size_t buffer_size_ = 0;
};

// ---------------------------------------------------------------------------
// UTF-8 / JSON helpers
// ---------------------------------------------------------------------------
bool DecodeUtf8(const std::string& text, std::vector<uint32_t>* out) {
    out->clear();
    size_t i = 0;
    while (i < text.size()) {
        const uint8_t first = static_cast<uint8_t>(text[i]);
        uint32_t cp = 0;
        size_t extra = 0;
        if (first < 0x80) {
            cp = first;
            extra = 0;
        } else if ((first & 0xe0) == 0xc0) {
            cp = first & 0x1f;
            extra = 1;
        } else if ((first & 0xf0) == 0xe0) {
            cp = first & 0x0f;
            extra = 2;
        } else if ((first & 0xf8) == 0xf0) {
            cp = first & 0x07;
            extra = 3;
        } else {
            return false;
        }
        if (i + extra >= text.size()) return false;
        for (size_t k = 1; k <= extra; ++k) {
            const uint8_t next = static_cast<uint8_t>(text[i + k]);
            if ((next & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (next & 0x3f);
        }
        if ((extra == 1 && cp < 0x80) || (extra == 2 && cp < 0x800) ||
            (extra == 3 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff)) {
            return false;
        }
        out->push_back(cp);
        i += extra + 1;
    }
    return true;
}

bool IsValidUtf8(const std::string& text) {
    std::vector<uint32_t> cps;
    return DecodeUtf8(text, &cps);
}

size_t CodePointCount(const std::string& text) {
    std::vector<uint32_t> cps;
    return DecodeUtf8(text, &cps) ? cps.size() : 0;
}

size_t Utf16Units(const std::string& text) {
    std::vector<uint32_t> cps;
    if (!DecodeUtf8(text, &cps)) return std::numeric_limits<size_t>::max();
    size_t units = 0;
    for (uint32_t cp : cps) units += cp > 0xffff ? 2 : 1;
    return units;
}

bool HasControl(const std::string& text, bool allow_line_breaks) {
    for (unsigned char ch : text) {
        if (ch < 0x20 || ch == 0x7f) {
            if (allow_line_breaks && (ch == '\n' || ch == '\r' || ch == '\t')) continue;
            return true;
        }
    }
    return false;
}

std::string TrimAscii(const std::string& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin]))) ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) --end;
    return text.substr(begin, end - begin);
}

std::string JsonEscape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    static const char* hex = "0123456789abcdef";
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
                    out += "\\u00";
                    out.push_back(hex[ch >> 4]);
                    out.push_back(hex[ch & 0x0f]);
                } else {
                    out.push_back(static_cast<char>(ch));
                }
        }
    }
    return out;
}

bool Fail(SubmissionV2Error* error, const char* code, const char* field, const char* message) {
    if (error) {
        error->code = code;
        error->field = field;
        error->message = message;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Field/path/UUID/time validation
// ---------------------------------------------------------------------------
bool ValidateText(const std::string& value, int max_chars, bool allow_empty,
                  bool allow_line_breaks, SubmissionV2Error* error,
                  const char* field, const char* code) {
    if (!IsValidUtf8(value)) return Fail(error, code, field, "must be valid UTF-8");
    if (HasControl(value, allow_line_breaks)) return Fail(error, code, field, "contains control characters");
    if (!allow_empty && TrimAscii(value).empty()) return Fail(error, code, field, "must not be empty");
    if (CodePointCount(value) > static_cast<size_t>(max_chars)) {
        return Fail(error, code, field, "is too long");
    }
    return true;
}

bool IsGithubLogin(const std::string& value) {
    if (value.empty() || value.size() > 39) return false;
    if (!std::isalnum(static_cast<unsigned char>(value.front()))) return false;
    if (!std::isalnum(static_cast<unsigned char>(value.back()))) return false;
    for (unsigned char ch : value) {
        if (!(std::isalnum(ch) || ch == '-')) return false;
    }
    return true;
}

bool IsProjectId(const std::string& value) {
    if (value.empty() || value.size() > 64) return false;
    if (!(value.front() >= 'a' && value.front() <= 'z') &&
        !(value.front() >= '0' && value.front() <= '9')) return false;
    for (unsigned char ch : value) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) return false;
    }
    return true;
}

bool IsLowerHex64(const std::string& value) {
    if (value.size() != 64) return false;
    for (unsigned char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    return true;
}

bool IsUuidV4(const std::string& value) {
    if (value.size() != 36) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return value[14] == '4' && (value[19] == '8' || value[19] == '9' ||
                                value[19] == 'a' || value[19] == 'b');
}

bool IsDigit(char ch) { return ch >= '0' && ch <= '9'; }

bool ValidTimestamp(const std::string& value) {
    if (value.size() < 20 || value.size() > 27) return false;
    if (value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
        value[13] != ':' || value[16] != ':') return false;
    for (size_t i : {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18}) {
        if (!IsDigit(value[i])) return false;
    }
    size_t pos = 19;
    if (pos < value.size() && value[pos] == '.') {
        ++pos;
        size_t digits = 0;
        while (pos < value.size() && IsDigit(value[pos])) {
            ++pos;
            ++digits;
        }
        if (digits < 1 || digits > 6) return false;
    }
    if (pos >= value.size() || value[pos] != 'Z' || pos + 1 != value.size()) return false;

    const int year = std::stoi(value.substr(0, 4));
    const int month = std::stoi(value.substr(5, 2));
    const int day = std::stoi(value.substr(8, 2));
    const int hour = std::stoi(value.substr(11, 2));
    const int minute = std::stoi(value.substr(14, 2));
    const int second = std::stoi(value.substr(17, 2));
    if (year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int max_day = days[month - 1];
    if (month == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)) max_day = 29;
    return day >= 1 && day <= max_day;
}

#if defined(_WIN32)
bool Utf8ToWideString(const std::string& text, std::wstring* out) {
    out->clear();
    if (text.empty()) return true;
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                          static_cast<int>(text.size()), nullptr, 0);
    if (count <= 0) return false;
    out->assign(static_cast<size_t>(count), L'\0');
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                               static_cast<int>(text.size()), out->data(), count) == count;
}

bool WideToUtf8String(const std::wstring& text, std::string* out) {
    out->clear();
    if (text.empty()) return true;
    const int count = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                          static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) return false;
    out->assign(static_cast<size_t>(count), '\0');
    return WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                               out->data(), count, nullptr, nullptr) == count;
}

bool NormalizeUtf8(const std::string& text, NORM_FORM form, std::string* out) {
    std::wstring wide;
    if (!Utf8ToWideString(text, &wide)) return false;
    int needed = NormalizeString(form, wide.data(), static_cast<int>(wide.size()), nullptr, 0);
    if (needed <= 0) return false;
    std::wstring normalized(static_cast<size_t>(needed), L'\0');
    const int written = NormalizeString(form, wide.data(), static_cast<int>(wide.size()),
                                        normalized.data(), needed);
    if (written <= 0) return false;
    normalized.resize(static_cast<size_t>(written));
    return WideToUtf8String(normalized, out);
}

#endif

bool IsNfcPath(const std::string& path) {
#if defined(_WIN32)
    std::string normalized;
    return NormalizeUtf8(path, NormalizationC, &normalized) && normalized == path;
#else
    // Without a Unicode normalization dependency the portable core fails
    // closed for non-ASCII; ASCII is trivially NFC.
    return IsValidUtf8(path) && std::all_of(path.begin(), path.end(),
                                            [](unsigned char ch) { return ch < 0x80; });
#endif
}

void AppendUtf8(uint32_t cp, std::string* out) {
    if (cp <= 0x7f) {
        out->push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ff) {
        out->push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        out->push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out->push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

std::string ApplyCaseFoldSpecials(const std::string& text) {
    std::vector<uint32_t> cps;
    if (!DecodeUtf8(text, &cps)) return std::string();
    std::string out;
    for (uint32_t cp : cps) {
        // Windows' invariant case mapping does not implement Unicode casefold
        // for these code points; the v2 oracle does.
        if (cp == 0x00df || cp == 0x1e9e) {  // ß / ẞ
            out += "ss";
        } else if (cp == 0x0130) {  // İ -> i + combining dot
            out += "i";
            out += "\xCC\x87";
        } else {
            AppendUtf8(cp, &out);
        }
    }
    return out;
}

std::string PathCollisionKey(const std::string& path) {
#if defined(_WIN32)
    std::string normalized;
    if (!NormalizeUtf8(path, NormalizationKC, &normalized)) return std::string();
    normalized = ApplyCaseFoldSpecials(normalized);
    std::wstring wide;
    if (!Utf8ToWideString(normalized, &wide)) return std::string();
    std::wstring upper(wide.size() + 8, L'\0');
    int n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, wide.data(),
                          static_cast<int>(wide.size()), upper.data(),
                          static_cast<int>(upper.size()), nullptr, nullptr, 0);
    if (n <= 0) return std::string();
    upper.resize(static_cast<size_t>(n));
    std::wstring lower(upper.size() + 8, L'\0');
    n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, upper.data(),
                      static_cast<int>(upper.size()), lower.data(),
                      static_cast<int>(lower.size()), nullptr, nullptr, 0);
    if (n <= 0) return std::string();
    lower.resize(static_cast<size_t>(n));
    std::string result;
    return WideToUtf8String(lower, &result) ? result : std::string();
#else
    if (!IsValidUtf8(path) || !std::all_of(path.begin(), path.end(),
                                           [](unsigned char ch) { return ch < 0x80; })) {
        return std::string();
    }
    std::string result = path;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return result;
#endif
}

bool IsReservedName(const std::string& segment) {
    std::string base = segment.substr(0, segment.find('.'));
    std::transform(base.begin(), base.end(), base.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    static const char* reserved[] = {"con", "prn", "aux", "nul", "conin$", "conout$",
                                     "com1", "com2", "com3", "com4", "com5", "com6",
                                     "com7", "com8", "com9", "lpt1", "lpt2", "lpt3",
                                     "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
    for (const char* item : reserved) {
        if (base == item) return true;
    }
    return false;
}

bool ValidateRelativePath(const std::string& path, SubmissionV2Error* error) {
    auto path_fail = [&](const char* message) {
        return Fail(error, "COMMUNITY_V2_PATH", "files.path", message);
    };
    if (path.empty()) return path_fail("path must not be empty");
    if (!IsValidUtf8(path)) return path_fail("path must be valid UTF-8");
    if (!IsNfcPath(path)) return path_fail("path must use NFC");
    if (Utf16Units(path) > kMaxPathUnits) return path_fail("path is too long");
    if (path.front() == '/' || path.find('\\') != std::string::npos ||
        path.find(':') != std::string::npos) {
        return path_fail("path must be relative and use '/'");
    }
    if (path.find("//") != std::string::npos) return path_fail("path contains an empty segment");

    size_t start = 0;
    size_t depth = 0;
    while (start <= path.size()) {
        const size_t slash = path.find('/', start);
        const std::string segment = path.substr(start, slash == std::string::npos
                                                           ? std::string::npos
                                                           : slash - start);
        if (segment.empty() || segment == "." || segment == "..") {
            return path_fail("path contains an empty, . or .. segment");
        }
        if (Utf16Units(segment) > kMaxSegmentUnits) return path_fail("path segment is too long");
        if (segment.back() == ' ' || segment.back() == '.') {
            return path_fail("path segment must not end with a space or dot");
        }
        for (unsigned char ch : segment) {
            if (ch < 0x20 || ch == 0x7f || ch == '<' || ch == '>' || ch == '"' ||
                ch == '|' || ch == '?' || ch == '*') {
                return path_fail("path contains an invalid character");
            }
        }
        if (IsReservedName(segment)) return path_fail("path uses a Windows reserved name");
        ++depth;
        if (depth > kMaxDepth) return path_fail("path is too deep");
        if (slash == std::string::npos) break;
        start = slash + 1;
    }

    const size_t slash = path.find_last_of('/');
    const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    const size_t dot = name.find('.');
    if (dot == std::string::npos || dot == 0 || name.find('.', dot + 1) != std::string::npos) {
        return path_fail("only exact lowercase .csv/.blk is allowed");
    }
    const std::string ext = name.substr(dot);
    if (ext != ".csv" && ext != ".blk") {
        return path_fail("only exact lowercase .csv/.blk is allowed");
    }
    return true;
}

std::filesystem::path PathFromUtf8(const std::string& path) {
#if defined(__cpp_char8_t)
    return std::filesystem::path(
        std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size()));
#else
    return std::filesystem::u8path(path);
#endif
}

bool RandomBytes(uint8_t* out, size_t size) {
#if defined(_WIN32)
    return BCryptGenRandom(nullptr, out, static_cast<ULONG>(size),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(__linux__)
    size_t done = 0;
    while (done < size) {
        const ssize_t n = getrandom(out + done, size - done, 0);
        if (n < 0) {
            std::ifstream urandom("/dev/urandom", std::ios::binary);
            if (!urandom) return false;
            urandom.read(reinterpret_cast<char*>(out + done), static_cast<std::streamsize>(size - done));
            return urandom.gcount() == static_cast<std::streamsize>(size - done);
        }
        done += static_cast<size_t>(n);
    }
    return true;
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) return false;
    urandom.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(size));
    return urandom.gcount() == static_cast<std::streamsize>(size);
#endif
}

}  // namespace

bool ValidatePathV2(const std::string& path, SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    return ValidateRelativePath(path, error);
}

std::string PathCollisionKeyV2(const std::string& path) {
    return PathCollisionKey(path);
}

std::string Sha256HexV2(const void* data, size_t size) {
    Sha256 hash;
    hash.Update(data, size);
    return hash.FinalHex();
}

std::string Sha256FileHexV2(const std::string& utf8_path, bool* ok) {
    std::ifstream file(PathFromUtf8(utf8_path), std::ios::binary);
    if (!file) {
        if (ok) *ok = false;
        return std::string();
    }
    Sha256 hash;
    std::array<char, 64 * 1024> buffer{};
    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = file.gcount();
        if (got > 0) hash.Update(buffer.data(), static_cast<size_t>(got));
    }
    if (!file.eof()) {
        if (ok) *ok = false;
        return std::string();
    }
    if (ok) *ok = true;
    return hash.FinalHex();
}

std::string UtcNowV2() {
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buffer;
}

std::string GenerateSubmissionUidV4() {
    uint8_t bytes[16]{};
    if (!RandomBytes(bytes, sizeof(bytes))) {
        throw std::runtime_error("cryptographic random source unavailable");
    }
    bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0f) | 0x40);
    bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3f) | 0x80);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        out.push_back(hex[bytes[i] >> 4]);
        out.push_back(hex[bytes[i] & 0x0f]);
    }
    return out;
}

bool HasArchiveMagic(const uint8_t* data, size_t size) {
    static const uint8_t kPk1[] = {0x50, 0x4b, 0x03, 0x04};
    static const uint8_t kPk2[] = {0x50, 0x4b, 0x05, 0x06};
    static const uint8_t kPk3[] = {0x50, 0x4b, 0x07, 0x08};
    static const uint8_t kRar[] = {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07};
    static const uint8_t k7z[] = {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c};
    static const uint8_t kGz[] = {0x1f, 0x8b};
    auto starts = [&](const uint8_t* sig, size_t n) {
        return size >= n && std::memcmp(data, sig, n) == 0;
    };
    return starts(kPk1, sizeof(kPk1)) || starts(kPk2, sizeof(kPk2)) ||
           starts(kPk3, sizeof(kPk3)) || starts(kRar, sizeof(kRar)) ||
           starts(k7z, sizeof(k7z)) || starts(kGz, sizeof(kGz)) ||
           (size >= 2 && data[0] == 'M' && data[1] == 'Z');
}

bool IsCsvStructureValid(const uint8_t* data, size_t size, char delimiter) {
    int rows = 0;
    int columns = 1;
    int first_width = -1;
    bool in_quotes = false;
    bool field_start = true;
    bool row_has_data = false;
    bool file_has_data = false;
    auto end_row = [&]() {
        if (columns < 2 || columns > 4096) return false;
        if (first_width < 0) first_width = columns;
        else if (columns != first_width) return false;
        if (row_has_data) file_has_data = true;
        ++rows;
        columns = 1;
        field_start = true;
        row_has_data = false;
        return true;
    };
    for (size_t i = 0; i < size; ++i) {
        const uint8_t ch = data[i];
        if (ch == 0 || (ch < 0x20 && ch != '\t' && ch != '\r' && ch != '\n') || ch == 0x7f) {
            return false;
        }
        if (in_quotes) {
            if (ch == '"') {
                if (i + 1 < size && data[i + 1] == '"') ++i;
                else in_quotes = false;
            }
            row_has_data = true;
            continue;
        }
        if (ch == '"') {
            if (field_start) {
                in_quotes = true;
                field_start = false;
            } else {
                row_has_data = true;
            }
        } else if (ch == static_cast<uint8_t>(delimiter)) {
            ++columns;
            field_start = true;
        } else if (ch == '\r' || ch == '\n') {
            if (ch == '\r' && i + 1 < size && data[i + 1] == '\n') ++i;
            if (!end_row()) return false;
        } else {
            field_start = false;
            row_has_data = true;
        }
    }
    if (in_quotes) return false;
    if (columns > 1 || row_has_data) {
        if (!end_row()) return false;
    }
    return rows > 0 && file_has_data;
}

bool IsBlkStructureValid(const uint8_t* data, size_t size) {
    size_t begin = 0;
    if (size >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf) begin = 3;
    if (begin >= size) return false;
    std::string text(reinterpret_cast<const char*>(data + begin), size - begin);
    std::vector<uint32_t> cps;
    if (!DecodeUtf8(text, &cps)) return false;
    bool non_space = false;
    for (uint32_t cp : cps) {
        if (cp == 0 || (cp < 0x20 && cp != 0x09 && cp != 0x0a && cp != 0x0d) || cp == 0x7f) {
            return false;
        }
        if (!(cp == ' ' || cp == '\t' || cp == '\r' || cp == '\n' || cp == '\f' || cp == '\v')) {
            non_space = true;
        }
    }
    return non_space;
}

bool ReadFileBytesV2(const std::string& path, std::vector<uint8_t>* out) {
    std::ifstream file(PathFromUtf8(path), std::ios::binary);
    if (!file) return false;
    out->clear();
    std::array<char, 64 * 1024> buffer{};
    while (file) {
        file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = file.gcount();
        if (got > 0) out->insert(out->end(), buffer.begin(), buffer.begin() + got);
        if (out->size() > kMaxFileBytes) return false;
    }
    return file.eof();
}

bool ValidateSubmissionMetadataV2(const SubmissionMetadataV2& metadata,
                                  const SubmissionScanV2& scan,
                                  SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    if (metadata.schema_version != 2) {
        return Fail(error, "COMMUNITY_V2_SCHEMA", "schema_version", "must be integer 2");
    }
    if (!IsUuidV4(metadata.submission_uid)) {
        return Fail(error, "COMMUNITY_V2_UID", "submission_uid", "must be lowercase UUID v4");
    }
    if (!ValidateText(metadata.author_name, kMaxAuthor, false, false, error,
                      "author_name", "COMMUNITY_V2_AUTHOR")) return false;
    if (!IsGithubLogin(metadata.github_user)) {
        return Fail(error, "COMMUNITY_V2_GITHUB_USER", "github_user", "invalid GitHub login");
    }
    if (metadata.project_id.has_value() && !IsProjectId(*metadata.project_id)) {
        return Fail(error, "COMMUNITY_V2_PROJECT_ID", "project_id", "invalid project_id");
    }
    if (!ValidateText(metadata.project_name, kMaxProjectName, false, false, error,
                      "project_name", "COMMUNITY_V2_PROJECT_NAME")) return false;
    if (!ValidateText(metadata.game_version, kMaxVersion, false, false, error,
                      "game_version", "COMMUNITY_V2_GAME_VERSION")) return false;
    if (!ValidateText(metadata.translation_version, kMaxVersion, false, false, error,
                      "translation_version", "COMMUNITY_V2_TRANSLATION_VERSION")) return false;
    if (metadata.channel != "stable" && metadata.channel != "beta") {
        return Fail(error, "COMMUNITY_V2_CHANNEL", "channel", "must be stable or beta");
    }
    if (!metadata.changelog.has_value()) {
        return Fail(error, "COMMUNITY_V2_CHANGELOG", "changelog", "is required");
    }
    if (!ValidateText(*metadata.changelog, kMaxChangelog, true, true, error,
                      "changelog", "COMMUNITY_V2_CHANGELOG")) return false;
    if (!ValidTimestamp(metadata.created_at)) {
        return Fail(error, "COMMUNITY_V2_CREATED_AT", "created_at", "invalid RFC3339 UTC timestamp");
    }
    if (scan.files.empty() || scan.files.size() > kMaxFiles) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "must contain 1..300 files");
    }
    if (scan.file_count != scan.files.size()) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "file_count", "does not match files length");
    }
    uint64_t declared_total = 0;
    std::set<std::string> seen;
    std::map<std::string, std::string> prefixes;
    for (const SubmissionFileV2& file : scan.files) {
        if (!ValidateRelativePath(file.path, error)) return false;
        const std::string key = PathCollisionKey(file.path);
        if (key.empty()) {
            return Fail(error, "COMMUNITY_V2_PATH", "files.path", "cannot normalize path");
        }
        if (!seen.insert(key).second) {
            return Fail(error, "COMMUNITY_V2_PATH", "files.path", "duplicate or colliding path");
        }
        size_t start = 0;
        while (start <= file.path.size()) {
            const size_t slash = file.path.find('/', start);
            const std::string prefix = file.path.substr(
                start, slash == std::string::npos ? std::string::npos : slash - start);
            const std::string prefix_key = PathCollisionKey(prefix);
            if (prefix_key.empty()) {
                return Fail(error, "COMMUNITY_V2_PATH", "files.path", "cannot normalize path prefix");
            }
            auto existing = prefixes.find(prefix_key);
            if (existing != prefixes.end() && existing->second != prefix) {
                return Fail(error, "COMMUNITY_V2_PATH", "files.path", "path prefix collision");
            }
            prefixes[prefix_key] = prefix;
            if (slash == std::string::npos) break;
            start = slash + 1;
        }
        if (file.size > kMaxFileBytes) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files.size", "file is too large");
        }
        if (!IsLowerHex64(file.sha256)) {
            return Fail(error, "COMMUNITY_V2_HASH", "files.sha256", "invalid SHA-256 format");
        }
        declared_total += file.size;
        if (declared_total > kMaxTotalBytes) {
            return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "payload is too large");
        }
    }
    if (scan.total_size != declared_total) {
        return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "does not match file sizes");
    }
    return true;
}

bool ValidateSubmissionV2Local(const SubmissionMetadataV2& metadata,
                               const SubmissionScanV2& scan,
                               SubmissionV2Error* error) {
    if (!ValidateSubmissionMetadataV2(metadata, scan, error)) return false;
    uint64_t actual_total = 0;
    for (const SubmissionFileV2& file : scan.files) {
        if (file.full_path.empty()) {
            return Fail(error, "COMMUNITY_V2_PATH", "files.full_path", "missing local file path");
        }
        std::error_code ec;
        const std::filesystem::path path = PathFromUtf8(file.full_path);
        const std::filesystem::file_status symlink = std::filesystem::symlink_status(path, ec);
        if (ec || symlink.type() == std::filesystem::file_type::not_found) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files.full_path", "local file does not exist");
        }
        if (std::filesystem::is_symlink(symlink)) {
            return Fail(error, "COMMUNITY_V2_PATH", "files.full_path", "symbolic links are not allowed");
        }
        if (!std::filesystem::is_regular_file(symlink)) {
            return Fail(error, "COMMUNITY_V2_PATH", "files.full_path", "not a regular file");
        }
        const uint64_t actual_size = std::filesystem::file_size(path, ec);
        if (ec) return Fail(error, "COMMUNITY_V2_SIZE", "files.size", "cannot read file size");
        if (actual_size != file.size) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files.size", "does not match actual file size");
        }
        std::vector<uint8_t> bytes;
        if (!ReadFileBytesV2(file.full_path, &bytes) || bytes.size() != file.size) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files.size", "cannot read exact file bytes");
        }
        if (!ValidatePayloadV2(file.path, bytes.data(), bytes.size(), error)) return false;
        if (Sha256HexV2(bytes.data(), bytes.size()) != file.sha256) {
            return Fail(error, "COMMUNITY_V2_HASH", "files.sha256", "does not match actual file");
        }
        actual_total += actual_size;
        if (actual_total > kMaxTotalBytes) {
            return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "payload is too large");
        }
    }
    if (actual_total != scan.total_size) {
        return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "does not match actual file sum");
    }
    return true;
}

bool ValidatePayloadV2(const std::string& path, const void* data, size_t size,
                       SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    if (!ValidateRelativePath(path, error)) return false;
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    if (size == 0) return Fail(error, "COMMUNITY_V2_SIZE", "files.size", "payload is empty");
    if (HasArchiveMagic(bytes, size)) {
        return Fail(error, "COMMUNITY_V2_PAYLOAD", "files.path", "archive or executable signature");
    }
    const size_t slash = path.find_last_of('/');
    const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    const std::string ext = name.substr(name.find('.'));
    if (ext == ".blk") {
        if (!IsBlkStructureValid(bytes, size)) {
            return Fail(error, "COMMUNITY_V2_BLK", "files.path", "invalid BLK content");
        }
        return true;
    }
    if (!IsCsvStructureValid(bytes, size, ',') && !IsCsvStructureValid(bytes, size, ';')) {
        return Fail(error, "COMMUNITY_V2_CSV", "files.path", "invalid CSV content");
    }
    return true;
}

std::string BuildSubmissionJsonV2(const SubmissionMetadataV2& metadata,
                                  const SubmissionScanV2& scan,
                                  ProjectIdOutput project_id_output,
                                  SubmissionV2Error* error) {
    if (!ValidateSubmissionV2Local(metadata, scan, error)) return std::string();

    std::vector<SubmissionFileV2> files = scan.files;
    std::sort(files.begin(), files.end(),
              [](const SubmissionFileV2& a, const SubmissionFileV2& b) { return a.path < b.path; });
    uint64_t total = 0;
    for (const auto& file : files) total += file.size;

    std::ostringstream out;
    out << "{\n";
    out << "  \"schema_version\": 2,\n";
    out << "  \"submission_uid\": \"" << JsonEscape(metadata.submission_uid) << "\",\n";
    out << "  \"author_name\": \"" << JsonEscape(metadata.author_name) << "\",\n";
    out << "  \"github_user\": \"" << JsonEscape(metadata.github_user) << "\",\n";
    if (metadata.project_id.has_value()) {
        out << "  \"project_id\": \"" << JsonEscape(*metadata.project_id) << "\",\n";
    } else if (project_id_output == ProjectIdOutput::Null) {
        out << "  \"project_id\": null,\n";
    }
    out << "  \"project_name\": \"" << JsonEscape(metadata.project_name) << "\",\n";
    out << "  \"game_version\": \"" << JsonEscape(metadata.game_version) << "\",\n";
    out << "  \"translation_version\": \"" << JsonEscape(metadata.translation_version) << "\",\n";
    out << "  \"channel\": \"" << JsonEscape(metadata.channel) << "\",\n";
    out << "  \"changelog\": \"" << JsonEscape(*metadata.changelog) << "\",\n";
    out << "  \"created_at\": \"" << JsonEscape(metadata.created_at) << "\",\n";
    out << "  \"file_count\": " << files.size() << ",\n";
    out << "  \"total_size\": " << total << ",\n";
    out << "  \"files\": [\n";
    for (size_t i = 0; i < files.size(); ++i) {
        const auto& file = files[i];
        out << "    {\"path\": \"" << JsonEscape(file.path) << "\", \"size\": " << file.size
            << ", \"sha256\": \"" << JsonEscape(file.sha256) << "\"}";
        if (i + 1 != files.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

}  // namespace wtu::v2
