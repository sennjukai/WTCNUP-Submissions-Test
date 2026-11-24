#include "zip.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace wtu {

// ===========================================================================
// 小工具
// ===========================================================================
static uint16_t ReadU16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t ReadU32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t ReadU64(const uint8_t* p) {
    return (uint64_t)ReadU32(p) | ((uint64_t)ReadU32(p + 4) << 32);
}

static std::wstring DecodeEntryName(const uint8_t* data, size_t length, uint16_t flags) {
    std::string bytes(reinterpret_cast<const char*>(data), length);
    bool utf8_flag = (flags & 0x800) != 0;
    if (utf8_flag) return Utf8ToWide(bytes);

    // 未声明 UTF-8：先按严格 UTF-8 尝试，失败再按系统 ANSI 代码页
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), nullptr, 0);
    if (n > 0) return Utf8ToWide(bytes);

    n = MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
    if (n <= 0) return Utf8ToWide(bytes);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), out.data(), n);
    return out;
}

static std::wstring NormalizeEntryName(const std::wstring& raw) {
    std::wstring name = raw;
    std::replace(name.begin(), name.end(), L'\\', L'/');
    while (name.rfind(L"./", 0) == 0) name = name.substr(2);
    return name;
}

// ===========================================================================
// DEFLATE 解码（RFC 1951）
// ===========================================================================
namespace {

struct BitReader {
    const uint8_t* data;
    size_t size;
    size_t pos = 0;
    uint32_t bit_buffer = 0;
    int bit_count = 0;
    bool failed = false;

    BitReader(const uint8_t* input, size_t length) : data(input), size(length) {}

    int ReadBit() {
        if (bit_count == 0) {
            if (pos >= size) {
                failed = true;
                return 0;
            }
            bit_buffer = data[pos++];
            bit_count = 8;
        }
        int bit = bit_buffer & 1;
        bit_buffer >>= 1;
        --bit_count;
        return bit;
    }

    uint32_t ReadBits(int count) {
        uint32_t value = 0;
        for (int i = 0; i < count; ++i) value |= (uint32_t)ReadBit() << i;
        return value;
    }

    void AlignToByte() {
        bit_buffer = 0;
        bit_count = 0;
    }
};

struct Huffman {
    uint16_t counts[16]{};
    std::vector<uint16_t> symbols;

    bool Build(const uint8_t* lengths, int n) {
        memset(counts, 0, sizeof(counts));
        for (int i = 0; i < n; ++i) counts[lengths[i]]++;
        if (counts[0] == n) return false;  // 没有任何编码

        int left = 1;
        for (int len = 1; len < 16; ++len) {
            left <<= 1;
            left -= counts[len];
            if (left < 0) return false;  // 过订阅
        }

        uint16_t offsets[16]{};
        offsets[1] = 0;
        for (int len = 1; len < 15; ++len) offsets[len + 1] = (uint16_t)(offsets[len] + counts[len]);
        symbols.assign(n, 0);
        for (int i = 0; i < n; ++i) {
            if (lengths[i]) symbols[offsets[lengths[i]]++] = (uint16_t)i;
        }
        return true;
    }

    bool Decode(BitReader& reader, int& symbol) const {
        int code = 0;
        int first = 0;
        int index = 0;
        for (int len = 1; len < 16; ++len) {
            code |= reader.ReadBit();
            int count = counts[len];
            if (code - first < count) {
                symbol = symbols[(size_t)(index + (code - first))];
                return true;
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        return false;
    }
};

const uint16_t kLengthBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                  31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const uint8_t kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                  2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const uint16_t kDistBase[30] = {1,    2,    3,    4,    5,    7,     9,     13,    17,   25,
                                33,   49,   65,   97,   129,  193,   257,   385,   513,  769,
                                1025, 1537, 2049, 3073, 4097, 6145,  8193,  12289, 16385, 24577};
const uint8_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                                6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool BuildFixedTrees(Huffman& lit, Huffman& dist) {
    uint8_t lit_lengths[288];
    for (int i = 0; i < 144; ++i) lit_lengths[i] = 8;
    for (int i = 144; i < 256; ++i) lit_lengths[i] = 9;
    for (int i = 256; i < 280; ++i) lit_lengths[i] = 7;
    for (int i = 280; i < 288; ++i) lit_lengths[i] = 8;
    if (!lit.Build(lit_lengths, 288)) return false;
    uint8_t dist_lengths[30];
    for (int i = 0; i < 30; ++i) dist_lengths[i] = 5;
    return dist.Build(dist_lengths, 30);
}

bool ReadDynamicTrees(BitReader& reader, Huffman& lit, Huffman& dist, std::string* error) {
    static const int kOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    int hlit = (int)reader.ReadBits(5) + 257;
    int hdist = (int)reader.ReadBits(5) + 1;
    int hclen = (int)reader.ReadBits(4) + 4;
    if (hlit > 286 || hdist > 30) {
        if (error) *error = "invalid HLIT/HDIST";
        return false;
    }
    uint8_t code_lengths[19] = {0};
    for (int i = 0; i < hclen; ++i) code_lengths[kOrder[i]] = (uint8_t)reader.ReadBits(3);
    Huffman code_tree;
    if (!code_tree.Build(code_lengths, 19)) {
        if (error) *error = "invalid code-length tree";
        return false;
    }

    std::vector<uint8_t> lengths((size_t)(hlit + hdist), 0);
    int index = 0;
    while (index < hlit + hdist) {
        int symbol = 0;
        if (!code_tree.Decode(reader, symbol)) {
            if (error) *error = "invalid code length";
            return false;
        }
        if (symbol < 16) {
            lengths[(size_t)index++] = (uint8_t)symbol;
        } else if (symbol == 16) {
            if (index == 0) {
                if (error) *error = "repeat with no previous length";
                return false;
            }
            int repeat = 3 + (int)reader.ReadBits(2);
            uint8_t previous = lengths[(size_t)(index - 1)];
            if (index + repeat > hlit + hdist) {
                if (error) *error = "repeat overflow";
                return false;
            }
            for (int i = 0; i < repeat; ++i) lengths[(size_t)index++] = previous;
        } else if (symbol == 17) {
            int repeat = 3 + (int)reader.ReadBits(3);
            if (index + repeat > hlit + hdist) {
                if (error) *error = "zero repeat overflow";
                return false;
            }
            index += repeat;
        } else if (symbol == 18) {
            int repeat = 11 + (int)reader.ReadBits(7);
            if (index + repeat > hlit + hdist) {
                if (error) *error = "long zero repeat overflow";
                return false;
            }
            index += repeat;
        } else {
            if (error) *error = "invalid code length symbol";
            return false;
        }
    }

    if (!lit.Build(lengths.data(), hlit)) {
        if (error) *error = "invalid literal tree";
        return false;
    }
    if (!dist.Build(lengths.data() + hlit, hdist)) {
        // 允许"没有任何距离码"的合法数据流：构造一个占位码
        uint8_t dummy[1] = {1};
        if (!dist.Build(dummy, 1)) {
            if (error) *error = "invalid distance tree";
            return false;
        }
    }
    return true;
}

}  // namespace

bool InflateRaw(const uint8_t* data, size_t size, size_t expected_size, std::vector<uint8_t>& out,
                std::string* error) {
    out.clear();
    if (expected_size > 0) out.reserve(expected_size);

    BitReader reader(data, size);
    bool final_block = false;
    while (!final_block) {
        if (reader.pos >= size && reader.bit_count == 0) {
            if (error) *error = "unexpected end of deflate stream";
            return false;
        }
        final_block = reader.ReadBits(1) != 0;
        int type = (int)reader.ReadBits(2);
        if (type == 0) {
            reader.AlignToByte();
            if (reader.pos + 4 > size) {
                if (error) *error = "truncated stored block";
                return false;
            }
            uint16_t len = ReadU16(data + reader.pos);
            uint16_t nlen = ReadU16(data + reader.pos + 2);
            reader.pos += 4;
            if ((uint16_t)(len ^ 0xFFFF) != nlen) {
                if (error) *error = "stored block length mismatch";
                return false;
            }
            if (reader.pos + len > size) {
                if (error) *error = "truncated stored block data";
                return false;
            }
            out.insert(out.end(), data + reader.pos, data + reader.pos + len);
            reader.pos += len;
        } else if (type == 1 || type == 2) {
            Huffman lit;
            Huffman dist;
            if (type == 1) {
                if (!BuildFixedTrees(lit, dist)) {
                    if (error) *error = "cannot build fixed trees";
                    return false;
                }
            } else {
                if (!ReadDynamicTrees(reader, lit, dist, error)) return false;
            }

            for (;;) {
                int symbol = 0;
                if (!lit.Decode(reader, symbol)) {
                    if (error) *error = "invalid literal/length code";
                    return false;
                }
                if (symbol < 256) {
                    out.push_back((uint8_t)symbol);
                } else if (symbol == 256) {
                    break;
                } else if (symbol >= 257 && symbol <= 285) {
                    int index = symbol - 257;
                    int length = kLengthBase[index] + (int)reader.ReadBits(kLengthExtra[index]);
                    int dist_symbol = 0;
                    if (!dist.Decode(reader, dist_symbol) || dist_symbol >= 30) {
                        if (error) *error = "invalid distance code";
                        return false;
                    }
                    int distance = kDistBase[dist_symbol] + (int)reader.ReadBits(kDistExtra[dist_symbol]);
                    if (distance <= 0 || (size_t)distance > out.size()) {
                        if (error) *error = "distance exceeds output";
                        return false;
                    }
                    size_t source = out.size() - (size_t)distance;
                    for (int i = 0; i < length; ++i) out.push_back(out[source + (size_t)i]);
                } else {
                    if (error) *error = "invalid length code";
                    return false;
                }
                if (expected_size > 0 && out.size() > expected_size) {
                    if (error) *error = "output exceeds declared size";
                    return false;
                }
            }
        } else {
            if (error) *error = "invalid block type";
            return false;
        }
        if (reader.failed) {
            if (error) *error = "truncated deflate stream";
            return false;
        }
    }

    if (expected_size > 0 && out.size() != expected_size) {
        if (error) *error = "inflated size mismatch";
        return false;
    }
    return true;
}

// ===========================================================================
// ZIP 解析
// ===========================================================================
bool ZipArchive::Open(const std::wstring& path, std::string* error) {
    if (!IsFile(path)) {
        if (error) *error = "file not found";
        return false;
    }
    uint64_t size = FileSize(path);
    if (size > 512ull * 1024 * 1024) {
        if (error) *error = "zip too large";
        return false;
    }
    std::vector<uint8_t> data;
    if (!ReadFileBytes(path, data)) {
        if (error) *error = "cannot read file";
        return false;
    }
    return OpenMemory(std::move(data), error);
}

bool ZipArchive::OpenMemory(std::vector<uint8_t> data, std::string* error) {
    data_ = std::move(data);
    entries_.clear();
    return Parse(error);
}

bool ZipArchive::Parse(std::string* error) {
    if (data_.size() < 22) {
        if (error) *error = "file too small";
        return false;
    }
    const uint8_t* base = data_.data();
    size_t size = data_.size();

    // 找 EOCD（从尾部向前扫描）
    size_t eocd = std::string::npos;
    size_t min_pos = size >= 22 + 65535 ? size - 22 - 65535 : 0;
    for (size_t i = size - 22 + 1; i-- > min_pos;) {
        if (ReadU32(base + i) == 0x06054b50) {
            eocd = i;
            break;
        }
    }
    if (eocd == std::string::npos) {
        if (error) *error = "EOCD not found";
        return false;
    }

    uint64_t total_entries = ReadU16(base + eocd + 10);
    uint64_t cd_size = ReadU32(base + eocd + 12);
    uint64_t cd_offset = ReadU32(base + eocd + 16);

    // ZIP64
    if (total_entries == 0xFFFF || cd_size == 0xFFFFFFFF || cd_offset == 0xFFFFFFFF) {
        size_t locator = std::string::npos;
        for (size_t i = eocd; i-- > 0;) {
            if (ReadU32(base + i) == 0x07064b50) {
                locator = i;
                break;
            }
            if (eocd - i > 64) break;
        }
        if (locator == std::string::npos) {
            if (error) *error = "zip64 locator missing";
            return false;
        }
        uint64_t zip64_offset = ReadU64(base + locator + 8);
        if (zip64_offset + 56 > size || ReadU32(base + zip64_offset) != 0x06064b50) {
            if (error) *error = "invalid zip64 EOCD";
            return false;
        }
        total_entries = ReadU64(base + zip64_offset + 32);
        cd_size = ReadU64(base + zip64_offset + 40);
        cd_offset = ReadU64(base + zip64_offset + 48);
    }

    if (cd_offset + cd_size > size) {
        if (error) *error = "central directory out of range";
        return false;
    }

    size_t pos = (size_t)cd_offset;
    for (uint64_t i = 0; i < total_entries; ++i) {
        if (pos + 46 > size || ReadU32(base + pos) != 0x02014b50) {
            if (error) *error = "bad central directory entry";
            return false;
        }
        ZipEntry entry;
        entry.flags = ReadU16(base + pos + 8);
        entry.method = ReadU16(base + pos + 10);
        entry.dos_time = ReadU16(base + pos + 12);
        entry.dos_date = ReadU16(base + pos + 14);
        entry.crc = ReadU32(base + pos + 16);
        entry.compressed_size = ReadU32(base + pos + 20);
        entry.uncompressed_size = ReadU32(base + pos + 24);
        uint16_t name_len = ReadU16(base + pos + 28);
        uint16_t extra_len = ReadU16(base + pos + 30);
        uint16_t comment_len = ReadU16(base + pos + 32);
        entry.external_attr = ReadU32(base + pos + 38);
        entry.local_offset = ReadU32(base + pos + 42);

        if (pos + 46 + name_len + extra_len + comment_len > size) {
            if (error) *error = "central directory overruns file";
            return false;
        }
        entry.raw_name = DecodeEntryName(base + pos + 46, name_len, entry.flags);
        entry.name = NormalizeEntryName(entry.raw_name);

        // ZIP64 扩展字段
        size_t extra_pos = pos + 46 + name_len;
        size_t extra_end = extra_pos + extra_len;
        while (extra_pos + 4 <= extra_end) {
            uint16_t id = ReadU16(base + extra_pos);
            uint16_t length = ReadU16(base + extra_pos + 2);
            size_t payload = extra_pos + 4;
            if (payload + length > extra_end) break;
            if (id == 0x0001) {
                size_t cursor = payload;
                if (entry.uncompressed_size == 0xFFFFFFFF && cursor + 8 <= payload + length) {
                    entry.uncompressed_size = ReadU64(base + cursor);
                    cursor += 8;
                }
                if (entry.compressed_size == 0xFFFFFFFF && cursor + 8 <= payload + length) {
                    entry.compressed_size = ReadU64(base + cursor);
                    cursor += 8;
                }
                if (entry.local_offset == 0xFFFFFFFF && cursor + 8 <= payload + length) {
                    entry.local_offset = ReadU64(base + cursor);
                    cursor += 8;
                }
            }
            extra_pos = payload + length;
        }

        entry.is_directory = (!entry.name.empty() && entry.name.back() == '/') ||
                             (entry.external_attr & 0x10) != 0;
        entries_.push_back(std::move(entry));
        pos += 46 + name_len + extra_len + comment_len;
    }
    return true;
}

bool ZipArchive::ExtractEntry(size_t index, std::vector<uint8_t>& out, std::string* error) const {
    out.clear();
    if (index >= entries_.size()) {
        if (error) *error = "entry index out of range";
        return false;
    }
    const ZipEntry& entry = entries_[index];
    const uint8_t* base = data_.data();
    size_t size = data_.size();
    if (entry.local_offset + 30 > size) {
        if (error) *error = "local header out of range";
        return false;
    }
    if (ReadU32(base + entry.local_offset) != 0x04034b50) {
        if (error) *error = "bad local header";
        return false;
    }
    uint16_t name_len = ReadU16(base + entry.local_offset + 26);
    uint16_t extra_len = ReadU16(base + entry.local_offset + 28);
    uint64_t data_offset = entry.local_offset + 30 + name_len + extra_len;
    if (data_offset + entry.compressed_size > size) {
        if (error) *error = "entry data out of range";
        return false;
    }
    if (entry.flags & 0x1) {
        if (error) *error = "encrypted entry";
        return false;
    }

    if (entry.method == 0) {
        out.assign(base + data_offset, base + data_offset + (size_t)entry.compressed_size);
    } else if (entry.method == 8) {
        if (!InflateRaw(base + data_offset, (size_t)entry.compressed_size, (size_t)entry.uncompressed_size, out,
                        error)) {
            return false;
        }
    } else {
        if (error) *error = "unsupported compression method " + std::to_string(entry.method);
        return false;
    }

    if (out.size() != entry.uncompressed_size) {
        if (error) *error = "uncompressed size mismatch";
        return false;
    }

    // CRC32 显式校验
    static uint32_t table[256];
    static bool table_ready = false;
    if (!table_ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t value = i;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value & 1) ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
            }
            table[i] = value;
        }
        table_ready = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t byte : out) crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    crc ^= 0xFFFFFFFFu;
    if (entry.crc != 0 && crc != entry.crc) {
        if (error) *error = "crc mismatch for " + WideToUtf8(entry.name);
        return false;
    }
    return true;
}

// ===========================================================================
// 安全校验
// ===========================================================================
bool IsUnsafeEntryName(const std::wstring& raw) {
    if (raw.empty()) return true;
    if (raw == L"." || raw == L"..") return true;
    if (raw[0] == L'/' || raw[0] == L'\\') return true;
    if (raw.size() >= 2 && raw[0] == L'\\' && raw[1] == L'\\') return true;
    if (raw.size() >= 2 && ((raw[0] >= L'A' && raw[0] <= L'Z') || (raw[0] >= L'a' && raw[0] <= L'z')) &&
        raw[1] == L':') {
        return true;
    }

    static const std::set<std::wstring> kReserved = {
        L"CON", L"PRN", L"AUX", L"NUL", L"COM1", L"COM2", L"COM3", L"COM4", L"COM5",
        L"COM6", L"COM7", L"COM8", L"COM9", L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5",
        L"LPT6", L"LPT7", L"LPT8", L"LPT9"};

    std::wstring name = raw;
    std::replace(name.begin(), name.end(), L'\\', L'/');
    size_t start = 0;
    while (start <= name.size()) {
        size_t slash = name.find(L'/', start);
        std::wstring part = name.substr(start, slash == std::wstring::npos ? std::wstring::npos : slash - start);
        if (part.empty() || part == L".") {
            // 忽略空段
        } else {
            if (part == L"..") return true;
            size_t dot = part.find(L'.');
            std::wstring stem = ToLower(dot == std::wstring::npos ? part : part.substr(0, dot));
            if (kReserved.count(ToLower(Trim(stem)))) return true;
            for (wchar_t ch : part) {
                if (ch < 32) return true;
                if (ch == L'<' || ch == L'>' || ch == L':' || ch == L'"' || ch == L'|' || ch == L'?' ||
                    ch == L'*') {
                    return true;
                }
            }
        }
        if (slash == std::wstring::npos) break;
        start = slash + 1;
    }
    return false;
}

static void ValidateEntryTypes(const std::vector<ZipEntry>& entries) {
    std::vector<std::wstring> bad;
    for (const ZipEntry& entry : entries) {
        uint16_t mode = (uint16_t)((entry.external_attr >> 16) & 0xFFFF);
        if (mode == 0) continue;
        uint16_t type = (uint16_t)(mode & 0xF000);
        if (type == 0) continue;
        if (type == 0xA000) bad.push_back(entry.name + L"（符号链接）");
        else if (type != 0x8000 && type != 0x4000) bad.push_back(entry.name + L"（特殊文件类型）");
    }
    if (!bad.empty()) {
        throw MakeError(L"安装包中包含符号链接或特殊文件，已拒绝安装。", "ZIP_UNSAFE_ENTRY",
                        L"出于安全考虑程序不会解压该压缩包，请向 Mod 作者反馈。",
                        "bad entries: " + WideToUtf8(bad.front()));
    }
}

std::wstring VerifyReport::summary() const {
    std::wstring text = L"条目 " + std::to_wstring(entry_count) + L" 个（文件 " + std::to_wstring(file_count) +
                        L" 个），解压后约 " + HumanSize(total_uncompressed);
    text += size_checked ? L"，大小校验通过" : L"，大小校验跳过";
    if (hash_checked) text += L"，SHA-256 校验通过";
    else text += L"，SHA-256 校验跳过（" + (hash_skipped_reason.empty() ? L"未提供" : hash_skipped_reason) + L"）";
    return text;
}

// ===========================================================================
// 校验
// ===========================================================================
VerifyReport VerifyZip(const std::wstring& zip_path, int64_t expected_size, const std::string& expected_sha256) {
    VerifyReport report;
    if (!IsFile(zip_path)) {
        throw MakeError(L"找不到已下载的安装包文件。", "ZIP_CORRUPT", L"请重新执行一次更新。",
                        "missing: " + WideToUtf8(zip_path));
    }
    uint64_t actual_size = FileSize(zip_path);
    if (expected_size > 0) {
        if (actual_size != (uint64_t)expected_size) {
            throw MakeError(L"安装包大小与官方记录不一致，可能未下载完整。", "ZIP_CORRUPT", L"请重新执行一次更新。",
                            "expected=" + std::to_string(expected_size) + " actual=" + std::to_string(actual_size));
        }
        report.size_checked = true;
    }

    std::vector<uint8_t> head;
    {
        HANDLE handle = CreateFileW(LongPath(zip_path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            throw MakeError(L"无法读取已下载的安装包。", "ZIP_CORRUPT", L"请重新执行一次更新。", "open failed");
        }
        uint8_t buffer[4]{};
        DWORD read = 0;
        ReadFile(handle, buffer, 4, &read, nullptr);
        CloseHandle(handle);
        head.assign(buffer, buffer + read);
    }
    bool magic_ok = head.size() >= 4 && head[0] == 'P' && head[1] == 'K' &&
                    ((head[2] == 3 && head[3] == 4) || (head[2] == 5 && head[3] == 6) ||
                     (head[2] == 7 && head[3] == 8));
    if (!magic_ok) {
        throw MakeError(L"下载到的文件不是有效的 ZIP 压缩包。", "ZIP_NOT_ZIP",
                        L"请重试；若反复出现请更换网络环境或配置代理。", "bad magic");
    }

    report.sha256 = Sha256File(zip_path);
    if (!expected_sha256.empty()) {
        if (ToLower(report.sha256) != ToLower(expected_sha256)) {
            throw MakeError(L"安装包校验值与官方记录不一致，文件可能已损坏。", "ZIP_HASH_MISMATCH",
                            L"请重新执行一次更新；若反复出现请更换网络环境。",
                            "expected=" + expected_sha256 + " actual=" + report.sha256);
        }
        report.hash_checked = true;
    } else {
        report.hash_skipped_reason = L"GitHub 未提供该文件的摘要";
    }

    ZipArchive archive;
    std::string error;
    if (!archive.Open(zip_path, &error)) {
        throw MakeError(L"安装包已损坏，无法读取。", "ZIP_CORRUPT", L"请重新执行一次更新。", "zip: " + error);
    }
    const auto& entries = archive.entries();
    if (entries.empty()) {
        throw MakeError(L"安装包是空的。", "ZIP_EMPTY", L"请向 Mod 作者反馈该版本的问题。", "no entries");
    }
    size_t files = 0;
    for (const ZipEntry& entry : entries) {
        if (!entry.is_directory) ++files;
    }
    if (files == 0) {
        throw MakeError(L"安装包里没有任何文件。", "ZIP_EMPTY", L"请向 Mod 作者反馈该版本的问题。", "only dirs");
    }

    std::vector<std::wstring> unsafe;
    for (const ZipEntry& entry : entries) {
        if (IsUnsafeEntryName(entry.name)) unsafe.push_back(entry.name);
    }
    if (!unsafe.empty()) {
        throw MakeError(L"安装包中包含不安全的文件路径，已拒绝安装。", "ZIP_UNSAFE_ENTRY",
                        L"出于安全考虑程序不会解压该压缩包，请向 Mod 作者反馈。",
                        "unsafe: " + WideToUtf8(unsafe.front()));
    }
    ValidateEntryTypes(entries);

    // CRC 全量校验（分块解码，内存占用与条目大小相关）
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].is_directory) continue;
        std::vector<uint8_t> content;
        if (!archive.ExtractEntry(i, content, &error)) {
            throw MakeError(L"安装包内部数据校验失败（可能已损坏）。", "ZIP_CORRUPT", L"请重新执行一次更新。",
                            "entry=" + WideToUtf8(entries[i].name) + " " + error);
        }
    }

    report.ok = true;
    report.entry_count = entries.size();
    report.file_count = files;
    for (const ZipEntry& entry : entries) {
        if (!entry.is_directory) report.total_uncompressed += entry.uncompressed_size;
    }
    LogFormat(LogLevel::Info, L"安装包校验通过：%ls", report.summary().c_str());
    return report;
}

// ===========================================================================
// 解压
// ===========================================================================
static bool IsGameTopLevelDir(const std::wstring& name) {
    static const std::set<std::wstring> kDirs = {
        L"lang",      L"content",     L"cache",     L"config.blk", L"userskins", L"screenshots",
        L"replays",   L"logs",        L"update",    L"warthunder", L"aces",      L"sound",
        L"char",      L"gui",         L"fonts",     L"cef",        L"clog",      L"gameparams",
        L"levels",    L"missions",    L"profile",   L"textures",   L"ui",        L"usercontent"};
    return kDirs.count(ToLower(name)) > 0;
}

static bool IsSpaceChar(wchar_t ch) {
    return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n' || ch == L'\f' || ch == L'\v';
}

static std::wstring LooseEqualKey(const std::wstring& value) {
    std::wstring out;
    for (wchar_t ch : ToLower(value)) {
        if (ch == L'.' || ch == L'_' || ch == L'-' || IsSpaceChar(ch)) continue;
        out.push_back(ch);
    }
    return out;
}

static bool IsVersionLike(const std::wstring& name) {
    if (name.empty()) return false;
    if (!(name[0] >= L'0' && name[0] <= L'9')) return false;
    for (wchar_t ch : name) {
        bool ok = (ch >= L'0' && ch <= L'9') || (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
                  ch == L'.' || ch == L'_' || ch == L'-' || ch == L'+' || ch == L' ';
        if (!ok) return false;
    }
    return true;
}

static std::wstring ApplyTimestamp(const std::wstring& target, const ZipEntry& entry) {
    FILETIME local{};
    if (!DosDateTimeToFileTime(entry.dos_date, entry.dos_time, &local)) return target;
    FILETIME utc{};
    if (!LocalFileTimeToFileTime(&local, &utc)) return target;
    HANDLE handle = CreateFileW(LongPath(target).c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
        SetFileTime(handle, &utc, &utc, &utc);
        CloseHandle(handle);
    }
    return target;
}

static std::wstring DetectWrapper(const std::wstring& root, const std::wstring& release_tag,
                                  const std::wstring& asset_name) {
    std::wstring pattern = JoinPath(root, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE handle = FindFirstFileW(LongPath(pattern).c_str(), &data);
    if (handle == INVALID_HANDLE_VALUE) return std::wstring();

    std::vector<std::wstring> dirs;
    bool has_files = false;
    std::wstring sole_name;
    do {
        std::wstring name = data.cFileName;
        if (name == L"." || name == L"..") continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            dirs.push_back(name);
        } else {
            has_files = true;
        }
    } while (FindNextFileW(handle, &data));
    FindClose(handle);

    if (has_files || dirs.size() != 1) return std::wstring();
    sole_name = dirs[0];
    if (IsGameTopLevelDir(sole_name)) return std::wstring();

    std::wstring tag = Trim(release_tag);
    std::wstring stem = Trim(asset_name);
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem = stem.substr(0, dot);

    if (!tag.empty() && IEquals(sole_name, tag)) return sole_name;
    if (!stem.empty() && IEquals(sole_name, stem)) return sole_name;
    if (!tag.empty() && !stem.empty() && LooseEqualKey(sole_name) == LooseEqualKey(tag)) return sole_name;
    if (!tag.empty() && LooseEqualKey(sole_name) == LooseEqualKey(tag)) return sole_name;
    if (!stem.empty() && LooseEqualKey(sole_name) == LooseEqualKey(stem)) return sole_name;
    if (IsVersionLike(sole_name)) return sole_name;
    return std::wstring();
}

ExtractReport ExtractZip(const std::wstring& zip_path, const std::wstring& dest_root, const std::wstring& release_tag,
                         const std::wstring& asset_name) {
    ZipArchive archive;
    std::string error;
    if (!archive.Open(zip_path, &error)) {
        throw MakeError(L"解压安装包失败：压缩包已损坏。", "ZIP_CORRUPT", L"请重新执行一次更新。", "zip: " + error);
    }

    EnsureDir(dest_root);
    std::wstring root = AbsolutePath(dest_root);
    std::wstring root_key = NormalizePath(root);
    size_t written = 0;
    uint64_t total_bytes = 0;

    const auto& entries = archive.entries();
    for (size_t i = 0; i < entries.size(); ++i) {
        const ZipEntry& entry = entries[i];
        std::wstring name = NormalizeEntryName(entry.name);
        if (name.empty()) continue;
        if (IsUnsafeEntryName(name)) {
            throw MakeError(L"安装包中包含不安全的文件路径，已拒绝安装。", "ZIP_UNSAFE_ENTRY",
                            L"出于安全考虑程序不会解压该压缩包，请向 Mod 作者反馈。",
                            "entry=" + WideToUtf8(name));
        }

        std::wstring relative = name;
        std::replace(relative.begin(), relative.end(), L'/', L'\\');
        std::wstring target = AbsolutePath(JoinPath(root, relative));
        std::wstring target_key = NormalizePath(target);
        if (!(target_key == root_key || target_key.rfind(root_key + L"\\", 0) == 0)) {
            throw MakeError(L"安装包中包含越界的文件路径，已拒绝安装。", "ZIP_UNSAFE_ENTRY",
                            L"出于安全考虑程序不会解压该压缩包。", "entry=" + WideToUtf8(name));
        }

        if (entry.is_directory) {
            EnsureDir(target);
            continue;
        }
        size_t slash = target.find_last_of(L'\\');
        if (slash != std::wstring::npos) EnsureDir(target.substr(0, slash));

        std::vector<uint8_t> content;
        if (!archive.ExtractEntry(i, content, &error)) {
            throw MakeError(L"解压安装包失败：压缩包数据已损坏。", "ZIP_CORRUPT",
                            L"请重新执行一次更新；若反复出现请向 Mod 作者反馈。",
                            "entry=" + WideToUtf8(name) + " " + error);
        }
        WriteFileBytesAtomic(target, content.data(), content.size());
        ApplyTimestamp(target, entry);
        ++written;
        total_bytes += entry.uncompressed_size;
    }

    if (written == 0) {
        throw MakeError(L"安装包中没有可安装的文件。", "ZIP_EMPTY", L"请向 Mod 作者反馈该版本的问题。",
                        "extracted 0 files");
    }

    ExtractReport report;
    report.root = root;
    report.file_count = written;
    report.total_bytes = total_bytes;
    std::wstring wrapper = DetectWrapper(root, release_tag, asset_name);
    if (!wrapper.empty()) {
        report.root = JoinPath(root, wrapper);
        report.stripped_wrapper = wrapper;
        LogFormat(LogLevel::Info, L"检测到多余的包装目录「%ls」，已在安装时自动忽略", wrapper.c_str());
    }
    return report;
}

}  // namespace wtu
