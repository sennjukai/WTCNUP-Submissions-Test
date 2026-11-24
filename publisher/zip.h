// ZIP 读取、校验与安全解压（自带 DEFLATE 解码，不依赖 zlib）。
#pragma once

#include "common.h"

#include <cstdint>
#include <string>
#include <vector>

namespace wtu {

struct ZipEntry {
    std::wstring raw_name;  // ZIP 中原始条目名（保留反斜线/./ 形式供安全审计）
    std::wstring name;      // 规范化条目名（已统一为 / 分隔）
    uint16_t flags = 0;
    uint16_t method = 0;    // 0 = stored, 8 = deflate
    uint32_t crc = 0;
    uint64_t compressed_size = 0;
    uint64_t uncompressed_size = 0;
    uint32_t external_attr = 0;
    uint16_t dos_time = 0;
    uint16_t dos_date = 0;
    uint64_t local_offset = 0;
    bool is_directory = false;
};

class ZipArchive {
public:
    bool Open(const std::wstring& path, std::string* error);
    bool OpenMemory(std::vector<uint8_t> data, std::string* error);

    const std::vector<ZipEntry>& entries() const { return entries_; }
    bool ExtractEntry(size_t index, std::vector<uint8_t>& out, std::string* error) const;

private:
    bool Parse(std::string* error);

    std::vector<uint8_t> data_;
    std::vector<ZipEntry> entries_;
};

struct VerifyReport {
    bool ok = false;
    bool size_checked = false;
    bool hash_checked = false;
    std::wstring hash_skipped_reason;
    size_t entry_count = 0;
    size_t file_count = 0;
    uint64_t total_uncompressed = 0;
    std::string sha256;
    std::wstring summary() const;
};

struct ExtractReport {
    std::wstring root;
    size_t file_count = 0;
    uint64_t total_bytes = 0;
    std::wstring stripped_wrapper;
};

// 执行四道闸门；失败抛 Error。
VerifyReport VerifyZip(const std::wstring& zip_path, int64_t expected_size, const std::string& expected_sha256);

// 安全解压到 dest_root，返回实际内容根目录（可能剥离一层包装目录）。
ExtractReport ExtractZip(const std::wstring& zip_path, const std::wstring& dest_root, const std::wstring& release_tag,
                         const std::wstring& asset_name);

// 判断条目名是否安全（导出便于自检）
bool IsUnsafeEntryName(const std::wstring& name);

// 解压单个 ZIP 内的全部内容到目录（内部使用）
bool InflateRaw(const uint8_t* data, size_t size, size_t expected_size, std::vector<uint8_t>& out,
                std::string* error);

}  // namespace wtu
