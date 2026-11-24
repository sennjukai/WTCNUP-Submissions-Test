#include "community_package_v2.h"

#include "common.h"
#include "zip.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace wtu::v2 {
namespace {

constexpr uint64_t kMaxZipBytes = 64ull * 1024 * 1024;
constexpr uint64_t kMaxFileBytes = 10ull * 1024 * 1024;
constexpr uint64_t kMaxTotalBytes = 50ull * 1024 * 1024;

bool Fail(SubmissionV2Error* error, const char* code, const char* field, const char* message) {
    if (error) {
        error->code = code;
        error->field = field;
        error->message = message;
    }
    return false;
}

std::filesystem::path PathFromUtf8(const std::string& value) {
#if defined(__cpp_char8_t)
    return std::filesystem::path(
        std::u8string(reinterpret_cast<const char8_t*>(value.data()), value.size()));
#else
    return std::filesystem::u8path(value);
#endif
}

std::string PathToUtf8(const std::filesystem::path& value) {
    const auto text = value.u8string();
    return std::string(text.begin(), text.end());
}

bool ReadFile(const std::filesystem::path& path, std::vector<uint8_t>* out, uint64_t max_size) {
    std::error_code ec;
    const uint64_t size = std::filesystem::file_size(path, ec);
    if (ec || size > max_size) return false;
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    out->assign(static_cast<size_t>(size), 0);
    if (size > 0) file.read(reinterpret_cast<char*>(out->data()), static_cast<std::streamsize>(size));
    return file.good() || file.eof();
}

bool ReadText(const std::filesystem::path& path, std::string* out, uint64_t max_size) {
    std::vector<uint8_t> bytes;
    if (!ReadFile(path, &bytes, max_size)) return false;
    out->assign(bytes.begin(), bytes.end());
    return true;
}

const Json* FindString(const Json& obj, const char* key) {
    const Json* value = obj.find(key);
    return value && value->is_string() ? value : nullptr;
}

class StrictJsonScanner {
public:
    explicit StrictJsonScanner(const std::string& text) : text_(text) {}

    bool Scan(std::string* message) {
        SkipSpace();
        if (!Value(0)) {
            if (message) *message = message_;
            return false;
        }
        SkipSpace();
        if (pos_ != text_.size()) {
            if (message) *message = "trailing JSON characters";
            return false;
        }
        return true;
    }

private:
    void SkipSpace() {
        while (pos_ < text_.size()) {
            const char ch = text_[pos_];
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') ++pos_;
            else break;
        }
    }

    static void AppendUtf8(uint32_t cp, std::string* out) {
        if (cp <= 0x7f) out->push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) {
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

    bool Hex4(uint32_t* value) {
        if (pos_ + 4 > text_.size()) return false;
        uint32_t result = 0;
        for (int i = 0; i < 4; ++i) {
            const unsigned char ch = static_cast<unsigned char>(text_[pos_++]);
            int digit = -1;
            if (ch >= '0' && ch <= '9') digit = ch - '0';
            else if (ch >= 'a' && ch <= 'f') digit = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') digit = ch - 'A' + 10;
            if (digit < 0) return false;
            result = result * 16 + static_cast<uint32_t>(digit);
        }
        *value = result;
        return true;
    }

    bool String(std::string* decoded) {
        if (pos_ >= text_.size() || text_[pos_] != '"') return false;
        ++pos_;
        while (pos_ < text_.size()) {
            const unsigned char ch = static_cast<unsigned char>(text_[pos_++]);
            if (ch == '"') return true;
            if (ch < 0x20) {
                message_ = "control character in JSON string";
                return false;
            }
            if (ch != '\\') {
                decoded->push_back(static_cast<char>(ch));
                continue;
            }
            if (pos_ >= text_.size()) return false;
            const char esc = text_[pos_++];
            switch (esc) {
                case '"': decoded->push_back('"'); break;
                case '\\': decoded->push_back('\\'); break;
                case '/': decoded->push_back('/'); break;
                case 'b': decoded->push_back('\b'); break;
                case 'f': decoded->push_back('\f'); break;
                case 'n': decoded->push_back('\n'); break;
                case 'r': decoded->push_back('\r'); break;
                case 't': decoded->push_back('\t'); break;
                case 'u': {
                    uint32_t cp = 0;
                    if (!Hex4(&cp)) return false;
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (pos_ + 2 > text_.size() || text_[pos_] != '\\' || text_[pos_ + 1] != 'u') {
                            message_ = "invalid JSON surrogate pair";
                            return false;
                        }
                        pos_ += 2;
                        uint32_t low = 0;
                        if (!Hex4(&low) || low < 0xdc00 || low > 0xdfff) return false;
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    }
                    AppendUtf8(cp, decoded);
                    break;
                }
                default: return false;
            }
        }
        return false;
    }

    bool Number() {
        const size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '-') ++pos_;
        if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) return false;
        if (text_[pos_] == '0') ++pos_;
        else while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        if (pos_ < text_.size() && text_[pos_] == '.') {
            ++pos_;
            if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) return false;
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            if (pos_ >= text_.size() || !std::isdigit(static_cast<unsigned char>(text_[pos_]))) return false;
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        }
        return pos_ > start;
    }

    bool Value(int depth) {
        if (depth > 64) {
            message_ = "JSON nesting too deep";
            return false;
        }
        SkipSpace();
        if (pos_ >= text_.size()) return false;
        const char ch = text_[pos_];
        if (ch == '{') return Object(depth + 1);
        if (ch == '[') return Array(depth + 1);
        if (ch == '"') {
            std::string ignored;
            return String(&ignored);
        }
        if (ch == 't') {
            if (text_.compare(pos_, 4, "true") != 0) return false;
            pos_ += 4;
            return true;
        }
        if (ch == 'f') {
            if (text_.compare(pos_, 5, "false") != 0) return false;
            pos_ += 5;
            return true;
        }
        if (ch == 'n') {
            if (text_.compare(pos_, 4, "null") != 0) return false;
            pos_ += 4;
            return true;
        }
        return Number();
    }

    bool Object(int depth) {
        ++pos_;  // {
        std::set<std::string> keys;
        SkipSpace();
        if (pos_ < text_.size() && text_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (pos_ < text_.size()) {
            std::string key;
            if (!String(&key)) return false;
            if (!keys.insert(key).second) {
                message_ = "duplicate JSON key: " + key;
                return false;
            }
            SkipSpace();
            if (pos_ >= text_.size() || text_[pos_] != ':') return false;
            ++pos_;
            if (!Value(depth)) return false;
            SkipSpace();
            if (pos_ < text_.size() && text_[pos_] == ',') {
                ++pos_;
                SkipSpace();
                continue;
            }
            if (pos_ < text_.size() && text_[pos_] == '}') {
                ++pos_;
                return true;
            }
            return false;
        }
        return false;
    }

    bool Array(int depth) {
        ++pos_;  // [
        SkipSpace();
        if (pos_ < text_.size() && text_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (pos_ < text_.size()) {
            if (!Value(depth)) return false;
            SkipSpace();
            if (pos_ < text_.size() && text_[pos_] == ',') {
                ++pos_;
                SkipSpace();
                continue;
            }
            if (pos_ < text_.size() && text_[pos_] == ']') {
                ++pos_;
                return true;
            }
            return false;
        }
        return false;
    }

    const std::string& text_;
    size_t pos_ = 0;
    std::string message_;
};

bool StrictJsonCheck(const std::string& raw, SubmissionV2Error* error) {
    StrictJsonScanner scanner(raw);
    std::string message;
    if (scanner.Scan(&message)) return true;
    return Fail(error, "COMMUNITY_V2_JSON", "json", message.empty() ? "invalid JSON" : message.c_str());
}

struct MetadataDoc {
    SubmissionMetadataV2 metadata;
    std::vector<SubmissionFileV2> files;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

bool ParseMetadataDoc(const std::string& raw, MetadataDoc* doc, SubmissionV2Error* error) {
    if (!StrictJsonCheck(raw, error)) return false;
    std::string parse_error;
    Json value = Json::parse(raw, &parse_error);
    if (!parse_error.empty() || !value.is_object()) {
        return Fail(error, "COMMUNITY_V2_SCHEMA", "submission.json", "invalid JSON object");
    }
    static const std::set<std::string> allowed = {
        "schema_version", "submission_uid", "author_name", "github_user", "project_id",
        "project_name", "game_version", "translation_version", "channel", "changelog",
        "created_at", "file_count", "total_size", "files"};
    for (const auto& [key, unused] : value.fields()) {
        if (!allowed.count(key)) {
            return Fail(error, "COMMUNITY_V2_SCHEMA", key.c_str(), "unknown field");
        }
    }
    const Json* schema = value.find("schema_version");
    if (!schema || !schema->is_number() || schema->as_int() != 2) {
        return Fail(error, "COMMUNITY_V2_SCHEMA", "schema_version", "must be integer 2");
    }
    const Json* uid = FindString(value, "submission_uid");
    const Json* author = FindString(value, "author_name");
    const Json* login = FindString(value, "github_user");
    const Json* project = FindString(value, "project_name");
    const Json* game = FindString(value, "game_version");
    const Json* version = FindString(value, "translation_version");
    const Json* channel = FindString(value, "channel");
    const Json* changelog = FindString(value, "changelog");
    const Json* created = FindString(value, "created_at");
    if (!uid || !author || !login || !project || !game || !version || !channel ||
        !changelog || !created) {
        return Fail(error, "COMMUNITY_V2_SCHEMA", "submission.json", "missing required string field");
    }
    doc->metadata = SubmissionMetadataV2{};
    doc->metadata.submission_uid = uid->as_string();
    doc->metadata.author_name = author->as_string();
    doc->metadata.github_user = login->as_string();
    doc->metadata.project_name = project->as_string();
    doc->metadata.game_version = game->as_string();
    doc->metadata.translation_version = version->as_string();
    doc->metadata.channel = channel->as_string();
    doc->metadata.changelog = changelog->as_string();
    doc->metadata.created_at = created->as_string();

    const Json* project_id = value.find("project_id");
    if (project_id && !project_id->is_null()) {
        if (!project_id->is_string()) {
            return Fail(error, "COMMUNITY_V2_PROJECT_ID", "project_id", "must be string or null");
        }
        doc->metadata.project_id = project_id->as_string();
    }
    const Json* count = value.find("file_count");
    const Json* total = value.find("total_size");
    if (!count || !count->is_number() || count->as_int() < 1) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "file_count", "invalid file_count");
    }
    if (!total || !total->is_number() || total->as_int() < 0) {
        return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "invalid total_size");
    }
    doc->file_count = static_cast<uint64_t>(count->as_int());
    doc->total_size = static_cast<uint64_t>(total->as_int());

    const Json* files = value.find("files");
    if (!files || !files->is_array()) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "must be an array");
    }
    doc->files.clear();
    for (const Json& item : files->items()) {
        if (!item.is_object() || item.fields().size() != 3 || !item.find("path") ||
            !item.find("size") || !item.find("sha256")) {
            return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "invalid file entry");
        }
        const Json* path = item.find("path");
        const Json* size = item.find("size");
        const Json* sha = item.find("sha256");
        if (!path || !path->is_string() || !size || !size->is_number() ||
            size->as_int() < 0 || !sha || !sha->is_string()) {
            return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "invalid file entry fields");
        }
        SubmissionFileV2 file;
        file.path = path->as_string();
        file.size = static_cast<uint64_t>(size->as_int());
        file.sha256 = sha->as_string();
        doc->files.push_back(std::move(file));
    }
    if (doc->file_count != doc->files.size()) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "file_count", "does not match files length");
    }
    return true;
}

std::string BuildManifestJson(const MetadataDoc& doc) {
    Json manifest = Json::MakeObject();
    manifest.set("schema_version", Json(2));
    manifest.set("submission_uid", Json(doc.metadata.submission_uid));
    manifest.set("file_count", Json(static_cast<int64_t>(doc.files.size())));
    manifest.set("total_size", Json(static_cast<int64_t>(doc.total_size)));
    std::vector<SubmissionFileV2> files = doc.files;
    std::sort(files.begin(), files.end(),
              [](const SubmissionFileV2& a, const SubmissionFileV2& b) { return a.path < b.path; });
    Json array = Json::MakeArray();
    for (const auto& file : files) {
        Json item = Json::MakeObject();
        item.set("path", Json(file.path));
        item.set("size", Json(static_cast<int64_t>(file.size)));
        item.set("sha256", Json(file.sha256));
        array.push(std::move(item));
    }
    manifest.set("files", std::move(array));
    return manifest.dump(false);
}

uint32_t Crc32(const uint8_t* data, size_t size) {
    static const std::array<uint32_t, 256> table = [] {
        std::array<uint32_t, 256> values{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
            values[i] = c;
        }
        return values;
    }();
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffffu;
}

void AppendU16(std::vector<uint8_t>* out, uint16_t value) {
    out->push_back(static_cast<uint8_t>(value & 0xff));
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
}
void AppendU32(std::vector<uint8_t>* out, uint32_t value) {
    for (int i = 0; i < 4; ++i) out->push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xff));
}

struct ZipWriteEntry {
    std::string name;
    std::vector<uint8_t> data;
    uint32_t crc = 0;
    uint32_t offset = 0;
};

bool BuildStoredZip(const std::vector<ZipWriteEntry>& entries, std::vector<uint8_t>* out) {
    std::vector<ZipWriteEntry> writable = entries;
    for (auto& entry : writable) entry.crc = Crc32(entry.data.data(), entry.data.size());
    out->clear();
    for (auto& entry : writable) {
        entry.offset = static_cast<uint32_t>(out->size());
        AppendU32(out, 0x04034b50);
        AppendU16(out, 20);
        AppendU16(out, 0x0800);  // UTF-8 names
        AppendU16(out, 0);       // stored
        AppendU16(out, 0);       // DOS time
        AppendU16(out, 0x0021);  // 1980-01-01
        AppendU32(out, entry.crc);
        AppendU32(out, static_cast<uint32_t>(entry.data.size()));
        AppendU32(out, static_cast<uint32_t>(entry.data.size()));
        AppendU16(out, static_cast<uint16_t>(entry.name.size()));
        AppendU16(out, 0);
        out->insert(out->end(), entry.name.begin(), entry.name.end());
        out->insert(out->end(), entry.data.begin(), entry.data.end());
    }
    const uint32_t central_offset = static_cast<uint32_t>(out->size());
    for (const auto& entry : writable) {
        AppendU32(out, 0x02014b50);
        AppendU16(out, 0x031e);  // Unix, ZIP 3.0
        AppendU16(out, 20);
        AppendU16(out, 0x0800);
        AppendU16(out, 0);
        AppendU16(out, 0);
        AppendU16(out, 0x0021);
        AppendU32(out, entry.crc);
        AppendU32(out, static_cast<uint32_t>(entry.data.size()));
        AppendU32(out, static_cast<uint32_t>(entry.data.size()));
        AppendU16(out, static_cast<uint16_t>(entry.name.size()));
        AppendU16(out, 0);
        AppendU16(out, 0);
        AppendU16(out, 0);
        AppendU16(out, 0);
        AppendU32(out, 0100644u << 16);  // regular file
        AppendU32(out, entry.offset);
        out->insert(out->end(), entry.name.begin(), entry.name.end());
    }
    const uint32_t central_size = static_cast<uint32_t>(out->size()) - central_offset;
    AppendU32(out, 0x06054b50);
    AppendU16(out, 0);
    AppendU16(out, 0);
    AppendU16(out, static_cast<uint16_t>(writable.size()));
    AppendU16(out, static_cast<uint16_t>(writable.size()));
    AppendU32(out, central_size);
    AppendU32(out, central_offset);
    AppendU16(out, 0);
    return out->size() <= kMaxZipBytes;
}

bool ParseManifest(const std::string& raw, const std::string& expected, SubmissionV2Error* error) {
    if (!StrictJsonCheck(raw, error)) return false;
    std::string parse_error;
    Json actual = Json::parse(raw, &parse_error);
    if (!parse_error.empty() || !actual.is_object()) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "manifest.json", "invalid JSON");
    }
    if (actual.dump(false) != expected) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "manifest.json", "does not match submission.json");
    }
    return true;
}

}  // namespace

bool ParseSubmissionJsonV2(const std::string& raw, SubmissionDocumentV2* document,
                           SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    MetadataDoc doc;
    if (!ParseMetadataDoc(raw, &doc, error)) return false;
    document->metadata = std::move(doc.metadata);
    document->files = std::move(doc.files);
    document->file_count = doc.file_count;
    document->total_size = doc.total_size;
    return true;
}

bool BuildSubmissionPackageV2(const std::string& source_dir,
                              const std::string& output_zip,
                              PackageV2Result* result,
                              SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    const std::filesystem::path source = PathFromUtf8(source_dir);
    const std::filesystem::path output = PathFromUtf8(output_zip);
    if (!std::filesystem::is_directory(source)) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "source_dir", "source is not a directory");
    }
    if (output.extension() != ".zip") {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "output_zip", "output must end with .zip");
    }
    std::string submission_text;
    if (!ReadText(source / "submission.json", &submission_text, 256 * 1024)) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "submission.json", "cannot read submission.json");
    }
    MetadataDoc doc;
    if (!ParseMetadataDoc(submission_text, &doc, error)) return false;

    std::map<std::string, std::filesystem::path> actual;
    const std::filesystem::path files_root = source / "files";
    if (!std::filesystem::is_directory(files_root)) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "files", "files/ is missing");
    }
    std::error_code ec;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             files_root, std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec) return Fail(error, "COMMUNITY_V2_PACKAGE", "files", "cannot enumerate files/");
        const auto status = entry.symlink_status(ec);
        if (ec) return Fail(error, "COMMUNITY_V2_PACKAGE", "files", "cannot inspect files/");
        if (std::filesystem::is_symlink(status)) {
            return Fail(error, "COMMUNITY_V2_PATH", "files", "symbolic links are not allowed");
        }
        if (std::filesystem::is_directory(status)) continue;
        if (!std::filesystem::is_regular_file(status)) {
            return Fail(error, "COMMUNITY_V2_PATH", "files", "special file is not allowed");
        }
        const std::filesystem::path relative = std::filesystem::relative(entry.path(), files_root, ec);
        if (ec) return Fail(error, "COMMUNITY_V2_PATH", "files", "cannot compute relative path");
        std::string relative_text = PathToUtf8(relative);
        std::replace(relative_text.begin(), relative_text.end(), '\\', '/');
        actual[relative_text] = entry.path();
    }
    if (actual.size() != doc.files.size()) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "declared and actual file sets differ");
    }
    for (auto& file : doc.files) {
        auto found = actual.find(file.path);
        if (found == actual.end()) {
            return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "declared and actual file sets differ");
        }
        file.full_path = PathToUtf8(found->second);
    }
    SubmissionScanV2 scan;
    scan.files = doc.files;
    scan.file_count = doc.files.size();
    scan.total_size = 0;
    for (const auto& file : doc.files) scan.total_size += file.size;
    if (!ValidateSubmissionV2Local(doc.metadata, scan, error)) return false;
    if (doc.file_count != scan.file_count || doc.total_size != scan.total_size) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "file_count", "metadata counts do not match files");
    }

    std::vector<ZipWriteEntry> entries;
    entries.push_back({"submission.json", std::vector<uint8_t>(submission_text.begin(), submission_text.end())});
    const std::string manifest_text = BuildManifestJson(doc);
    entries.push_back({"manifest.json", std::vector<uint8_t>(manifest_text.begin(), manifest_text.end())});
    for (const auto& file : doc.files) {
        std::vector<uint8_t> bytes;
        if (!ReadFile(PathFromUtf8(file.full_path), &bytes, kMaxFileBytes)) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files", "cannot read payload");
        }
        entries.push_back({"files/" + file.path, std::move(bytes)});
    }
    std::sort(entries.begin() + 2, entries.end(),
              [](const ZipWriteEntry& a, const ZipWriteEntry& b) { return a.name < b.name; });

    std::vector<uint8_t> zip;
    if (!BuildStoredZip(entries, &zip)) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "output_zip", "ZIP exceeds 64 MiB");
    }
    std::filesystem::create_directories(output.parent_path(), ec);
    std::ofstream out(output, std::ios::binary | std::ios::trunc);
    if (!out) return Fail(error, "COMMUNITY_V2_PACKAGE", "output_zip", "cannot write ZIP");
    out.write(reinterpret_cast<const char*>(zip.data()), static_cast<std::streamsize>(zip.size()));
    out.close();
    if (!out) return Fail(error, "COMMUNITY_V2_PACKAGE", "output_zip", "cannot write ZIP");
    if (result) {
        result->path = output_zip;
        result->zip_sha256 = Sha256HexV2(zip.data(), zip.size());
        result->zip_size = zip.size();
        result->file_count = doc.files.size();
        result->total_size = scan.total_size;
    }
    return true;
}

bool VerifySubmissionPackageV2(const std::string& zip_path,
                               const std::string& expected_sha256,
                               PackageV2VerifyResult* result,
                               SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    std::error_code ec;
    const std::filesystem::path path = PathFromUtf8(zip_path);
    if (!std::filesystem::is_regular_file(path, ec)) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "package", "package is missing");
    }
    const uint64_t zip_size = std::filesystem::file_size(path, ec);
    if (ec || zip_size > kMaxZipBytes) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "package", "ZIP exceeds 64 MiB");
    }
    bool hash_ok = false;
    const std::string actual_sha = Sha256FileHexV2(zip_path, &hash_ok);
    if (!hash_ok) return Fail(error, "COMMUNITY_V2_PACKAGE", "package", "cannot hash ZIP");
    if (!expected_sha256.empty() && expected_sha256 != actual_sha) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "package", "ZIP SHA-256 mismatch");
    }

    ZipArchive archive;
    std::string zip_error;
    if (!archive.Open(Utf8ToWide(zip_path), &zip_error)) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "package", "invalid ZIP");
    }
    const auto& entries = archive.entries();
    if (entries.size() > 302) {
        return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "too many ZIP entries");
    }
    std::map<std::string, size_t> by_name;
    for (size_t i = 0; i < entries.size(); ++i) {
        const ZipEntry& entry = entries[i];
        const std::string raw = WideToUtf8(entry.raw_name);
        const std::string name = WideToUtf8(entry.name);
        if (raw != name || raw.find('\\') != std::string::npos) {
            return Fail(error, "COMMUNITY_V2_PATH", "files", "ZIP names must use /");
        }
        if (entry.is_directory || (!name.empty() && name.back() == '/')) {
            return Fail(error, "COMMUNITY_V2_PACKAGE", "files", "directory entries are not allowed");
        }
        const uint16_t mode = static_cast<uint16_t>((entry.external_attr >> 16) & 0xf000);
        if (mode != 0 && mode != 0x8000) {
            return Fail(error, "COMMUNITY_V2_PATH", "files", "only regular ZIP files are allowed");
        }
        if (entry.uncompressed_size > kMaxFileBytes) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files", "ZIP member too large");
        }
        if (!by_name.emplace(name, i).second) {
            return Fail(error, "COMMUNITY_V2_PACKAGE", "files", "duplicate ZIP member");
        }
    }
    if (!by_name.count("submission.json") || !by_name.count("manifest.json")) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "files", "missing submission.json or manifest.json");
    }
    const std::set<std::string> allowed_prefix = {"submission.json", "manifest.json"};
    for (const auto& [name, unused] : by_name) {
        if (allowed_prefix.count(name)) continue;
        if (name.rfind("files/", 0) != 0) {
            return Fail(error, "COMMUNITY_V2_PACKAGE", name.c_str(), "unexpected ZIP member");
        }
    }

    auto read_entry = [&](size_t index, std::vector<uint8_t>* out, std::string* read_error) {
        return archive.ExtractEntry(index, *out, read_error);
    };
    std::vector<uint8_t> submission_bytes;
    std::vector<uint8_t> manifest_bytes;
    std::string extract_error;
    if (!read_entry(by_name["submission.json"], &submission_bytes, &extract_error) ||
        submission_bytes.size() > 256 * 1024) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "submission.json", "cannot read submission.json");
    }
    if (!read_entry(by_name["manifest.json"], &manifest_bytes, &extract_error) ||
        manifest_bytes.size() > 256 * 1024) {
        return Fail(error, "COMMUNITY_V2_PACKAGE", "manifest.json", "cannot read manifest.json");
    }
    const std::string submission_text(submission_bytes.begin(), submission_bytes.end());
    const std::string manifest_text(manifest_bytes.begin(), manifest_bytes.end());
    MetadataDoc doc;
    if (!ParseMetadataDoc(submission_text, &doc, error)) return false;
    if (!ParseManifest(manifest_text, BuildManifestJson(doc), error)) return false;

    std::set<std::string> expected_names = {"submission.json", "manifest.json"};
    for (const auto& file : doc.files) expected_names.insert("files/" + file.path);
    for (const auto& [name, unused] : by_name) {
        if (!expected_names.count(name)) {
            return Fail(error, "COMMUNITY_V2_PACKAGE", name.c_str(), "unexpected ZIP member");
        }
    }
    SubmissionScanV2 scan;
    scan.files = doc.files;
    scan.file_count = doc.files.size();
    scan.total_size = doc.total_size;
    if (!ValidateSubmissionMetadataV2(doc.metadata, scan, error)) return false;
    std::set<std::string> actual_paths;
    uint64_t actual_total = 0;
    for (const auto& file : doc.files) {
        const std::string name = "files/" + file.path;
        auto found = by_name.find(name);
        if (found == by_name.end()) {
            return Fail(error, "COMMUNITY_V2_FILE_COUNT", "files", "declared and actual file sets differ");
        }
        std::vector<uint8_t> bytes;
        if (!read_entry(found->second, &bytes, &extract_error)) {
            return Fail(error, "COMMUNITY_V2_PACKAGE", file.path.c_str(), "cannot read payload");
        }
        if (bytes.size() != file.size) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files", "payload size mismatch");
        }
        if (Sha256HexV2(bytes.data(), bytes.size()) != file.sha256) {
            return Fail(error, "COMMUNITY_V2_HASH", "files", "payload SHA-256 mismatch");
        }
        if (!ValidatePayloadV2(file.path, bytes.data(), bytes.size(), error)) return false;
        actual_paths.insert(file.path);
        actual_total += bytes.size();
        if (actual_total > kMaxTotalBytes) {
            return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "payload exceeds 50 MiB");
        }
    }
    if (actual_total != doc.total_size || doc.file_count != actual_paths.size()) {
        return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "package count/size mismatch");
    }
    if (result) {
        result->path = zip_path;
        result->zip_sha256 = actual_sha;
        result->submission_uid = doc.metadata.submission_uid;
        result->zip_size = zip_size;
        result->file_count = doc.file_count;
        result->total_size = doc.total_size;
    }
    return true;
}

}  // namespace wtu::v2
