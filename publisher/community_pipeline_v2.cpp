#include "community_pipeline_v2.h"

#include "community_package_v2.h"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>

namespace wtu::v2 {
namespace {

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

bool Fail(SubmissionV2Error* error, const char* code, const char* field, const char* message) {
    if (error) {
        error->code = code;
        error->field = field;
        error->message = message;
    }
    return false;
}

bool WriteBytes(const std::filesystem::path& path, const std::string& text) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) return false;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    return out.good();
}

}  // namespace

bool RunTrustedPipelineV2(const std::string& repo,
                          const std::string& base,
                          const std::string& head,
                          const std::string& author,
                          const std::string& branch,
                          const std::string& output_zip,
                          PipelineV2Result* result,
                          SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    GitV2ValidationResult validated;
    GitV2Submission loaded;
    if (!ValidateGitSubmissionV2(repo, base, head, author, branch, &validated, error, &loaded)) {
        return false;
    }

    static std::atomic<unsigned> counter{0};
    std::error_code ec;
    const std::filesystem::path root = std::filesystem::current_path(ec) /
        (L"wtcnup-pipeline-" + std::to_wstring(counter.fetch_add(1)));
    if (ec) return Fail(error, "COMMUNITY_PIPELINE", "temp", "cannot get current path");
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / "files", ec);
    if (ec) return Fail(error, "COMMUNITY_PIPELINE", "temp", "cannot create temp source");

    bool ok = WriteBytes(root / "submission.json", loaded.submission_json);
    if (ok) {
        for (size_t i = 0; i < loaded.files.size(); ++i) {
            std::string path = loaded.files[i].path;
            std::filesystem::path target = root / "files" / PathFromUtf8(path);
            std::string content(loaded.payloads[i].begin(), loaded.payloads[i].end());
            if (!WriteBytes(target, content)) {
                ok = false;
                break;
            }
        }
    }
    if (!ok) {
        std::filesystem::remove_all(root, ec);
        return Fail(error, "COMMUNITY_PIPELINE", "temp", "cannot write validated source");
    }

    PackageV2Result packaged;
    if (!BuildSubmissionPackageV2(PathToUtf8(root), output_zip, &packaged, error)) {
        std::filesystem::remove_all(root, ec);
        return false;
    }
    PackageV2VerifyResult verified;
    if (!VerifySubmissionPackageV2(output_zip, packaged.zip_sha256, &verified, error)) {
        std::filesystem::remove_all(root, ec);
        return false;
    }
    std::filesystem::remove_all(root, ec);

    if (result) {
        result->uid = validated.uid;
        result->base = base;
        result->head = head;
        result->zip_path = output_zip;
        result->zip_sha256 = packaged.zip_sha256;
        result->zip_size = packaged.zip_size;
        result->file_count = packaged.file_count;
        result->total_size = packaged.total_size;
    }
    return true;
}

}  // namespace wtu::v2
