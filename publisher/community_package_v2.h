#pragma once

#include "community_submission_v2.h"

#include <cstdint>
#include <string>

namespace wtu::v2 {

struct PackageV2Result {
    std::string path;
    std::string zip_sha256;
    uint64_t zip_size = 0;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

struct PackageV2VerifyResult {
    std::string path;
    std::string zip_sha256;
    std::string submission_uid;
    uint64_t zip_size = 0;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

struct SubmissionDocumentV2 {
    SubmissionMetadataV2 metadata;
    std::vector<SubmissionFileV2> files;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

// Parses submission.json into the public document shape. Shared by package
// and Git-object validation; rejects unknown/duplicate-shaped metadata fields.
bool ParseSubmissionJsonV2(const std::string& raw, SubmissionDocumentV2* document,
                           SubmissionV2Error* error = nullptr);

// Builds a deterministic stored ZIP containing submission.json, manifest.json
// and files/<path>. The source directory is validated before writing.
bool BuildSubmissionPackageV2(const std::string& source_dir,
                              const std::string& output_zip,
                              PackageV2Result* result,
                              SubmissionV2Error* error = nullptr);

// Verifies a v2 package independently. Supports stored/deflated ZIPs through
// the existing C++ ZipArchive reader. Does not write or execute payload files.
bool VerifySubmissionPackageV2(const std::string& zip_path,
                               const std::string& expected_sha256,
                               PackageV2VerifyResult* result,
                               SubmissionV2Error* error = nullptr);

}  // namespace wtu::v2
