#pragma once

// Phase 3.3.2-B: independent Schema v2 core.
// This file deliberately does not include common.h/windows.h so the core can
// be compiled on a non-Windows runner. It is not wired into the legacy v1
// submission path.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wtu::v2 {

struct SubmissionFileV2 {
    // UTF-8, '/'-separated relative path (for example "lang/chinese.csv").
    std::string path;
    // UTF-8 full path used by local validation; never serialized.
    std::string full_path;
    uint64_t size = 0;
    std::string sha256;  // lowercase 64 hex
};

struct SubmissionScanV2 {
    std::vector<SubmissionFileV2> files;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

struct SubmissionMetadataV2 {
    // Included for explicit schema-version validation; Build always emits 2.
    int schema_version = 2;

    std::string author_name;
    std::string github_user;
    std::optional<std::string> project_id;  // nullopt = omit (or explicit null via mode)
    std::string project_name;
    std::string game_version;
    std::string translation_version;
    std::string channel;  // stable | beta

    // nullopt means the required field is missing; an empty string is valid.
    std::optional<std::string> changelog;

    std::string created_at;      // RFC3339 UTC, e.g. 2026-11-23T00:00:00Z
    std::string submission_uid;  // lowercase UUID v4
};

struct SubmissionV2Error {
    std::string code;
    std::string field;
    std::string message;
};

enum class ProjectIdOutput {
    Omit,  // valid when project_id is nullopt
    Null,  // emit an explicit JSON null
};

// RFC 4122/9562 UUID v4, lowercase, using the platform CSPRNG.
std::string GenerateSubmissionUidV4();
std::string UtcNowV2();

// Validates metadata and the shape/path/limits of the scan. Does not open
// file.full_path; used by package verifiers that already hold payload bytes.
bool ValidateSubmissionMetadataV2(const SubmissionMetadataV2& metadata,
                                  const SubmissionScanV2& scan,
                                  SubmissionV2Error* error = nullptr);

// Validates one payload by path/bytes (magic, CSV/BLK, UTF-8, controls).
bool ValidatePayloadV2(const std::string& path, const void* data, size_t size,
                       SubmissionV2Error* error = nullptr);

// Shared path-vector surface used by the C++/Python cross-vector tests.
bool ValidatePathV2(const std::string& path, SubmissionV2Error* error = nullptr);
std::string PathCollisionKeyV2(const std::string& path);

// Validates metadata and the actual bytes at every file.full_path.
// The supplied size/sha256 values are not trusted: they must match the file.
bool ValidateSubmissionV2Local(const SubmissionMetadataV2& metadata,
                               const SubmissionScanV2& scan,
                               SubmissionV2Error* error = nullptr);

// Validates first, then returns deterministic UTF-8 JSON. Returns empty string
// and fills error on failure.
std::string BuildSubmissionJsonV2(const SubmissionMetadataV2& metadata,
                                  const SubmissionScanV2& scan,
                                  ProjectIdOutput project_id_output = ProjectIdOutput::Omit,
                                  SubmissionV2Error* error = nullptr);

// Exposed for tests and adapters; returns lowercase hex.
std::string Sha256HexV2(const void* data, size_t size);
std::string Sha256FileHexV2(const std::string& utf8_path, bool* ok = nullptr);

}  // namespace wtu::v2
