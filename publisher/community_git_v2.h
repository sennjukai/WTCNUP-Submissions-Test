#pragma once

#include "community_submission_v2.h"

#include <cstdint>
#include <string>
#include <vector>

namespace wtu::v2 {

struct GitV2ValidationResult {
    std::string uid;
    std::string base;
    std::string head;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

struct GitV2Submission {
    std::string submission_json;
    std::vector<SubmissionFileV2> files;
    std::vector<std::vector<uint8_t>> payloads;
};

// Reads Git objects only; never checks out or executes submission files.
// `repo` may be a worktree or bare repository, with exact base/head SHAs.
// Reads commit parents without checkout or execution.
bool ReadGitCommitParentsV2(const std::string& repo,
                            const std::string& commit,
                            std::vector<std::string>* parents,
                            SubmissionV2Error* error = nullptr);

bool ValidateGitSubmissionV2(const std::string& repo,
                             const std::string& base,
                             const std::string& head,
                             const std::string& author,
                             const std::string& branch,
                             GitV2ValidationResult* result,
                             SubmissionV2Error* error = nullptr,
                             GitV2Submission* loaded = nullptr);

}  // namespace wtu::v2
