#pragma once

#include "community_git_v2.h"

#include <cstdint>
#include <string>

namespace wtu::v2 {

struct PipelineV2Result {
    std::string uid;
    std::string base;
    std::string head;
    std::string zip_path;
    std::string zip_sha256;
    uint64_t zip_size = 0;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

// Trusted C++ pipeline: Git objects -> validated v2 source -> C++ ZIP -> verify.
// Does not check out or execute submission content; no Python is invoked.
bool RunTrustedPipelineV2(const std::string& repo,
                          const std::string& base,
                          const std::string& head,
                          const std::string& author,
                          const std::string& branch,
                          const std::string& output_zip,
                          PipelineV2Result* result,
                          SubmissionV2Error* error = nullptr);

}  // namespace wtu::v2
