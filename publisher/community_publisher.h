#pragma once

#include "community_git_v2.h"
#include "community_package_v2.h"
#include "community_submission_v2.h"

#include <cstdint>
#include <string>

namespace wtu::publisher {

// TP-A: stable publisher-facing structures. This module does not create
// GitHub Releases, write branches, sign indexes, or execute submission files.

enum class PublicationState {
    Received,
    Revalidating,
    Validated,
    Packaging,
    PackageReady,
    ReleaseUploaded,
    IndexPrepared,
    IndexSigned,
    IndexPublished,
    Published,
    ValidationFailed,
    PackageFailed,
    ReleaseFailed,
    IndexFailed,
    SignatureFailed,
    IndexPublishFailed,
};

const char* PublicationStateName(PublicationState state);
bool ParsePublicationState(const std::string& text, PublicationState* state);

struct PublisherConfig {
    // The local bare/worktree repository is used for Git-object validation.
    std::string repository_path;
    std::string repository = "sennjukai/WTCNUP-Submissions-Test";
    std::string base_branch = "main";
    std::string release_branch = "approved-packages";
    std::string index_path = "CommunityIndex.json";
    std::string release_tag_prefix = "community-";
};

struct MergedSubmissionInput {
    std::string repository_path;
    std::string base_sha;
    std::string merge_sha;
    std::string submission_uid;
    std::string pr_author;
    int pr_number = 0;
};

struct MergedSubmissionValidation {
    std::string submission_uid;
    std::string base_sha;
    std::string merge_sha;
    std::string author;
    uint64_t file_count = 0;
    uint64_t total_size = 0;
};

struct PublisherResult {
    PublicationState state = PublicationState::Received;
    std::string code;
    std::string message;
    MergedSubmissionValidation validation;
    v2::PackageV2Result package;
    bool ok() const {
        return state == PublicationState::Validated || state == PublicationState::PackageReady;
    }
};

class TrustedPublisher {
public:
    explicit TrustedPublisher(PublisherConfig config);

    // TP-B: validates a merged submission from trusted Git objects only.
    // The first parent of merge_sha must equal base_sha. The change set must
    // add exactly submissions/<uid>/ and no other path.
    PublisherResult ValidateMerged(const MergedSubmissionInput& input,
                                   v2::SubmissionV2Error* error = nullptr) const;

    // TP-C: validates the merged submission, then builds and verifies a
    // deterministic ZIP. It never creates a Release or updates a branch.
    PublisherResult BuildPackage(const MergedSubmissionInput& input,
                                 const std::string& output_zip,
                                 v2::SubmissionV2Error* error = nullptr) const;

    const PublisherConfig& config() const { return config_; }

private:
    PublisherConfig config_;
};

}  // namespace wtu::publisher
