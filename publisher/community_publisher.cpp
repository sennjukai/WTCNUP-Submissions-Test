#include "community_publisher.h"

#include "community_pipeline_v2.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace wtu::publisher {

const char* PublicationStateName(PublicationState state) {
    switch (state) {
        case PublicationState::Received: return "RECEIVED";
        case PublicationState::Revalidating: return "REVALIDATING";
        case PublicationState::Validated: return "VALIDATED";
        case PublicationState::Packaging: return "PACKAGING";
        case PublicationState::PackageReady: return "PACKAGE_READY";
        case PublicationState::ReleaseUploaded: return "RELEASE_UPLOADED";
        case PublicationState::IndexPrepared: return "INDEX_PREPARED";
        case PublicationState::IndexSigned: return "INDEX_SIGNED";
        case PublicationState::IndexPublished: return "INDEX_PUBLISHED";
        case PublicationState::Published: return "PUBLISHED";
        case PublicationState::ValidationFailed: return "VALIDATION_FAILED";
        case PublicationState::PackageFailed: return "PACKAGE_FAILED";
        case PublicationState::ReleaseFailed: return "RELEASE_FAILED";
        case PublicationState::IndexFailed: return "INDEX_FAILED";
        case PublicationState::SignatureFailed: return "SIGNATURE_FAILED";
        case PublicationState::IndexPublishFailed: return "INDEX_PUBLISH_FAILED";
    }
    return "UNKNOWN";
}

bool ParsePublicationState(const std::string& text, PublicationState* state) {
    for (PublicationState candidate : {
             PublicationState::Received, PublicationState::Revalidating,
             PublicationState::Validated, PublicationState::Packaging,
             PublicationState::PackageReady, PublicationState::ReleaseUploaded,
             PublicationState::IndexPrepared, PublicationState::IndexSigned,
             PublicationState::IndexPublished, PublicationState::Published,
             PublicationState::ValidationFailed, PublicationState::PackageFailed,
             PublicationState::ReleaseFailed, PublicationState::IndexFailed,
             PublicationState::SignatureFailed, PublicationState::IndexPublishFailed}) {
        if (text == PublicationStateName(candidate)) {
            if (state) *state = candidate;
            return true;
        }
    }
    return false;
}

TrustedPublisher::TrustedPublisher(PublisherConfig config) : config_(std::move(config)) {}

PublisherResult TrustedPublisher::ValidateMerged(const MergedSubmissionInput& input,
                                                 v2::SubmissionV2Error* error) const {
    PublisherResult result;
    result.state = PublicationState::Revalidating;
    if (error) *error = v2::SubmissionV2Error{};
    auto fail = [&](const char* code, const char* field, const char* message) {
        result.state = PublicationState::ValidationFailed;
        result.code = code;
        result.message = message;
        if (error) {
            error->code = code;
            error->field = field;
            error->message = message;
        }
        return result;
    };

    const std::string repo = input.repository_path.empty() ? config_.repository_path
                                                           : input.repository_path;
    if (repo.empty()) return fail("COMMUNITY_PUBLISHER_REPO", "repository", "repository path is empty");
    if (input.pr_number <= 0) return fail("COMMUNITY_PUBLISHER_PR", "pr_number", "invalid PR number");
    if (input.submission_uid.empty()) {
        return fail("COMMUNITY_PUBLISHER_UID", "submission_uid", "submission UID is empty");
    }

    std::vector<std::string> parents;
    if (!v2::ReadGitCommitParentsV2(repo, input.merge_sha, &parents, error)) {
        result.state = PublicationState::ValidationFailed;
        result.code = error ? error->code : "COMMUNITY_GIT";
        result.message = error ? error->message : "cannot read merge commit";
        return result;
    }
    if (parents.empty() || parents.front() != input.base_sha) {
        return fail("COMMUNITY_PUBLISHER_MERGE_BASE", "merge_sha",
                    "merge commit first parent does not match base SHA");
    }

    v2::GitV2ValidationResult validated;
    const std::string branch = "wtcnup/submission-" + input.submission_uid;
    if (!v2::ValidateGitSubmissionV2(repo, input.base_sha, input.merge_sha, input.pr_author,
                                     branch, &validated, error)) {
        result.state = PublicationState::ValidationFailed;
        result.code = error ? error->code : "COMMUNITY_GIT";
        result.message = error ? error->message : "merged submission validation failed";
        return result;
    }
    if (validated.uid != input.submission_uid) {
        return fail("COMMUNITY_PUBLISHER_UID", "submission_uid", "validated UID differs from input");
    }
    result.state = PublicationState::Validated;
    result.code = "OK";
    result.validation.submission_uid = validated.uid;
    result.validation.base_sha = validated.base;
    result.validation.merge_sha = validated.head;
    result.validation.author = input.pr_author;
    result.validation.file_count = validated.file_count;
    result.validation.total_size = validated.total_size;
    return result;
}

PublisherResult TrustedPublisher::BuildPackage(const MergedSubmissionInput& input,
                                               const std::string& output_zip,
                                               v2::SubmissionV2Error* error) const {
    PublisherResult result = ValidateMerged(input, error);
    if (result.state != PublicationState::Validated) return result;
    result.state = PublicationState::Packaging;
    if (output_zip.empty()) {
        result.state = PublicationState::PackageFailed;
        result.code = "COMMUNITY_PUBLISHER_PACKAGE";
        result.message = "output ZIP path is empty";
        if (error) {
            error->code = result.code;
            error->field = "package";
            error->message = result.message;
        }
        return result;
    }

    v2::PipelineV2Result package;
    const std::string repo = input.repository_path.empty() ? config_.repository_path
                                                           : input.repository_path;
    const std::string branch = "wtcnup/submission-" + input.submission_uid;
    if (!v2::RunTrustedPipelineV2(repo, input.base_sha, input.merge_sha, input.pr_author,
                                  branch, output_zip, &package, error)) {
        result.state = PublicationState::PackageFailed;
        result.code = error ? error->code : "COMMUNITY_PUBLISHER_PACKAGE";
        result.message = error ? error->message : "package build failed";
        return result;
    }
    result.state = PublicationState::PackageReady;
    result.code = "OK";
    result.message.clear();
    result.package.path = package.zip_path;
    result.package.zip_sha256 = package.zip_sha256;
    result.package.zip_size = package.zip_size;
    result.package.file_count = package.file_count;
    result.package.total_size = package.total_size;
    return result;
}

}  // namespace wtu::publisher
