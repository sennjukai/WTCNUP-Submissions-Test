#include "community_publisher.h"

#include "common.h"

#include <iostream>
#include <string>

namespace {

int Fail(const std::string& message) {
    std::cerr << "FAIL " << message << "\n";
    return 1;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return Fail("commands: validate-merged | build-package");
    const std::wstring command = argv[1];
    if (command != L"validate-merged" && command != L"build-package") {
        return Fail("unsupported command (TP-A/TP-B/TP-C supports validate-merged and build-package)");
    }
    wtu::publisher::MergedSubmissionInput input;
    std::string output_zip;
    for (int i = 2; i + 1 < argc; i += 2) {
        const std::wstring key = argv[i];
        const std::string value = wtu::WideToUtf8(argv[i + 1]);
        if (key == L"--repo") input.repository_path = value;
        else if (key == L"--base") input.base_sha = value;
        else if (key == L"--head") input.merge_sha = value;
        else if (key == L"--uid") input.submission_uid = value;
        else if (key == L"--author") input.pr_author = value;
        else if (key == L"--pr") {
            try {
                input.pr_number = std::stoi(value);
            } catch (...) {
                return Fail("invalid --pr");
            }
        } else if (key == L"--out") {
            output_zip = value;
        } else {
            return Fail("unknown argument");
        }
    }
    if (input.repository_path.empty() || input.base_sha.empty() || input.merge_sha.empty() ||
        input.submission_uid.empty() || input.pr_author.empty() || input.pr_number <= 0) {
        return Fail("missing required argument");
    }

    wtu::publisher::PublisherConfig config;
    config.repository_path = input.repository_path;
    wtu::publisher::TrustedPublisher publisher(config);
    wtu::v2::SubmissionV2Error error;
    wtu::publisher::PublisherResult result =
        command == L"validate-merged" ? publisher.ValidateMerged(input, &error)
                                      : publisher.BuildPackage(input, output_zip, &error);
    if (!result.ok()) {
        std::cerr << "FAIL " << result.code << " " << result.message << "\n";
        return 1;
    }
    std::cout << "PASS " << result.validation.submission_uid << " "
              << result.validation.base_sha << " " << result.validation.merge_sha << " "
              << result.validation.author << " " << result.validation.file_count << " "
              << result.validation.total_size << " " << wtu::publisher::PublicationStateName(result.state);
    if (result.state == wtu::publisher::PublicationState::PackageReady) {
        std::cout << " " << result.package.zip_sha256 << " " << result.package.zip_size;
    }
    std::cout << "\n";
    return 0;
}
