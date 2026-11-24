#include "community_git_v2.h"

#include "common.h"
#include "community_package_v2.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace wtu::v2 {
namespace {

constexpr uint64_t kMaxTreeBytes = 4ull * 1024 * 1024;
constexpr uint64_t kMaxMetaBytes = 256ull * 1024;
constexpr uint64_t kMaxFileBytes = 10ull * 1024 * 1024;
constexpr uint64_t kMaxTotalBytes = 50ull * 1024 * 1024;
constexpr size_t kMaxFiles = 300;
constexpr size_t kMaxChanged = kMaxFiles + 1;

bool Fail(SubmissionV2Error* error, const char* code, const char* field, const char* message) {
    if (error) {
        error->code = code;
        error->field = field;
        error->message = message;
    }
    return false;
}

bool IsLowerHex(const std::string& value, size_t length) {
    if (value.size() != length) return false;
    for (unsigned char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    return true;
}

bool IsLogin(const std::string& value) {
    if (value.empty() || value.size() > 39) return false;
    if (!std::isalnum(static_cast<unsigned char>(value.front()))) return false;
    if (!std::isalnum(static_cast<unsigned char>(value.back()))) return false;
    for (unsigned char ch : value) {
        if (!(std::isalnum(ch) || ch == '-')) return false;
    }
    return true;
}

bool IsUuidV4(const std::string& value) {
    if (value.size() != 36) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return value[14] == '4' && (value[19] == '8' || value[19] == '9' ||
                                value[19] == 'a' || value[19] == 'b');
}

bool IEqualsAscii(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

#if defined(_WIN32)
std::wstring QuoteWindowsArg(const std::wstring& value) {
    if (value.empty()) return L"\"\"";
    if (value.find_first_of(L" \t\n\v\"") == std::wstring::npos) return value;
    std::wstring out = L"\"";
    for (size_t i = 0; i < value.size(); ++i) {
        size_t backslashes = 0;
        while (i < value.size() && value[i] == L'\\') {
            ++backslashes;
            ++i;
        }
        if (i == value.size()) {
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (value[i] == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(value[i]);
        }
    }
    out.push_back(L'"');
    return out;
}

bool RunGit(const std::vector<std::string>& args, uint64_t max_bytes,
            std::vector<uint8_t>* out, SubmissionV2Error* error) {
    std::wstring exe = GetEnv(L"WTU_GIT_EXE");
    if (exe.empty()) exe = L"git";
    std::wstring command = QuoteWindowsArg(exe);
    for (const std::string& arg : args) command += L" " + QuoteWindowsArg(Utf8ToWide(arg));

    static std::atomic<unsigned> counter{0};
    std::error_code temp_error;
    // Use a closed, private temp directory in the current working directory.
    // Some runner sandboxes deny creating files directly in the 8.3 TEMP path.
    const std::filesystem::path temp_dir = std::filesystem::current_path(temp_error);
    if (temp_error) {
        return Fail(error, "COMMUNITY_GIT", "git", "cannot get temp path");
    }
    const std::filesystem::path temp_root = temp_dir /
        (L"wtcnup-git-" + std::to_wstring(GetCurrentProcessId()));
    std::filesystem::create_directories(temp_root, temp_error);
    if (temp_error) {
        return Fail(error, "COMMUNITY_GIT", "git", "cannot create git temp directory");
    }
    const std::filesystem::path temp_path = temp_root /
        (L"out-" + std::to_wstring(counter.fetch_add(1)) + L".out");
    const std::wstring temp_file = temp_path.wstring();
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE output = CreateFileW(temp_file.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ, &inherit, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (output == INVALID_HANDLE_VALUE) {
        if (error) {
            error->code = "COMMUNITY_GIT";
            error->field = "git";
            error->message = "cannot create git output file: " + std::to_string(GetLastError()) +
                             " path=" + WideToUtf8(temp_file);
        }
        return false;
    }
    HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = output;
    startup.hStdError = nul == INVALID_HANDLE_VALUE ? output : nul;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> writable(command.begin(), command.end());
    writable.push_back(L'\0');
    BOOL created = CreateProcessW(nullptr, writable.data(), nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(output);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!created) {
        DeleteFileW(temp_file.c_str());
        return Fail(error, "COMMUNITY_GIT", "git", "git is unavailable");
    }
    const DWORD wait = WaitForSingleObject(process.hProcess, 60000);
    DWORD exit_code = 1;
    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(process.hProcess, 1);
    }
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    HANDLE read = CreateFileW(temp_file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (read == INVALID_HANDLE_VALUE) {
        DeleteFileW(temp_file.c_str());
        return Fail(error, "COMMUNITY_GIT", "git", "cannot read git output");
    }
    LARGE_INTEGER size{};
    GetFileSizeEx(read, &size);
    if (size.QuadPart > static_cast<LONGLONG>(max_bytes)) {
        CloseHandle(read);
        DeleteFileW(temp_file.c_str());
        return Fail(error, "COMMUNITY_GIT", "git", "git output exceeds limit");
    }
    out->assign(static_cast<size_t>(size.QuadPart), 0);
    DWORD read_bytes = 0;
    if (!out->empty() &&
        (!ReadFile(read, out->data(), static_cast<DWORD>(out->size()), &read_bytes, nullptr) ||
         read_bytes != out->size())) {
        CloseHandle(read);
        DeleteFileW(temp_file.c_str());
        return Fail(error, "COMMUNITY_GIT", "git", "cannot read git output");
    }
    CloseHandle(read);
    DeleteFileW(temp_file.c_str());
    std::error_code cleanup_error;
    std::filesystem::remove_all(temp_root, cleanup_error);
    if (wait == WAIT_TIMEOUT) {
        return Fail(error, "COMMUNITY_GIT", "git", "git command timed out");
    }
    if (exit_code != 0) {
        if (error) {
            error->code = "COMMUNITY_GIT";
            error->field = "git";
            error->message = "git command failed: exit=" + std::to_string(exit_code) +
                             " command=" + WideToUtf8(command);
        }
        return false;
    }
    return true;
}
#else
bool RunGit(const std::vector<std::string>&, uint64_t, std::vector<uint8_t>*,
            SubmissionV2Error* error) {
    return Fail(error, "COMMUNITY_GIT", "git", "git runner not implemented on this platform");
}
#endif

bool ParseChanges(const std::vector<uint8_t>& raw,
                  std::vector<std::pair<char, std::string>>* changes,
                  SubmissionV2Error* error) {
    changes->clear();
    size_t pos = 0;
    while (pos < raw.size()) {
        const size_t status_end = pos;
        while (pos < raw.size() && raw[pos] != 0) ++pos;
        if (pos == status_end || pos + 1 >= raw.size()) {
            return Fail(error, "COMMUNITY_GIT", "git", "invalid git diff");
        }
        const std::string status(reinterpret_cast<const char*>(raw.data() + status_end),
                                 pos - status_end);
        if (status.size() != 1) return Fail(error, "COMMUNITY_GIT", "git", "invalid git status");
        ++pos;  // NUL
        const size_t name_begin = pos;
        while (pos < raw.size() && raw[pos] != 0) ++pos;
        if (pos == name_begin) return Fail(error, "COMMUNITY_GIT", "git", "invalid git path");
        const std::string path(reinterpret_cast<const char*>(raw.data() + name_begin),
                               pos - name_begin);
        if (pos < raw.size()) ++pos;  // NUL
        changes->emplace_back(status[0], path);
    }
    return true;
}

struct TreeEntry {
    std::string mode;
    std::string type;
    std::string oid;
};

bool ParseTree(const std::vector<uint8_t>& raw, std::map<std::string, TreeEntry>* entries,
               SubmissionV2Error* error) {
    entries->clear();
    size_t pos = 0;
    while (pos < raw.size()) {
        const size_t tab = std::find(raw.begin() + static_cast<ptrdiff_t>(pos), raw.end(), '\t') - raw.begin();
        if (tab >= raw.size()) return Fail(error, "COMMUNITY_GIT", "git", "invalid git tree");
        const std::string info(reinterpret_cast<const char*>(raw.data() + pos), tab - pos);
        std::istringstream stream(info);
        TreeEntry entry;
        if (!(stream >> entry.mode >> entry.type >> entry.oid)) {
            return Fail(error, "COMMUNITY_GIT", "git", "invalid git tree");
        }
        pos = tab + 1;
        const size_t name_begin = pos;
        while (pos < raw.size() && raw[pos] != 0) ++pos;
        const std::string name(reinterpret_cast<const char*>(raw.data() + name_begin),
                               pos - name_begin);
        if (pos < raw.size()) ++pos;
        if (name.empty() || !entries->emplace(name, entry).second) {
            return Fail(error, "COMMUNITY_GIT", "git", "duplicate or invalid git tree entry");
        }
    }
    return true;
}

bool ReadBlob(const std::string& repo, const std::string& oid, uint64_t limit,
              std::vector<uint8_t>* out, SubmissionV2Error* error) {
    std::vector<uint8_t> size_raw;
    if (!RunGit({"-C", repo, "cat-file", "-s", oid}, 128, &size_raw, error)) return false;
    std::string size_text(size_raw.begin(), size_raw.end());
    while (!size_text.empty() && std::isspace(static_cast<unsigned char>(size_text.back()))) {
        size_text.pop_back();
    }
    uint64_t size = 0;
    try {
        size = std::stoull(size_text);
    } catch (...) {
        return Fail(error, "COMMUNITY_GIT", "git", "invalid blob size");
    }
    if (size > limit) return Fail(error, "COMMUNITY_GIT", "git", "blob too large");
    if (!RunGit({"-C", repo, "cat-file", "blob", oid}, size, out, error)) return false;
    if (out->size() != size) return Fail(error, "COMMUNITY_GIT", "git", "blob size mismatch");
    return true;
}

}  // namespace

bool ReadGitCommitParentsV2(const std::string& repo,
                            const std::string& commit,
                            std::vector<std::string>* parents,
                            SubmissionV2Error* error) {
    if (error) *error = SubmissionV2Error{};
    if (parents) parents->clear();
    if (!IsLowerHex(commit, 40)) {
        return Fail(error, "COMMUNITY_GIT", "commit", "invalid commit SHA");
    }
    std::vector<uint8_t> raw;
    if (!RunGit({"-C", repo, "rev-list", "--parents", "-n", "1", commit},
                4096, &raw, error)) {
        return false;
    }
    std::istringstream input(std::string(raw.begin(), raw.end()));
    std::string current;
    std::vector<std::string> values;
    while (input >> current) values.push_back(current);
    if (values.empty() || values.front() != commit || values.size() < 2) {
        return Fail(error, "COMMUNITY_GIT", "commit", "commit has no readable parent");
    }
    for (size_t i = 1; i < values.size(); ++i) {
        if (!IsLowerHex(values[i], 40)) {
            return Fail(error, "COMMUNITY_GIT", "commit", "invalid parent SHA");
        }
        if (parents) parents->push_back(values[i]);
    }
    return true;
}

bool ValidateGitSubmissionV2(const std::string& repo,
                             const std::string& base,
                             const std::string& head,
                             const std::string& author,
                             const std::string& branch,
                             GitV2ValidationResult* result,
                             SubmissionV2Error* error,
                             GitV2Submission* loaded) {
    if (error) *error = SubmissionV2Error{};
    if (loaded) *loaded = GitV2Submission{};
    if (!IsLowerHex(base, 40) || !IsLowerHex(head, 40) || base == head) {
        return Fail(error, "COMMUNITY_GIT", "base/head", "invalid commit SHA");
    }
    if (!IsLogin(author)) return Fail(error, "COMMUNITY_GIT", "author", "invalid PR author");
    static const std::string kPrefix = "wtcnup/submission-";
    if (branch.rfind(kPrefix, 0) != 0) {
        return Fail(error, "COMMUNITY_GIT", "branch", "invalid branch");
    }
    const std::string uid = branch.substr(kPrefix.size());
    if (!IsUuidV4(uid)) return Fail(error, "COMMUNITY_GIT", "branch", "invalid branch UID");

    const std::string prefix = "submissions/" + uid + "/";
    const std::string metadata_path = prefix + "submission.json";
    const std::string files_prefix = prefix + "files/";
    std::vector<uint8_t> diff;
    if (!RunGit({"-C", repo, "-c", "core.quotepath=false", "diff", "--no-ext-diff",
                 "--no-textconv", "--no-renames", "--name-status", "-z", base, head, "--"},
                kMaxTreeBytes, &diff, error)) return false;
    std::vector<std::pair<char, std::string>> changes;
    if (!ParseChanges(diff, &changes, error)) return false;
    if (changes.size() < 2 || changes.size() > kMaxChanged) {
        if (error) {
            error->code = "COMMUNITY_GIT";
            error->field = "changed";
            error->message = "invalid changed-file count: " + std::to_string(changes.size()) +
                             " bytes=" + std::to_string(diff.size());
        }
        return false;
    }
    std::set<std::string> changed_names;
    for (const auto& [status, name] : changes) {
        if (status != 'A') {
            return Fail(error, "COMMUNITY_GIT", name.c_str(), "PR may only add submission files");
        }
        if (name != metadata_path && name.rfind(files_prefix, 0) != 0) {
            return Fail(error, "COMMUNITY_GIT", name.c_str(), "unexpected changed path");
        }
        if (!changed_names.insert(name).second) {
            return Fail(error, "COMMUNITY_GIT", name.c_str(), "duplicate changed path");
        }
    }
    std::vector<uint8_t> tree_raw;
    if (!RunGit({"-C", repo, "-c", "core.quotepath=false", "ls-tree", "-r", "-z",
                 "--full-tree", head, "--", prefix}, kMaxTreeBytes, &tree_raw, error)) return false;
    std::map<std::string, TreeEntry> tree;
    if (!ParseTree(tree_raw, &tree, error)) return false;
    if (tree.size() != changed_names.size()) {
        return Fail(error, "COMMUNITY_GIT", "tree", "tree and change set differ");
    }
    for (const auto& name : changed_names) {
        if (!tree.count(name)) return Fail(error, "COMMUNITY_GIT", "tree", "tree and change set differ");
    }
    if (!tree.count(metadata_path)) {
        return Fail(error, "COMMUNITY_GIT", "submission.json", "missing submission.json");
    }
    for (const auto& [name, entry] : tree) {
        if (entry.mode != "100644" || entry.type != "blob" || !IsLowerHex(entry.oid, 40)) {
            return Fail(error, "COMMUNITY_GIT", name.c_str(), "only regular Git blobs are allowed");
        }
    }

    std::vector<uint8_t> metadata_bytes;
    if (!ReadBlob(repo, tree[metadata_path].oid, kMaxMetaBytes, &metadata_bytes, error)) return false;
    const std::string metadata_text(metadata_bytes.begin(), metadata_bytes.end());
    SubmissionDocumentV2 document;
    if (!ParseSubmissionJsonV2(metadata_text, &document, error)) return false;
    if (loaded) loaded->submission_json = metadata_text;
    if (document.metadata.submission_uid != uid) {
        return Fail(error, "COMMUNITY_GIT", "submission_uid", "UID does not match branch");
    }
    if (!IEqualsAscii(document.metadata.github_user, author)) {
        return Fail(error, "COMMUNITY_GIT", "github_user", "PR author mismatch");
    }
    SubmissionScanV2 scan;
    scan.files = document.files;
    scan.file_count = document.file_count;
    scan.total_size = document.total_size;
    if (!ValidateSubmissionMetadataV2(document.metadata, scan, error)) return false;

    std::map<std::string, TreeEntry> actual;
    for (const auto& [name, entry] : tree) {
        if (name.rfind(files_prefix, 0) == 0) {
            actual[name.substr(files_prefix.size())] = entry;
        }
    }
    std::set<std::string> declared;
    for (const auto& file : document.files) declared.insert(file.path);
    if (actual.size() != declared.size()) {
        return Fail(error, "COMMUNITY_GIT", "files", "declared and actual file sets differ");
    }
    uint64_t total = 0;
    for (const auto& file : document.files) {
        auto found = actual.find(file.path);
        if (found == actual.end()) {
            return Fail(error, "COMMUNITY_GIT", "files", "declared and actual file sets differ");
        }
        std::vector<uint8_t> bytes;
        if (!ReadBlob(repo, found->second.oid, kMaxFileBytes, &bytes, error)) return false;
        if (bytes.size() != file.size) {
            return Fail(error, "COMMUNITY_V2_SIZE", "files.size", "file size mismatch");
        }
        if (Sha256HexV2(bytes.data(), bytes.size()) != file.sha256) {
            return Fail(error, "COMMUNITY_V2_HASH", "files.sha256", "file SHA-256 mismatch");
        }
        if (!ValidatePayloadV2(file.path, bytes.data(), bytes.size(), error)) return false;
        total += bytes.size();
        if (total > kMaxTotalBytes) {
            return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "submission too large");
        }
        if (loaded) {
            loaded->files.push_back(file);
            loaded->payloads.push_back(std::move(bytes));
        }
    }
    if (total != document.total_size) {
        return Fail(error, "COMMUNITY_V2_TOTAL_SIZE", "total_size", "total size mismatch");
    }
    if (result) {
        result->uid = uid;
        result->base = base;
        result->head = head;
        result->file_count = actual.size();
        result->total_size = total;
    }
    return true;
}

}  // namespace wtu::v2
