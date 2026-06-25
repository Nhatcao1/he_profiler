#include <chrono>
#include <array>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <streambuf>
#include <string>

#ifdef HE_PROFILER_WITH_OPENFHE
#include "binfhecontext-ser.h"
#endif

namespace {

struct CliArgs {
    std::filesystem::path secret_key_path = "client/private/secret_key.bin";
    std::filesystem::path response_ct_path = "client/incoming/response_ct.bin";
    std::filesystem::path log_path = "logs/client_decrypt.log";
    std::string context_id = "synthetic-v1";
};

constexpr std::array<const char*, 8> kCompanyNames = {
    "Unknown",
    "Viettel",
    "VNPT/VinaPhone",
    "MobiFone",
    "Vietnamobile",
    "Gmobile",
    "Hanoi Landline",
    "HCMC Landline",
};

class TeeBuf : public std::streambuf {
public:
    TeeBuf(std::streambuf* first, std::streambuf* second) : first_(first), second_(second) {}

private:
    int overflow(int ch) override {
        if (ch == EOF) {
            return !EOF;
        }
        const int first_result = first_->sputc(static_cast<char>(ch));
        const int second_result = second_->sputc(static_cast<char>(ch));
        return (first_result == EOF || second_result == EOF) ? EOF : ch;
    }

    int sync() override {
        const int first_result = first_->pubsync();
        const int second_result = second_->pubsync();
        return (first_result == 0 && second_result == 0) ? 0 : -1;
    }

    std::streambuf* first_;
    std::streambuf* second_;
};

class ScopedLog {
public:
    explicit ScopedLog(const std::filesystem::path& path)
        : out_tee_(std::cout.rdbuf(), log_file_.rdbuf()),
          err_tee_(std::cerr.rdbuf(), log_file_.rdbuf()) {
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
        log_file_.open(path, std::ios::out | std::ios::trunc);
        if (log_file_) {
            old_out_ = std::cout.rdbuf(&out_tee_);
            old_err_ = std::cerr.rdbuf(&err_tee_);
            enabled_ = true;
        }
    }

    ~ScopedLog() {
        if (enabled_) {
            std::cout.rdbuf(old_out_);
            std::cerr.rdbuf(old_err_);
        }
    }

private:
    std::ofstream log_file_;
    TeeBuf out_tee_;
    TeeBuf err_tee_;
    std::streambuf* old_out_ = nullptr;
    std::streambuf* old_err_ = nullptr;
    bool enabled_ = false;
};

using Clock = std::chrono::steady_clock;

double elapsed_ms(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

CliArgs parse_args(int argc, char** argv) {
    CliArgs args;

    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--context") {
            if (++i >= argc) {
                throw std::runtime_error("--context requires a path");
            }
            std::cout << "[client] --context is ignored; context is recreated from agreed params\n";
        } else if (flag == "--secret-key") {
            if (++i >= argc) {
                throw std::runtime_error("--secret-key requires a path");
            }
            args.secret_key_path = argv[i];
        } else if (flag == "--response-ct") {
            if (++i >= argc) {
                throw std::runtime_error("--response-ct requires a path");
            }
            args.response_ct_path = argv[i];
        } else if (flag == "--context-id") {
            if (++i >= argc) {
                throw std::runtime_error("--context-id requires a value");
            }
            args.context_id = argv[i];
        } else if (flag == "--log") {
            if (++i >= argc) {
                throw std::runtime_error("--log requires a path");
            }
            args.log_path = argv[i];
        } else {
            throw std::runtime_error("unknown argument: " + flag);
        }
    }

    return args;
}

const char* company_name(std::size_t code) {
    if (code >= kCompanyNames.size()) {
        return "Invalid";
    }
    return kCompanyNames[code];
}

std::uint64_t fnv1a_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("could not read file for fingerprint: " + path.string());
    }

    std::uint64_t hash = 1469598103934665603ULL;
    char ch = 0;
    while (f.get(ch)) {
        hash ^= static_cast<unsigned char>(ch);
        hash *= 1099511628211ULL;
    }
    return hash;
}

void print_artifact(const std::string& label, const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    const auto hash = fnv1a_file(path);
    std::cout << label << ": " << path
              << " bytes=" << size
              << " fnv1a64=0x" << std::hex << std::setw(16) << std::setfill('0')
              << hash << std::dec << std::setfill(' ') << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const CliArgs args = parse_args(argc, argv);
        ScopedLog log(args.log_path);
        const auto total_start = Clock::now();
        std::cout << "[client-log] writing_log=" << args.log_path << "\n";

#ifdef HE_PROFILER_WITH_OPENFHE
        using lbcrypto::BinFHEContext;
        using lbcrypto::GINX;
        using lbcrypto::LWECiphertext;
        using lbcrypto::LWEPlaintext;
        using lbcrypto::LWEPrivateKey;
        using lbcrypto::TOY;

        constexpr std::uint32_t kRingDim = 1024;
        constexpr std::uint32_t kLogQ = 12;

        std::cout << "[client] recreating local context and loading secret key\n";
        std::cout << "[client-view] visible_before_decrypt=secret_key.bin,response_ct.bin,context_params\n";
        std::cout << "[client-view] response_ct_is_ciphertext=true\n";
        std::cout << "[client-view] company_code_visible_before_decrypt=false\n";
        std::cout << "[client-report] context_id=" << args.context_id << "\n";
        std::cout << "[client-report] binfhe_paramset=TOY method=GINX arbitrary_function=true logQ="
                  << kLogQ << " ringDim=" << kRingDim << "\n";
        std::cout << "[client-report] context_recreated_from_params=true\n";
        print_artifact("  secret_key", args.secret_key_path);
        print_artifact("  response_ct", args.response_ct_path);

        const auto context_start = Clock::now();
        BinFHEContext cc;
        cc.GenerateBinFHEContext(TOY, true, kLogQ, kRingDim, GINX, false);
        const auto context_end = Clock::now();
        std::cout << "[client-time] recreate_context_ms=" << elapsed_ms(context_start, context_end) << "\n";

        std::cout << "[client] reading secret key; it never went to the server\n";
        const auto read_secret_start = Clock::now();
        LWEPrivateKey secret_key;
        if (!lbcrypto::Serial::DeserializeFromFile(args.secret_key_path.string(), secret_key, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize secret key");
        }
        const auto read_secret_end = Clock::now();
        std::cout << "[client-time] read_secret_key_ms=" << elapsed_ms(read_secret_start, read_secret_end) << "\n";
        std::cout << "[client-view] secret_key_loaded_locally=true\n";

        std::cout << "[client] reading encrypted company_code response\n";
        const auto read_ct_start = Clock::now();
        LWECiphertext response_ct;
        if (!lbcrypto::Serial::DeserializeFromFile(args.response_ct_path.string(), response_ct, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize response ciphertext");
        }
        const auto read_ct_end = Clock::now();
        std::cout << "[client-time] read_response_ciphertext_ms=" << elapsed_ms(read_ct_start, read_ct_end) << "\n";
        std::cout << "[client-view] response_ciphertext_loaded=true\n";

        const auto plaintext_modulus = cc.GetMaxPlaintextSpace().ConvertToInt();
        LWEPlaintext company_code = 0;
        std::cout << "[client] decrypting response...\n";
        const auto decrypt_start = Clock::now();
        cc.Decrypt(secret_key, response_ct, &company_code, plaintext_modulus);
        const auto decrypt_end = Clock::now();
        std::cout << "[client-time] decrypt_response_ms=" << elapsed_ms(decrypt_start, decrypt_end) << "\n";

        std::cout << "[client] decrypted result\n";
        std::cout << "company_code=" << company_code << "\n";
        std::cout << "company_name=" << company_name(static_cast<std::size_t>(company_code)) << "\n";
        std::cout << "[client-view] company_code_visible_after_decrypt=true\n";
        std::cout << "[client-view] decrypted_company_code=" << company_code << "\n";
#else
        std::cout << "OpenFHE disabled; decrypt_response requires -DHE_PROFILER_WITH_OPENFHE=ON\n";
#endif
        const auto total_end = Clock::now();
        std::cout << "[client-time] total_ms=" << elapsed_ms(total_start, total_end) << "\n";

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
