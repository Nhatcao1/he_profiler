#include <array>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

#ifdef HE_PROFILER_WITH_OPENFHE
#include "binfhecontext-ser.h"
#endif

namespace {

struct CliArgs {
    std::filesystem::path secret_key_path = "client/private/secret_key.bin";
    std::filesystem::path response_ct_path = "client/incoming/response_ct.bin";
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
        std::cout << "[client-report] context_id=" << args.context_id << "\n";
        std::cout << "[client-report] binfhe_paramset=TOY method=GINX arbitrary_function=true logQ="
                  << kLogQ << " ringDim=" << kRingDim << "\n";
        std::cout << "[client-report] context_recreated_from_params=true\n";
        print_artifact("  secret_key", args.secret_key_path);
        print_artifact("  response_ct", args.response_ct_path);

        BinFHEContext cc;
        cc.GenerateBinFHEContext(TOY, true, kLogQ, kRingDim, GINX, false);

        std::cout << "[client] reading secret key; it never went to the server\n";
        LWEPrivateKey secret_key;
        if (!lbcrypto::Serial::DeserializeFromFile(args.secret_key_path.string(), secret_key, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize secret key");
        }

        std::cout << "[client] reading encrypted company_code response\n";
        LWECiphertext response_ct;
        if (!lbcrypto::Serial::DeserializeFromFile(args.response_ct_path.string(), response_ct, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize response ciphertext");
        }

        const auto plaintext_modulus = cc.GetMaxPlaintextSpace().ConvertToInt();
        LWEPlaintext company_code = 0;
        std::cout << "[client] decrypting response...\n";
        cc.Decrypt(secret_key, response_ct, &company_code, plaintext_modulus);

        std::cout << "[client] decrypted result\n";
        std::cout << "company_code=" << company_code << "\n";
        std::cout << "company_name=" << company_name(static_cast<std::size_t>(company_code)) << "\n";
#else
        std::cout << "OpenFHE disabled; decrypt_response requires -DHE_PROFILER_WITH_OPENFHE=ON\n";
#endif

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
