#include <array>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#ifdef HE_PROFILER_WITH_OPENFHE
#include "binfhecontext-ser.h"
#endif

namespace {

struct CliArgs {
    std::filesystem::path context_path = "client/outgoing/context.bin";
    std::filesystem::path secret_key_path = "client/private/secret_key.bin";
    std::filesystem::path response_ct_path = "client/incoming/response_ct.bin";
};

constexpr std::array<const char*, 9> kCompanyNames = {
    "Unknown",
    "Viettel",
    "VNPT/VinaPhone",
    "MobiFone",
    "Vietnamobile",
    "Gmobile",
    "Hanoi Landline",
    "HCMC Landline",
    "Other Registered",
};

CliArgs parse_args(int argc, char** argv) {
    CliArgs args;

    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--context") {
            if (++i >= argc) {
                throw std::runtime_error("--context requires a path");
            }
            args.context_path = argv[i];
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

}  // namespace

int main(int argc, char** argv) {
    try {
        const CliArgs args = parse_args(argc, argv);

#ifdef HE_PROFILER_WITH_OPENFHE
        using lbcrypto::BinFHEContext;
        using lbcrypto::LWECiphertext;
        using lbcrypto::LWEPlaintext;
        using lbcrypto::LWEPrivateKey;
        using lbcrypto::Serial;
        using lbcrypto::SerType;

        BinFHEContext cc;
        if (!Serial::DeserializeFromFile(args.context_path.string(), cc, SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize context");
        }

        LWEPrivateKey secret_key;
        if (!Serial::DeserializeFromFile(args.secret_key_path.string(), secret_key, SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize secret key");
        }

        LWECiphertext response_ct;
        if (!Serial::DeserializeFromFile(args.response_ct_path.string(), response_ct, SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize response ciphertext");
        }

        const auto plaintext_modulus = cc.GetMaxPlaintextSpace().ConvertToInt();
        LWEPlaintext company_code = 0;
        cc.Decrypt(secret_key, response_ct, &company_code, plaintext_modulus);

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
