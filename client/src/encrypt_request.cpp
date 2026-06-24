#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#ifdef HE_PROFILER_WITH_OPENFHE
#include "binfhecontext-ser.h"
#endif

namespace {

struct CliArgs {
    int directory_code = 1;
    std::filesystem::path outgoing_dir = "client/outgoing";
    std::filesystem::path private_dir = "client/private";
    std::string request_id = "req-0001";
    std::string context_id = "synthetic-v1";
};

int parse_code(const std::string& value, const std::string& name) {
    const int parsed = std::stoi(value);
    if (parsed < 0 || parsed > 15) {
        throw std::runtime_error(name + " must be in 0..15");
    }
    return parsed;
}

CliArgs parse_args(int argc, char** argv) {
    CliArgs args;

    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--directory-code") {
            if (++i >= argc) {
                throw std::runtime_error("--directory-code requires a value");
            }
            args.directory_code = parse_code(argv[i], "directory_code");
        } else if (flag == "--outgoing") {
            if (++i >= argc) {
                throw std::runtime_error("--outgoing requires a path");
            }
            args.outgoing_dir = argv[i];
        } else if (flag == "--private") {
            if (++i >= argc) {
                throw std::runtime_error("--private requires a path");
            }
            args.private_dir = argv[i];
        } else if (flag == "--request-id") {
            if (++i >= argc) {
                throw std::runtime_error("--request-id requires a value");
            }
            args.request_id = argv[i];
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

void write_request_manifest(const CliArgs& args) {
    std::ofstream f(args.outgoing_dir / "request.json");
    if (!f) {
        throw std::runtime_error("could not write request.json");
    }

    f << "{\n"
      << "  \"request_id\": \"" << args.request_id << "\",\n"
      << "  \"scheme\": \"BinFHE\",\n"
      << "  \"context_id\": \"" << args.context_id << "\",\n"
      << "  \"context_file\": \"context.bin\",\n"
      << "  \"refresh_key_file\": \"refresh_key.bin\",\n"
      << "  \"switch_key_file\": \"switch_key.bin\",\n"
      << "  \"ciphertext_file\": \"request_ct.bin\"\n"
      << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const CliArgs args = parse_args(argc, argv);
        std::filesystem::create_directories(args.outgoing_dir);
        std::filesystem::create_directories(args.private_dir);

#ifdef HE_PROFILER_WITH_OPENFHE
        using lbcrypto::BinFHEContext;
        using lbcrypto::GINX;
        using lbcrypto::LARGE_DIM;
        using lbcrypto::LWEPlaintext;
        using lbcrypto::Serial;
        using lbcrypto::SerType;
        using lbcrypto::STD128;

        constexpr std::uint32_t kRingDim = 4096;
        constexpr std::uint32_t kLogQ = 12;

        BinFHEContext cc;
        cc.GenerateBinFHEContext(STD128, true, kLogQ, kRingDim, GINX, false);

        auto secret_key = cc.KeyGen();
        cc.BTKeyGen(secret_key);

        const auto plaintext_modulus = cc.GetMaxPlaintextSpace().ConvertToInt();
        if (plaintext_modulus < 16) {
            throw std::runtime_error("BinFHE plaintext modulus is smaller than 16");
        }

        auto ct = cc.Encrypt(
            secret_key,
            static_cast<LWEPlaintext>(args.directory_code),
            LARGE_DIM,
            plaintext_modulus);

        if (!Serial::SerializeToFile((args.outgoing_dir / "context.bin").string(), cc, SerType::BINARY)) {
            throw std::runtime_error("failed to serialize context.bin");
        }
        if (!Serial::SerializeToFile((args.outgoing_dir / "refresh_key.bin").string(), cc.GetRefreshKey(), SerType::BINARY)) {
            throw std::runtime_error("failed to serialize refresh_key.bin");
        }
        if (!Serial::SerializeToFile((args.outgoing_dir / "switch_key.bin").string(), cc.GetSwitchKey(), SerType::BINARY)) {
            throw std::runtime_error("failed to serialize switch_key.bin");
        }
        if (!Serial::SerializeToFile((args.private_dir / "secret_key.bin").string(), secret_key, SerType::BINARY)) {
            throw std::runtime_error("failed to serialize secret_key.bin");
        }
        if (!Serial::SerializeToFile((args.outgoing_dir / "request_ct.bin").string(), ct, SerType::BINARY)) {
            throw std::runtime_error("failed to serialize request_ct.bin");
        }

        write_request_manifest(args);

        std::cout << "wrote encrypted request artifacts to " << args.outgoing_dir << "\n";
        std::cout << "wrote client secret key to " << args.private_dir / "secret_key.bin" << "\n";
        std::cout << "directory_code encrypted; plaintext not written to request artifacts\n";
#else
        write_request_manifest(args);
        std::cout << "OpenFHE disabled; wrote request manifest only\n";
        std::cout << "configure with -DHE_PROFILER_WITH_OPENFHE=ON to serialize ciphertext artifacts\n";
#endif

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
