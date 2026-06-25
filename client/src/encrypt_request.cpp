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
    int directory_code = 1;
    std::string phone_number;
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

std::string normalize_phone(const std::string& phone_number) {
    std::string digits;
    for (const char ch : phone_number) {
        if (ch >= '0' && ch <= '9') {
            digits.push_back(ch);
        }
    }
    return digits;
}

int directory_code_for_phone(const std::string& phone_number) {
    const std::string digits = normalize_phone(phone_number);
    if (digits == "84961234567") return 1;
    if (digits == "84971234567") return 2;
    if (digits == "84981234567") return 3;
    if (digits == "84861234567") return 4;
    if (digits == "84911234567") return 5;
    if (digits == "84941234567") return 6;
    if (digits == "84881234567") return 7;
    if (digits == "84901234567") return 8;
    if (digits == "84931234567") return 9;
    if (digits == "84891234567") return 10;
    if (digits == "84921234567") return 11;
    if (digits == "84991234567") return 12;
    if (digits == "84241234567") return 13;
    if (digits == "84281234567") return 14;
    if (digits == "84701234567") return 15;
    throw std::runtime_error("phone number is not in the tiny demo directory");
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

CliArgs parse_args(int argc, char** argv) {
    CliArgs args;
    bool explicit_directory_code = false;

    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--directory-code") {
            if (++i >= argc) {
                throw std::runtime_error("--directory-code requires a value");
            }
            args.directory_code = parse_code(argv[i], "directory_code");
            explicit_directory_code = true;
        } else if (flag == "--phone-number") {
            if (++i >= argc) {
                throw std::runtime_error("--phone-number requires a value");
            }
            args.phone_number = argv[i];
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

    if (!args.phone_number.empty()) {
        args.directory_code = directory_code_for_phone(args.phone_number);
    } else if (!explicit_directory_code) {
        std::cout << "No --phone-number or --directory-code supplied; using demo directory_code=1\n";
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
        using lbcrypto::STD128;

        constexpr std::uint32_t kRingDim = 4096;
        constexpr std::uint32_t kLogQ = 12;

        std::cout << "[client] preparing one encrypted lookup request\n";
        if (!args.phone_number.empty()) {
            std::cout << "[client] phone_number stays local: " << args.phone_number << "\n";
            std::cout << "[client] mapped phone_number -> directory_code=" << args.directory_code << "\n";
        }
        std::cout << "[client] generating BinFHE context\n";
        BinFHEContext cc;
        cc.GenerateBinFHEContext(STD128, true, kLogQ, kRingDim, GINX, false);

        std::cout << "[client] generating secret key and bootstrapping keys\n";
        auto secret_key = cc.KeyGen();
        cc.BTKeyGen(secret_key);

        const auto plaintext_modulus = cc.GetMaxPlaintextSpace().ConvertToInt();
        if (plaintext_modulus < 16) {
            throw std::runtime_error("BinFHE plaintext modulus is smaller than 16");
        }

        std::cout << "[client] encrypting directory_code\n";
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
        std::cout << "[client] outgoing artifacts for server:\n";
        print_artifact("  context", args.outgoing_dir / "context.bin");
        print_artifact("  refresh_key", args.outgoing_dir / "refresh_key.bin");
        print_artifact("  switch_key", args.outgoing_dir / "switch_key.bin");
        print_artifact("  request_ct", args.outgoing_dir / "request_ct.bin");
        print_artifact("  request_manifest", args.outgoing_dir / "request.json");
        std::cout << "[client] private artifact, DO NOT SEND:\n";
        print_artifact("  secret_key", args.private_dir / "secret_key.bin");
#else
        write_request_manifest(args);
        std::cout << "OpenFHE disabled; wrote request manifest only\n";
        if (!args.phone_number.empty()) {
            std::cout << "phone_number mapped locally to directory_code=" << args.directory_code << "\n";
        }
        print_artifact("request_manifest", args.outgoing_dir / "request.json");
        std::cout << "configure with -DHE_PROFILER_WITH_OPENFHE=ON to serialize ciphertext artifacts\n";
#endif

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
