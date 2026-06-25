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
    int lookup_slot = 0;
    std::string phone_number;
    std::filesystem::path outgoing_dir = "client/outgoing";
    std::filesystem::path private_dir = "client/private";
    std::string context_id = "synthetic-v1";
};

std::string normalize_phone(const std::string& phone_number) {
    std::string digits;
    for (const char ch : phone_number) {
        if (ch >= '0' && ch <= '9') {
            digits.push_back(ch);
        }
    }
    return digits;
}

int lookup_slot_for_phone(const std::string& phone_number) {
    const std::string digits = normalize_phone(phone_number);
    if (digits == "84961234567") return 1;  // Viettel
    if (digits == "84911234567") return 2;  // VNPT/VinaPhone
    if (digits == "84901234567") return 3;  // MobiFone
    if (digits == "84921234567") return 4;  // Vietnamobile
    if (digits == "84991234567") return 5;  // Gmobile
    if (digits == "84241234567") return 6;  // Hanoi Landline
    if (digits == "84281234567") return 7;  // HCMC Landline
    if (digits == "84701234567") return 0;  // Unknown/other demo bucket
    throw std::runtime_error("phone number is not in the tiny demo registry");
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

    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--phone-number") {
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
        } else if (flag == "--context-id") {
            if (++i >= argc) {
                throw std::runtime_error("--context-id requires a value");
            }
            args.context_id = argv[i];
        } else {
            throw std::runtime_error("unknown argument: " + flag);
        }
    }

    if (args.phone_number.empty()) {
        throw std::runtime_error("--phone-number is required");
    }
    args.lookup_slot = lookup_slot_for_phone(args.phone_number);

    return args;
}

void write_request_manifest(const CliArgs& args) {
    std::ofstream f(args.outgoing_dir / "request.json");
    if (!f) {
        throw std::runtime_error("could not write request.json");
    }

    f << "{\n"
      << "  \"scheme\": \"BinFHE\",\n"
      << "  \"flow\": \"private_company_lookup\",\n"
      << "  \"context_id\": \"" << args.context_id << "\",\n"
      << "  \"context_params\": {\n"
      << "    \"paramset\": \"TOY\",\n"
      << "    \"method\": \"GINX\",\n"
      << "    \"arbitrary_function\": true,\n"
      << "    \"logQ\": 12,\n"
      << "    \"ringDim\": 1024,\n"
      << "    \"time_optimization\": false\n"
      << "  },\n"
      << "  \"encrypted_input\": \"lookup_slot\",\n"
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
        using lbcrypto::TOY;

        constexpr std::uint32_t kRingDim = 1024;
        constexpr std::uint32_t kLogQ = 12;

        std::cout << "[client] preparing one encrypted lookup request\n";
        std::cout << "[client] phone_number stays local: " << args.phone_number << "\n";
        std::cout << "[client] mapped phone_number to a local demo lookup slot\n";
        std::cout << "[client-report] context_id=" << args.context_id << "\n";
        std::cout << "[client-report] binfhe_paramset=TOY method=GINX arbitrary_function=true logQ="
                  << kLogQ << " ringDim=" << kRingDim << "\n";
        std::cout << "[client-report] context_recreated_from_params=true\n";
        std::cout << "[client-report] server_receives=refresh_key.bin,switch_key.bin,request_ct.bin,request.json\n";
        std::cout << "[client-report] client_keeps_private=phone_number,lookup_slot,secret_key.bin,decrypted_result\n";
        std::cout << "[client] generating BinFHE context\n";
        BinFHEContext cc;
        cc.GenerateBinFHEContext(TOY, true, kLogQ, kRingDim, GINX, false);

        std::cout << "[client] generating secret key and bootstrapping keys\n";
        auto secret_key = cc.KeyGen();
        cc.BTKeyGen(secret_key);

        const auto plaintext_modulus = cc.GetMaxPlaintextSpace().ConvertToInt();
        if (plaintext_modulus < 8) {
            throw std::runtime_error(
                "BinFHE plaintext modulus is smaller than 8: " + std::to_string(plaintext_modulus));
        }
        std::cout << "[client-report] plaintext_modulus=" << plaintext_modulus << " lookup_slot_domain=0..7\n";

        std::cout << "[client] encrypting lookup slot\n";
        auto ct = cc.Encrypt(
            secret_key,
            static_cast<LWEPlaintext>(args.lookup_slot),
            LARGE_DIM,
            plaintext_modulus);

        if (!lbcrypto::Serial::SerializeToFile((args.outgoing_dir / "refresh_key.bin").string(), cc.GetRefreshKey(), lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to serialize refresh_key.bin");
        }
        if (!lbcrypto::Serial::SerializeToFile((args.outgoing_dir / "switch_key.bin").string(), cc.GetSwitchKey(), lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to serialize switch_key.bin");
        }
        if (!lbcrypto::Serial::SerializeToFile((args.private_dir / "secret_key.bin").string(), secret_key, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to serialize secret_key.bin");
        }
        if (!lbcrypto::Serial::SerializeToFile((args.outgoing_dir / "request_ct.bin").string(), ct, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to serialize request_ct.bin");
        }

        write_request_manifest(args);

        std::cout << "wrote encrypted request artifacts to " << args.outgoing_dir << "\n";
        std::cout << "wrote client secret key to " << args.private_dir / "secret_key.bin" << "\n";
        std::cout << "lookup slot encrypted; plaintext phone number is not written to request artifacts\n";
        std::cout << "[client-report] encrypted_payload=request_ct.bin=Enc(lookup_slot)\n";
        std::cout << "[client] outgoing artifacts for server:\n";
        print_artifact("  refresh_key", args.outgoing_dir / "refresh_key.bin");
        print_artifact("  switch_key", args.outgoing_dir / "switch_key.bin");
        print_artifact("  request_ct", args.outgoing_dir / "request_ct.bin");
        print_artifact("  request_manifest", args.outgoing_dir / "request.json");
        std::cout << "[client] private artifact, DO NOT SEND:\n";
        print_artifact("  secret_key", args.private_dir / "secret_key.bin");
#else
        write_request_manifest(args);
        std::cout << "OpenFHE disabled; wrote request manifest only\n";
        std::cout << "phone_number mapped locally to a demo lookup slot\n";
        print_artifact("request_manifest", args.outgoing_dir / "request.json");
        std::cout << "configure with -DHE_PROFILER_WITH_OPENFHE=ON to serialize ciphertext artifacts\n";
#endif

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
