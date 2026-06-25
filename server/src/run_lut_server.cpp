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

constexpr int kDomain = 16;

constexpr std::array<int, kDomain> kCompanyByDirectoryCode = {
    0,  // unknown
    1,  // Viettel
    1,  // Viettel
    1,  // Viettel
    1,  // Viettel
    2,  // VNPT/VinaPhone
    2,  // VNPT/VinaPhone
    2,  // VNPT/VinaPhone
    3,  // MobiFone
    3,  // MobiFone
    3,  // MobiFone
    4,  // Vietnamobile
    5,  // Gmobile
    6,  // Hanoi Landline
    7,  // HCMC Landline
    8,  // Other Registered
};

struct CliArgs {
    std::filesystem::path incoming_dir = "server/incoming";
    std::filesystem::path outgoing_dir = "server/outgoing";
    std::string context_id = "synthetic-v1";
};

int company_code_plain(int lookup_slot) {
    if (lookup_slot < 0 || lookup_slot >= kDomain) {
        throw std::runtime_error("lookup_slot must be in 0..15");
    }
    return kCompanyByDirectoryCode[lookup_slot];
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
        if (flag == "--incoming") {
            if (++i >= argc) {
                throw std::runtime_error("--incoming requires a path");
            }
            args.incoming_dir = argv[i];
        } else if (flag == "--outgoing") {
            if (++i >= argc) {
                throw std::runtime_error("--outgoing requires a path");
            }
            args.outgoing_dir = argv[i];
        } else if (flag == "--context-id") {
            if (++i >= argc) {
                throw std::runtime_error("--context-id requires a value");
            }
            args.context_id = argv[i];
        } else if (flag == "--print-plain-lut") {
            for (int code = 0; code < kDomain; ++code) {
                std::cout << code << ',' << company_code_plain(code) << '\n';
            }
            std::exit(EXIT_SUCCESS);
        } else {
            throw std::runtime_error("unknown argument: " + flag);
        }
    }

    return args;
}

void write_response_manifest(const CliArgs& args) {
    std::ofstream f(args.outgoing_dir / "response.json");
    if (!f) {
        throw std::runtime_error("could not write response.json");
    }

    f << "{\n"
      << "  \"scheme\": \"BinFHE\",\n"
      << "  \"flow\": \"private_company_lookup\",\n"
      << "  \"context_id\": \"" << args.context_id << "\",\n"
      << "  \"encrypted_output\": \"company_code\",\n"
      << "  \"ciphertext_file\": \"response_ct.bin\"\n"
      << "}\n";
}

#ifdef HE_PROFILER_WITH_OPENFHE
lbcrypto::NativeInteger company_lut_function(
    lbcrypto::NativeInteger input,
    lbcrypto::NativeInteger plaintext_modulus) {
    const std::uint64_t lookup_slot = input.ConvertToInt();
    const std::uint64_t modulus = plaintext_modulus.ConvertToInt();
    if (lookup_slot < kCompanyByDirectoryCode.size()) {
        return lbcrypto::NativeInteger(
            static_cast<std::uint64_t>(kCompanyByDirectoryCode[lookup_slot]) % modulus);
    }
    return lbcrypto::NativeInteger(0);
}
#endif

}  // namespace

int main(int argc, char** argv) {
    try {
        const CliArgs args = parse_args(argc, argv);
        std::filesystem::create_directories(args.outgoing_dir);

#ifdef HE_PROFILER_WITH_OPENFHE
        using lbcrypto::BinFHEContext;
        using lbcrypto::LWECiphertext;
        using lbcrypto::LWESwitchingKey;
        using lbcrypto::RingGSWBTKey;
        using lbcrypto::RingGSWACCKey;

        std::cout << "[server] reading encrypted request artifacts from " << args.incoming_dir << "\n";
        std::cout << "[server-report] context_id=" << args.context_id << "\n";
        std::cout << "[server-report] server_receives=context.bin,refresh_key.bin,switch_key.bin,request_ct.bin,request.json\n";
        std::cout << "[server-report] server_does_not_receive=phone_number,lookup_slot,secret_key.bin\n";
        std::cout << "[server-report] encrypted_payload=request_ct.bin=Enc(lookup_slot)\n";
        print_artifact("  context", args.incoming_dir / "context.bin");
        print_artifact("  refresh_key", args.incoming_dir / "refresh_key.bin");
        print_artifact("  switch_key", args.incoming_dir / "switch_key.bin");
        print_artifact("  request_ct", args.incoming_dir / "request_ct.bin");
        if (std::filesystem::exists(args.incoming_dir / "request.json")) {
            print_artifact("  request_manifest", args.incoming_dir / "request.json");
        }

        std::cout << "[server] deserializing BinFHE context\n";
        BinFHEContext cc;
        if (!lbcrypto::Serial::DeserializeFromFile((args.incoming_dir / "context.bin").string(), cc, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize context.bin");
        }

        std::cout << "[server] loading bootstrapping key material\n";
        RingGSWACCKey refresh_key;
        if (!lbcrypto::Serial::DeserializeFromFile((args.incoming_dir / "refresh_key.bin").string(), refresh_key, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize refresh_key.bin");
        }

        LWESwitchingKey switch_key;
        if (!lbcrypto::Serial::DeserializeFromFile((args.incoming_dir / "switch_key.bin").string(), switch_key, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize switch_key.bin");
        }

        RingGSWBTKey bootstrapping_key;
        bootstrapping_key.BSkey = refresh_key;
        bootstrapping_key.KSkey = switch_key;
        cc.BTKeyLoad(bootstrapping_key);

        std::cout << "[server] reading encrypted lookup slot\n";
        LWECiphertext request_ct;
        if (!lbcrypto::Serial::DeserializeFromFile((args.incoming_dir / "request_ct.bin").string(), request_ct, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to deserialize request_ct.bin");
        }

        std::cout << "[server] generating company lookup LUT\n";
        const auto plaintext_modulus = cc.GetMaxPlaintextSpace();
        std::cout << "[server-report] plaintext_modulus=" << plaintext_modulus.ConvertToInt()
                  << " lookup_slot_domain=0..15 company_code_domain=0..8\n";
        std::cout << "[server-report] lut_semantics=lookup_slot_to_company_code\n";
        auto lut = cc.GenerateLUTviaFunction(company_lut_function, plaintext_modulus);
        std::cout << "[server] evaluating LUT on ciphertext; plaintext query remains hidden\n";
        std::cout << "[server-report] decryption_on_server=false\n";
        auto response_ct = cc.EvalFunc(request_ct, lut);

        if (!lbcrypto::Serial::SerializeToFile((args.outgoing_dir / "response_ct.bin").string(), response_ct, lbcrypto::SerType::BINARY)) {
            throw std::runtime_error("failed to serialize response_ct.bin");
        }

        write_response_manifest(args);
        std::cout << "wrote encrypted response artifacts to " << args.outgoing_dir << "\n";
        std::cout << "[server-report] encrypted_response=response_ct.bin=Enc(company_code)\n";
        print_artifact("  response_ct", args.outgoing_dir / "response_ct.bin");
        print_artifact("  response_manifest", args.outgoing_dir / "response.json");
#else
        write_response_manifest(args);
        std::cout << "OpenFHE disabled; wrote response manifest only\n";
        print_artifact("response_manifest", args.outgoing_dir / "response.json");
        std::cout << "configure with -DHE_PROFILER_WITH_OPENFHE=ON to evaluate ciphertext\n";
#endif

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
