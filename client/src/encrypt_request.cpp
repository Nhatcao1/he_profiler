#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#ifdef HE_PROFILER_WITH_OPENFHE
#include "binfhecontext.h"
#endif

namespace {

int parse_client_signal_code(int argc, char** argv) {
    if (argc < 2) {
        return 3;
    }
    const int value = std::stoi(argv[1]);
    if (value < 0 || value > 15) {
        throw std::runtime_error("client_signal_code must be in 0..15");
    }
    return value;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const int client_signal_code = parse_client_signal_code(argc, argv);

#ifdef HE_PROFILER_WITH_OPENFHE
        using lbcrypto::BinFHEContext;
        using lbcrypto::GINX;
        using lbcrypto::LARGE_DIM;
        using lbcrypto::LWEPlaintext;
        using lbcrypto::STD128;

        constexpr std::uint32_t kRingDim = 4096;
        constexpr std::uint32_t kLogQ = 12;

        BinFHEContext cc;
        cc.GenerateBinFHEContext(STD128, true, kLogQ, kRingDim, GINX, false);
        auto secret_key = cc.KeyGen();
        cc.BTKeyGen(secret_key);

        const auto plaintext_modulus = cc.GetMaxPlaintextSpace().ConvertToInt();
        auto ciphertext = cc.Encrypt(
            secret_key,
            static_cast<LWEPlaintext>(client_signal_code),
            LARGE_DIM,
            plaintext_modulus);

        LWEPlaintext roundtrip = 0;
        cc.Decrypt(secret_key, ciphertext, &roundtrip, plaintext_modulus);

        std::cout << "OpenFHE client smoke test ok\n";
        std::cout << "client_signal_code=" << client_signal_code << "\n";
        std::cout << "roundtrip=" << roundtrip << "\n";
        std::cout << "next: serialize context, eval key, and ciphertext request\n";
#else
        std::cout << "OpenFHE disabled; client skeleton only\n";
        std::cout << "client_signal_code=" << client_signal_code << "\n";
        std::cout << "configure with -DHE_PROFILER_WITH_OPENFHE=ON to encrypt\n";
#endif

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
