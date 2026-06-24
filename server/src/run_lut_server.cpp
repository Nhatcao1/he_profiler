#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

#ifdef HE_PROFILER_WITH_OPENFHE
#include "binfhecontext.h"
#endif

namespace {

constexpr int kDomain = 16;

int clamp_code(int value) {
    if (value < 0) {
        return 0;
    }
    if (value > 15) {
        return 15;
    }
    return value;
}

int adjusted_code_plain(int base_risk_code, int client_signal_code) {
    if (base_risk_code < 0 || base_risk_code >= kDomain) {
        throw std::runtime_error("base_risk_code must be in 0..15");
    }
    if (client_signal_code < 0 || client_signal_code >= kDomain) {
        throw std::runtime_error("client_signal_code must be in 0..15");
    }

    const int signal_pressure = client_signal_code / 4;
    const int signal_offset = (client_signal_code % 4 == 3) ? 1 : 0;
    return clamp_code(base_risk_code + signal_pressure + signal_offset);
}

void print_lut_matrix() {
    std::cout << "base_risk_code,client_signal_code,adjusted_risk_code\n";
    for (int base = 0; base < kDomain; ++base) {
        for (int signal = 0; signal < kDomain; ++signal) {
            std::cout << base << ',' << signal << ','
                      << adjusted_code_plain(base, signal) << '\n';
        }
    }
}

}  // namespace

int main() {
    try {
        print_lut_matrix();

#ifdef HE_PROFILER_WITH_OPENFHE
        std::cout << "# OpenFHE linked; encrypted request deserialization is next\n";
#else
        std::cout << "# OpenFHE disabled; plain LUT matrix emitted for smoke test\n";
#endif

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
