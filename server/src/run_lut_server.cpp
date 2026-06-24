#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

#ifdef HE_PROFILER_WITH_OPENFHE
#include "binfhecontext.h"
#endif

namespace {

constexpr int kDomain = 16;

constexpr std::array<int, kDomain> kCompanyByDirectoryCode = {
    0,  // unknown
    1,  // Viettel 096
    1,  // Viettel 097
    1,  // Viettel 098
    1,  // Viettel 086
    2,  // VNPT/VinaPhone 091
    2,  // VNPT/VinaPhone 094
    2,  // VNPT/VinaPhone 088
    3,  // MobiFone 090
    3,  // MobiFone 093
    3,  // MobiFone 089
    4,  // Vietnamobile 092
    5,  // Gmobile 099
    6,  // Landline 024
    7,  // Landline 028
    8,  // Other registered
};

int company_code_plain(int directory_code) {
    if (directory_code < 0 || directory_code >= kDomain) {
        throw std::runtime_error("directory_code must be in 0..15");
    }
    return kCompanyByDirectoryCode[directory_code];
}

void print_lut_matrix() {
    std::cout << "directory_code,company_code\n";
    for (int directory_code = 0; directory_code < kDomain; ++directory_code) {
        std::cout << directory_code << ','
                  << company_code_plain(directory_code) << '\n';
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
