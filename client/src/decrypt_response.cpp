#include <cstdlib>
#include <iostream>

int main() {
#ifdef HE_PROFILER_WITH_OPENFHE
    std::cout << "OpenFHE enabled; response deserialization/decryption is next\n";
#else
    std::cout << "OpenFHE disabled; decrypt_response skeleton only\n";
#endif
    return EXIT_SUCCESS;
}
