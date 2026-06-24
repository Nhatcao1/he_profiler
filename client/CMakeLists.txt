cmake_minimum_required(VERSION 3.16)

project(he_profiler_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(HE_PROFILER_WITH_OPENFHE "Build client with OpenFHE BinFHE support" OFF)

add_executable(encrypt_request src/encrypt_request.cpp)
add_executable(decrypt_response src/decrypt_response.cpp)

foreach(target encrypt_request decrypt_response)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    )
endforeach()

if(HE_PROFILER_WITH_OPENFHE)
    find_package(OpenFHE CONFIG REQUIRED)

    separate_arguments(OPENFHE_CXX_FLAGS_LIST NATIVE_COMMAND "${OpenFHE_CXX_FLAGS}")
    separate_arguments(OPENFHE_EXE_LINKER_FLAGS_LIST NATIVE_COMMAND "${OpenFHE_EXE_LINKER_FLAGS}")

    foreach(target encrypt_request decrypt_response)
        target_compile_definitions(${target} PRIVATE HE_PROFILER_WITH_OPENFHE=1)
        target_compile_options(${target} PRIVATE ${OPENFHE_CXX_FLAGS_LIST})
        target_include_directories(${target} SYSTEM PRIVATE
            ${OpenFHE_INCLUDE}
            ${OpenFHE_INCLUDE}/third-party/include
            ${OpenFHE_INCLUDE}/core
            ${OpenFHE_INCLUDE}/pke
            ${OpenFHE_INCLUDE}/binfhe
        )
        target_link_directories(${target} PRIVATE ${OpenFHE_LIBDIR})
        if(UNIX AND NOT APPLE)
            target_link_options(${target} PRIVATE -Wl,--no-as-needed)
        endif()
        target_link_options(${target} PRIVATE ${OPENFHE_EXE_LINKER_FLAGS_LIST})
        target_link_libraries(${target} PRIVATE ${OpenFHE_SHARED_LIBRARIES})
    endforeach()
endif()
