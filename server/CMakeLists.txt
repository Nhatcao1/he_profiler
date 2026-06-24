cmake_minimum_required(VERSION 3.16)

project(he_profiler_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(HE_PROFILER_WITH_OPENFHE "Build server with OpenFHE BinFHE support" OFF)

add_executable(run_lut_server src/run_lut_server.cpp)
target_compile_options(run_lut_server PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
)

if(HE_PROFILER_WITH_OPENFHE)
    find_package(OpenFHE CONFIG REQUIRED)

    separate_arguments(OPENFHE_CXX_FLAGS_LIST NATIVE_COMMAND "${OpenFHE_CXX_FLAGS}")
    separate_arguments(OPENFHE_EXE_LINKER_FLAGS_LIST NATIVE_COMMAND "${OpenFHE_EXE_LINKER_FLAGS}")

    target_compile_definitions(run_lut_server PRIVATE HE_PROFILER_WITH_OPENFHE=1)
    target_compile_options(run_lut_server PRIVATE ${OPENFHE_CXX_FLAGS_LIST})
    target_include_directories(run_lut_server SYSTEM PRIVATE
        ${OpenFHE_INCLUDE}
        ${OpenFHE_INCLUDE}/third-party/include
        ${OpenFHE_INCLUDE}/core
        ${OpenFHE_INCLUDE}/pke
        ${OpenFHE_INCLUDE}/binfhe
    )
    target_link_directories(run_lut_server PRIVATE ${OpenFHE_LIBDIR})
    if(UNIX AND NOT APPLE)
        target_link_options(run_lut_server PRIVATE -Wl,--no-as-needed)
    endif()
    target_link_options(run_lut_server PRIVATE ${OPENFHE_EXE_LINKER_FLAGS_LIST})
    target_link_libraries(run_lut_server PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()
