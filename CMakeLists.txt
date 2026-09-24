cmake_minimum_required(VERSION 3.22)
project(acns_fl_crypto_bench LANGUAGES CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -O3 -mcpu=apple-m1 -ffast-math -pthread")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Configure with:
# cmake -S . -B build -DCMAKE_PREFIX_PATH="$LIBTORCH_DIR;$SEAL_DIR"
find_package(Torch REQUIRED)
find_package(SEAL 4.4 REQUIRED)

set(RUST_TARGET_DIR "${CMAKE_SOURCE_DIR}/rust/target/release")
set(RUST_LIB "${RUST_TARGET_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}flzk${CMAKE_STATIC_LIBRARY_SUFFIX}")

add_custom_target(rust_crypto ALL
    COMMAND cargo build --manifest-path "${CMAKE_SOURCE_DIR}/rust/Cargo.toml" --release
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building Rust Bulletproof/commitment/PoI library"
)

add_executable(fl_bench
    cpp/src/main.cpp
    cpp/src/ml_models.cpp
    cpp/src/seal_rlwe.cpp
)
add_dependencies(fl_bench rust_crypto)

target_include_directories(fl_bench PRIVATE cpp/include)
target_link_libraries(fl_bench PRIVATE SEAL::seal "${TORCH_LIBRARIES}")

target_link_libraries(fl_bench PRIVATE "${RUST_LIB}" dl pthread m)
set_property(TARGET fl_bench PROPERTY CXX_STANDARD 20)

# LibTorch can require ABI/compiler flags supplied by TorchConfig.cmake.
target_compile_options(fl_bench PRIVATE ${TORCH_CXX_FLAGS})

install(TARGETS fl_bench RUNTIME DESTINATION bin)
