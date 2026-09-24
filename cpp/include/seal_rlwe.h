#pragma once
#include <seal/seal.h>
#include <cstddef>
#include <cstdint>
#include <vector>

struct SealBenchResult {
    double keygen_ms{0.0};
    double encode_ms{0.0};
    double encrypt_ms{0.0};
    double aggregate_ms{0.0};
    double decrypt_ms{0.0};
    std::size_t ciphertext_bytes_per_client{0};
    std::size_t plaintext_bytes_per_client{0};
    std::size_t aggregate_ciphertext_bytes{0};
    std::size_t chunks{0};
    bool decrypt_check{false};
    std::vector<int64_t> aggregate_prefix;
};

SealBenchResult benchmark_bgv_aggregation(const std::vector<std::vector<int64_t>>& client_updates,
                                          std::size_t poly_modulus_degree = 8192);
