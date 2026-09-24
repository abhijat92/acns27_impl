#pragma once
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t prove_us;
    uint64_t verify_us;
    uint64_t commitment_us;
    uint64_t proof_bytes;
    uint64_t commitment_bytes;
    uint64_t poi_us;
    uint64_t poi_bytes;
    uint64_t fairness_us;
    uint64_t fairness_bytes;
    uint64_t checks_passed;
    uint64_t checks_failed;
} zk_bench_result_t;

int flzk_benchmark_r1cs(uint64_t n, uint32_t mode, zk_bench_result_t *out);
int flzk_check_poi(uint64_t aggregate, uint64_t own, uint64_t excluded);

#ifdef __cplusplus
}
#endif
