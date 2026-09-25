#include "ml_models.h"
#include "seal_rlwe.h"
#include "crypto_ffi.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <algorithm>

namespace {
std::vector<std::size_t> parse_sizes(const std::string& s) {
    std::vector<std::size_t> out;
    std::stringstream ss(s);
    std::string x;
    while (std::getline(ss, x, ',')) out.push_back(static_cast<std::size_t>(std::stoull(x)));
    return out;
}
void print_header() {
    std::cout << "# ACNS FL crypto benchmark\n";
    std::cout << "# Fields: model,N,clients,train_ms,seal_keygen_ms,seal_encode_ms,seal_encrypt_ms,seal_aggregate_ms,seal_decrypt_ms,"
                 "ciphertext_B/client,plaintext_B,aggregate_ciphertext_B,zk_prove_ms,zk_verify_ms,commitment_B,poi_ms,poi_B,fairness_ms,fairness_B,checks\n";
}
}

int main(int argc, char** argv) {
    std::string sizes_arg = argc > 1 ? argv[1] : "256,512,1024,2048,4096,8192";
    int clients = argc > 2 ? std::atoi(argv[2]) : 4;
    int epochs = argc > 3 ? std::atoi(argv[3]) : 2;
    std::string model_name = argc > 4 ? argv[4] : "mlp";
    auto sizes = parse_sizes(sizes_arg);
    print_header();

    for (std::size_t n : sizes) {
        std::vector<std::vector<int64_t>> client_updates;
        double train_total = 0.0;
        for (int c = 0; c < clients; ++c) {
            TrainResult tr = (model_name == "cnn")
                ? train_cnn_and_extract(n, 64, epochs, 1000 + c)
                : train_mlp_and_extract(n, 64, epochs, 1000 + c);
            train_total += tr.train_ms;
            std::vector<int64_t> encoded(n);
            constexpr double scale = 1000.0;
            for (std::size_t j = 0; j < n; ++j) {
                encoded[j] = static_cast<int64_t>(std::llround(tr.update[j] * scale));
            }
            client_updates.push_back(std::move(encoded));
        }

        auto seal = benchmark_bgv_aggregation(client_updates, ACNS_RLWE_N);

        zk_bench_result_t zk{};
        // mode 0: linear/matrix-style R1CS (constant number of multiplication gates);
        // mode 1: vector-style R1CS (one multiplication gate per element).
        int rc_linear = flzk_benchmark_r1cs(static_cast<uint64_t>(n), 0, &zk);
        if (rc_linear != 0) {
            std::cerr << "R1CS benchmark failed for N=" << n << ": " << rc_linear << "\n";
            return 2;
        }

        uint64_t aggregate = static_cast<uint64_t>(clients) * 1234567ULL;
        uint64_t own = 1234567ULL;
        uint64_t excluded = aggregate - own;
        auto p0 = std::chrono::steady_clock::now();
        int poi_ok = flzk_check_poi(aggregate, own, excluded);
        auto p1 = std::chrono::steady_clock::now();
        double poi_ms = std::chrono::duration<double,std::milli>(p1-p0).count();

        auto f0 = std::chrono::steady_clock::now();
        //std::vector<uint64_t> eligible({clients/2 + 1, static_cast<uint64_t>(clients) - clients/2 - 1});
        //std::vector<uint64_t> included({clients/2, static_cast<uint64_t>(clients) - clients/2});
        
        std::vector<uint64_t> eligible{static_cast<uint64_t>(clients / 2 + 1), static_cast<uint64_t>(clients) - clients / 2 - 1};
        std::vector<uint64_t> included{static_cast<uint64_t>(clients / 2), static_cast<uint64_t>(clients) - clients / 2};
        
        std::vector<double> cr;
        for (std::size_t g = 0; g < eligible.size(); ++g) cr.push_back(eligible[g] ? double(included[g]) / double(eligible[g]) : 0.0);
        double mn = *std::min_element(cr.begin(), cr.end());
        double mx = *std::max_element(cr.begin(), cr.end());
        double disparity = mx - mn;
        double sum = 0.0, sq = 0.0;
        for (double x : cr) { sum += x; sq += x*x; }
        double jain = sq > 0.0 ? sum*sum / (cr.size()*sq) : 1.0;
        (void)disparity; (void)jain;
        auto f1 = std::chrono::steady_clock::now();
        double fairness_ms = std::chrono::duration<double,std::milli>(f1-f0).count();
        std::size_t fairness_bytes = cr.size() * (sizeof(uint64_t)*2 + sizeof(double));

        uint64_t total_checks = seal.decrypt_check && poi_ok ? 1 : 0;
        total_checks += zk.checks_passed;
        uint64_t failed = (seal.decrypt_check ? 0 : 1) + (poi_ok ? 0 : 1) + zk.checks_failed;

        std::cout << std::fixed << std::setprecision(3)
                  << model_name << "," << n << "," << clients << ","
                  << train_total << "," << seal.keygen_ms << "," << seal.encode_ms << ","
                  << seal.encrypt_ms << "," << seal.aggregate_ms << "," << seal.decrypt_ms << ","
                  << seal.ciphertext_bytes_per_client << "," << seal.plaintext_bytes_per_client << ","
                  << seal.aggregate_ciphertext_bytes << "," << (zk.prove_us/1000.0) << ","
                  << (zk.verify_us/1000.0) << "," << zk.commitment_bytes << ","
                  << poi_ms << "," << zk.poi_bytes << "," << fairness_ms << ","
                  << fairness_bytes << "," << total_checks << "/" << failed << "\n";
    }
    return 0;
}
