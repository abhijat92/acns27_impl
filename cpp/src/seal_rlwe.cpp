#include "seal_rlwe.h"
#include <chrono>
#include <stdexcept>
#include <iostream>
#include <algorithm>

using namespace seal;

namespace {
std::size_t serialized_ciphertext_size(const Ciphertext& x) { return x.save_size(); }
}

SealBenchResult benchmark_bgv_aggregation(const std::vector<std::vector<int64_t>>& updates,
                                          std::size_t poly_degree) {
    if (updates.empty()) throw std::invalid_argument("no clients");
    const std::size_t n = updates.front().size();
    for (const auto& u : updates) if (u.size() != n) throw std::invalid_argument("size mismatch");

    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_degree, 20));

    SEALContext context(parms);
    //if (!context.parameters_set()) throw std::runtime_error("invalid SEAL parameters: " + context.parameter_error_message());

    SealBenchResult r;
    auto t0 = std::chrono::steady_clock::now();
    KeyGenerator keygen(context);
    SecretKey sk = keygen.secret_key();
    PublicKey pk;
    keygen.create_public_key(pk);
    auto t1 = std::chrono::steady_clock::now();
    r.keygen_ms = std::chrono::duration<double, std::milli>(t1-t0).count();

    BatchEncoder encoder(context);
    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    const std::size_t slots = encoder.slot_count();
    r.chunks = (n + slots - 1) / slots;
    std::vector<Ciphertext> aggregate;
    aggregate.reserve(r.chunks);

    for (std::size_t c = 0; c < r.chunks; ++c) {
        std::vector<Ciphertext> encrypted;
        encrypted.reserve(updates.size());
        for (const auto& update : updates) {
            std::vector<uint64_t> packed(slots, 0);
            const std::size_t begin = c * slots;
            const std::size_t end = std::min(n, begin + slots);
            for (std::size_t j = begin; j < end; ++j) {
                int64_t v = update[j];
                // Modulo the plaintext modulus; BGV plaintexts are represented modulo t.
                const uint64_t t = context.first_context_data()->parms().plain_modulus().value();
                packed[j - begin] = static_cast<uint64_t>((v % static_cast<int64_t>(t) + static_cast<int64_t>(t)) % static_cast<int64_t>(t));
            }
            Plaintext pt;
            auto e0 = std::chrono::steady_clock::now();
            encoder.encode(packed, pt);
            auto e1 = std::chrono::steady_clock::now();
            r.encode_ms += std::chrono::duration<double, std::milli>(e1-e0).count();

            auto e2 = std::chrono::steady_clock::now();
            Ciphertext ct;
            encryptor.encrypt(pt, ct);
            auto e3 = std::chrono::steady_clock::now();
            r.encrypt_ms += std::chrono::duration<double, std::milli>(e3-e2).count();
            if (c == 0) {
                r.ciphertext_bytes_per_client += serialized_ciphertext_size(ct);
                r.plaintext_bytes_per_client += pt.save_size();
            }
            encrypted.push_back(std::move(ct));
        }
        auto a0 = std::chrono::steady_clock::now();
        Ciphertext agg = encrypted.front();
        for (std::size_t i = 1; i < encrypted.size(); ++i) evaluator.add_inplace(agg, encrypted[i]);
        auto a1 = std::chrono::steady_clock::now();
        r.aggregate_ms += std::chrono::duration<double, std::milli>(a1-a0).count();
        r.aggregate_ciphertext_bytes += serialized_ciphertext_size(agg);
        aggregate.push_back(std::move(agg));
    }

    auto d0 = std::chrono::steady_clock::now();
    std::vector<int64_t> expected_prefix;
    std::vector<int64_t> actual;
    actual.reserve(n);
    for (std::size_t c = 0; c < aggregate.size(); ++c) {
        Plaintext pt;
        decryptor.decrypt(aggregate[c], pt);
        std::vector<uint64_t> packed;
        encoder.decode(pt, packed);
        std::size_t begin = c * slots;
        std::size_t end = std::min(n, begin + slots);
        for (std::size_t j = begin; j < end; ++j) {
            int64_t sum = 0;
            for (const auto& u : updates) sum += u[j];
            expected_prefix.push_back(sum);
            actual.push_back(static_cast<int64_t>(packed[j-begin]));
        }
    }
    auto d1 = std::chrono::steady_clock::now();
    r.decrypt_ms = std::chrono::duration<double, std::milli>(d1-d0).count();
    r.aggregate_prefix.assign(actual.begin(), actual.begin() + std::min<std::size_t>(actual.size(), 8));

    r.decrypt_check = true;
    for (std::size_t i = 0; i < actual.size(); ++i) {
        int64_t expected = expected_prefix[i];
        const int64_t t = static_cast<int64_t>(context.first_context_data()->parms().plain_modulus().value());
        int64_t expected_mod = (expected % t + t) % t;
        if (actual[i] != expected_mod) { r.decrypt_check = false; break; }
    }
    return r;
}
