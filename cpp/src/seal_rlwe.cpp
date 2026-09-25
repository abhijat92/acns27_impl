#include "seal_rlwe.h"
#include <chrono>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <limits>
#include <sstream>

#include "seal/util/ntt.h"

using namespace seal;

namespace {

std::size_t serialized_ciphertext_size(const Ciphertext& x) {
    return x.save_size();
}

std::string rlwe_parameter_string(std::size_t poly_degree) {
    std::ostringstream os;
    os << "N=" << poly_degree
       << ", T=" << ACNS_PLAINTEXT_MODULUS
       << ", Q=[";
    for (std::size_t i = 0; i < std::size(ACNS_NTT_MODULI); ++i) {
        if (i) os << ",";
        os << ACNS_NTT_MODULI[i];
    }
    os << "]";
    return os.str();
}

// Construct a plaintext polynomial directly in coefficient form.
//
// We intentionally do not use BatchEncoder here: T = 2^16 is the
// application plaintext modulus requested by the RLWE construction, while
// SEAL's batching encoder requires a batching-compatible plaintext modulus.
// Direct coefficient encoding lets us keep T exactly equal to 2^16.
Plaintext encode_rlwe_plaintext(
    const std::vector<int64_t>& values,
    std::size_t begin,
    std::size_t poly_degree,
    std::uint64_t t)
{
    if (values.size() - begin > poly_degree) {
        throw std::invalid_argument("RLWE plaintext does not fit in one polynomial");
    }

    Plaintext pt(poly_degree);

    for (std::size_t i = 0; i < poly_degree; ++i) {
        std::int64_t v = 0;
        if (begin + i < values.size()) {
            v = values[begin + i];
        }

        const std::int64_t tt = static_cast<std::int64_t>(t);
        const std::int64_t reduced = (v % tt + tt) % tt;
        pt[i] = static_cast<std::uint64_t>(reduced);
    }

    return pt;
}

// Apply SEAL's negacyclic NTT independently to each RNS prime.
//
// The returned vector contains one NTT representation per q_i.
// This helper is used by the mode-1 Bulletproof path and is deliberately
// kept separate from the BGV benchmark so that the RLWE NTT representation
// is explicit.
std::vector<std::vector<std::uint64_t>> ntt_rns(
    const std::vector<std::uint64_t>& coeffs,
    const SEALContext& context)
{
    const auto& cd = *context.first_context_data();
    const auto& tables = cd.small_ntt_tables();

    if (coeffs.size() != cd.parms().poly_modulus_degree()) {
        throw std::invalid_argument("NTT input must have N coefficients");
    }

    std::vector<std::vector<std::uint64_t>> result;
    result.reserve(std::size(ACNS_NTT_MODULI));

    for (std::size_t r = 0; r < std::size(ACNS_NTT_MODULI); ++r) {
        std::vector<std::uint64_t> poly(coeffs.size());

        const std::uint64_t q = ACNS_NTT_MODULI[r];
        for (std::size_t i = 0; i < coeffs.size(); ++i) {
            poly[i] = coeffs[i] % q;
        }

        util::ntt_negacyclic_harvey(poly.data(), *tables[r]);
        result.push_back(std::move(poly));
    }

    return result;
}

} // namespace

SealBenchResult benchmark_bgv_aggregation(
    const std::vector<std::vector<int64_t>>& updates,
    std::size_t poly_degree)
{
    if (updates.empty()) {
        throw std::invalid_argument("no clients");
    }

    if (poly_degree != ACNS_RLWE_N) {
        throw std::invalid_argument(
            "ACNS RLWE parameter set currently requires N=8192");
    }

    const std::size_t n = updates.front().size();

    if (n > poly_degree) {
        throw std::invalid_argument(
            "update length exceeds the RLWE polynomial degree");
    }

    for (const auto& u : updates) {
        if (u.size() != n) {
            throw std::invalid_argument("size mismatch");
        }
    }

    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_degree);

    // Q is a 96-bit aggregate modulus represented by three 32-bit RNS
    // primes. Every prime satisfies q_i = 1 mod 2N, enabling the
    // negacyclic NTT for N=8192.
    parms.set_coeff_modulus({
        Modulus(ACNS_Q0),
        Modulus(ACNS_Q1),
        Modulus(ACNS_Q2)
    });

    // ACORN/RLWE plaintext modulus: T = 2^16 exactly.
    parms.set_plain_modulus(ACNS_PLAINTEXT_MODULUS);

    SEALContext context(parms);

    if (!context.parameters_set()) {
        throw std::runtime_error(
            "invalid SEAL parameters: " + context.parameter_error_message());
    }

    std::cout << "# RLWE parameters: "
              << rlwe_parameter_string(poly_degree) << "\n";

    // Sanity-check the NTT tables and modulus congruence.
    for (std::size_t i = 0; i < std::size(ACNS_NTT_MODULI); ++i) {
        const std::uint64_t q = ACNS_NTT_MODULI[i];

        if ((q - 1) % (2 * poly_degree) != 0) {
            throw std::runtime_error(
                "RLWE modulus is not NTT-friendly for N=8192");
        }

        if (ACNS_PLAINTEXT_MODULUS == 0 ||
            q % ACNS_PLAINTEXT_MODULUS == 0) {
            throw std::runtime_error(
                "plaintext modulus is not coprime to an RLWE modulus");
        }
    }

    SealBenchResult r;

    auto t0 = std::chrono::steady_clock::now();

    KeyGenerator keygen(context);
    SecretKey sk = keygen.secret_key();

    PublicKey pk;
    keygen.create_public_key(pk);

    auto t1 = std::chrono::steady_clock::now();
    r.keygen_ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();

    Encryptor encryptor(context, pk);
    Evaluator evaluator(context);
    Decryptor decryptor(context, sk);

    /*
     * With T=2^16 we intentionally encode the update directly as a
     * polynomial. BatchEncoder is not used because T is not a batching
     * prime for N=8192.
     */
    const std::size_t chunks =
        (n + poly_degree - 1) / poly_degree;

    r.chunks = chunks;

    std::vector<Ciphertext> aggregate;
    aggregate.reserve(chunks);

    for (std::size_t c = 0; c < chunks; ++c) {
        std::vector<Ciphertext> encrypted;
        encrypted.reserve(updates.size());

        const std::size_t begin = c * poly_degree;

        for (const auto& update : updates) {
            auto e0 = std::chrono::steady_clock::now();

            Plaintext pt = encode_rlwe_plaintext(
                update,
                begin,
                poly_degree,
                ACNS_PLAINTEXT_MODULUS);

            auto e1 = std::chrono::steady_clock::now();

            r.encode_ms +=
                std::chrono::duration<double, std::milli>(
                    e1 - e0).count();

            auto e2 = std::chrono::steady_clock::now();

            Ciphertext ct;
            encryptor.encrypt(pt, ct);

            auto e3 = std::chrono::steady_clock::now();

            r.encrypt_ms +=
                std::chrono::duration<double, std::milli>(
                    e3 - e2).count();

            if (c == 0) {
                r.ciphertext_bytes_per_client +=
                    serialized_ciphertext_size(ct);
                r.plaintext_bytes_per_client +=
                    pt.save_size();
            }

            encrypted.push_back(std::move(ct));
        }

        auto a0 = std::chrono::steady_clock::now();

        Ciphertext agg = encrypted.front();

        for (std::size_t i = 1; i < encrypted.size(); ++i) {
            evaluator.add_inplace(agg, encrypted[i]);
        }

        auto a1 = std::chrono::steady_clock::now();

        r.aggregate_ms +=
            std::chrono::duration<double, std::milli>(
                a1 - a0).count();

        r.aggregate_ciphertext_bytes +=
            serialized_ciphertext_size(agg);

        aggregate.push_back(std::move(agg));
    }

    /*
     * Decrypt and check coefficient-wise modulo T.
     */
    auto d0 = std::chrono::steady_clock::now();

    std::vector<int64_t> expected;
    std::vector<int64_t> actual;

    expected.reserve(n);
    actual.reserve(n);

    for (std::size_t c = 0; c < aggregate.size(); ++c) {
        Plaintext pt;
        decryptor.decrypt(aggregate[c], pt);

        const std::size_t begin = c * poly_degree;
        const std::size_t end =
            std::min(n, begin + poly_degree);

        for (std::size_t j = begin; j < end; ++j) {
            int64_t sum = 0;
            for (const auto& u : updates) {
                sum += u[j];
            }

            expected.push_back(sum);

            const std::uint64_t value =
                pt[j - begin] % ACNS_PLAINTEXT_MODULUS;

            actual.push_back(static_cast<int64_t>(value));
        }
    }

    auto d1 = std::chrono::steady_clock::now();

    r.decrypt_ms =
        std::chrono::duration<double, std::milli>(
            d1 - d0).count();

    r.aggregate_prefix.assign(
        actual.begin(),
        actual.begin() + std::min<std::size_t>(actual.size(), 8));

    r.decrypt_check = true;

    for (std::size_t i = 0; i < actual.size(); ++i) {
        const std::int64_t t =
            static_cast<std::int64_t>(ACNS_PLAINTEXT_MODULUS);

        const std::int64_t expected_mod =
            (expected[i] % t + t) % t;

        if (actual[i] != expected_mod) {
            r.decrypt_check = false;
            break;
        }
    }

    return r;
}
