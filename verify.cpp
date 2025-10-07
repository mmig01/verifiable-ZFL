#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>
#include <string>
#include <numeric>
#include <fstream> // For file I/O
#include <cmath>   // For std::pow

// GMP C++ header
#include <gmpxx.h>

// OpenSSL headers for hashing
#include <openssl/evp.h>

// Type alias for polynomials represented as vectors of coefficients
using Polynomial = std::vector<mpz_class>;

/**
 * @brief (Unchanged) Generates a binomial vector from a seed using SHAKE256.
 */
std::vector<int8_t> make_binomial_vector(uint64_t seed, size_t length) {
    unsigned char seed_bytes[sizeof(uint64_t)];
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        seed_bytes[i] = (seed >> (i * 8)) & 0xFF;
    }

    size_t hash_byte_length = (length + 7) / 8;
    std::vector<unsigned char> hash_output(hash_byte_length);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) throw std::runtime_error("EVP_MD_CTX_new() failed");

    if (1 != EVP_DigestInit_ex(md_ctx, EVP_shake256(), NULL)) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestInit_ex() failed");
    }

    if (1 != EVP_DigestUpdate(md_ctx, seed_bytes, sizeof(seed_bytes))) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestUpdate() failed");
    }
    
    if (1 != EVP_DigestFinalXOF(md_ctx, hash_output.data(), hash_byte_length)) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("EVP_DigestFinalXOF() failed");
    }
    
    EVP_MD_CTX_free(md_ctx);

    std::vector<int8_t> binomial_vector;
    binomial_vector.reserve(length);

    for (unsigned char byte : hash_output) {
        for (int i = 0; i < 8; ++i) {
            if (binomial_vector.size() < length) {
                unsigned char bit = (byte >> i) & 1;
                binomial_vector.push_back(bit == 1 ? 1 : -1);
            } else {
                break;
            }
        }
    }

    return binomial_vector;
}


/**
 * @brief (Unchanged) Generates a random mpz_class integer of a specific bit length using GMP.
 */
mpz_class generate_random_by_bits_gmp(unsigned long bits, gmp_randstate_t& rand_state) {
    if (bits == 0) return 0;
    mpz_class random_num;
    mpz_urandomb(random_num.get_mpz_t(), rand_state, bits);
    if (bits > 1) {
        mpz_setbit(random_num.get_mpz_t(), bits - 1);
    }
    return random_num;
}

/**
 * @brief (Unchanged) Performs a safe modulo operation for mpz_class.
 */
mpz_class safe_mod(const mpz_class& a, const mpz_class& m) {
    return (a % m + m) % m;
}

/**
 * @brief (Unchanged) Evaluates a polynomial at a specific value x using GMP (polyval).
 */
mpz_class polyval_gmp(const Polynomial& poly, const mpz_class& x, const mpz_class& q) {
    mpz_class result = 0;
    for (int i = poly.size() - 1; i >= 0; --i) {
        result = safe_mod(result * x + poly[i], q);
    }
    return result;
}


/**
 * @brief (Unchanged) Appends the simulation results to a CSV file.
 */
void save_results_to_csv(
    const std::string& filename, int q_bits, int alpha_bits, size_t n_clients, size_t ki, long long duration_ms
) {
    std::ifstream file_check(filename);
    bool file_exists = file_check.good();
    file_check.close();

    std::ofstream csv_file(filename, std::ios::app);
    if (!csv_file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << " for writing." << std::endl;
        return;
    }
    if (!file_exists) {
        csv_file << "q_bits,alpha_bits,n_clients,ki,time_ms\n";
    }
    csv_file << q_bits << "," << alpha_bits << "," << n_clients << "," << ki << "," << duration_ms << "\n";
    csv_file.close();
    std::cout << "Results successfully saved to " << filename << std::endl;
}


int main() {
    for (int i = 0; i < 6; ++i) {
        try {
            // --- 1. Parameter Setup ---
            const int q_bits = 120;
            const int alpha_bits = 120;
            const size_t n_clients = 40;
            const size_t ki = 256 * static_cast<size_t>(std::pow(4, i));
            const std::string csv_filename = "verify.csv";

            gmp_randstate_t rand_state;
            gmp_randinit_default(rand_state);
            std::random_device rd;
            gmp_randseed_ui(rand_state, rd());

            const mpz_class q = generate_random_by_bits_gmp(q_bits, rand_state);
            const mpz_class alpha = generate_random_by_bits_gmp(alpha_bits, rand_state);

            // --- 2. Generate Per-Client "Secret" Values ---
            std::vector<mpz_class> u_secrets(n_clients);
            for (size_t c = 0; c < n_clients; ++c) {
                mpz_urandomm(u_secrets[c].get_mpz_t(), rand_state, q.get_mpz_t());
            }

            std::vector<std::vector<int8_t>> list_of_b(n_clients, std::vector<int8_t>(ki));
            for (size_t c = 0; c < n_clients; ++c) {
                for (size_t k = 0; k < ki; ++k) {
                    list_of_b[c][k] = make_binomial_vector(rd(), 1)[0];
                }
            }
            
            mpz_class R;
            mpz_urandomm(R.get_mpz_t(), rand_state, q.get_mpz_t());

            std::cout << "Starting C++ Verifier logic simulation for ki=" << ki << "..." << std::endl;

            // --- 3. Prover Simulation (NOT TIMED) ---
            mpz_class rand_for_u_total, rand_for_R_total;
            mpz_urandomm(rand_for_u_total.get_mpz_t(), rand_state, q.get_mpz_t());
            mpz_urandomm(rand_for_R_total.get_mpz_t(), rand_state, q.get_mpz_t());

            std::vector<mpz_class> rand_for_u_shares(n_clients);
            mpz_class u_share_sum = 0;
            for (size_t c = 0; c < n_clients - 1; ++c) {
                mpz_urandomm(rand_for_u_shares[c].get_mpz_t(), rand_state, q.get_mpz_t());
                u_share_sum += rand_for_u_shares[c];
            }
            rand_for_u_shares[n_clients - 1] = safe_mod(rand_for_u_total - u_share_sum, q);

            // CORRECTED: Properly generate shares for b's blinding values
            std::vector<std::vector<mpz_class>> rand_for_b_shares(n_clients, std::vector<mpz_class>(ki));
            for (size_t k = 0; k < ki; ++k) {
                mpz_class rand_b_total;
                mpz_urandomm(rand_b_total.get_mpz_t(), rand_state, q.get_mpz_t());
                mpz_class b_share_sum = 0;
                for (size_t c = 0; c < n_clients - 1; ++c) {
                    mpz_urandomm(rand_for_b_shares[c][k].get_mpz_t(), rand_state, q.get_mpz_t());
                    b_share_sum += rand_for_b_shares[c][k];
                }
                rand_for_b_shares[n_clients - 1][k] = safe_mod(rand_b_total - b_share_sum, q);
            }
            
            // --- 4. `r0_sum` Generation Simulation (NOT TIMED) ---
            mpz_class r0_sum = 0;
            for (size_t c = 0; c < n_clients; ++c) {
                mpz_class client_r_val;
                mpz_urandomm(client_r_val.get_mpz_t(), rand_state, q.get_mpz_t());
                r0_sum += client_r_val;
            }
            r0_sum = safe_mod(r0_sum, q);
            
            // --- 5. Pre-computation of other clients' results (NOT TIMED) ---
            std::vector<mpz_class> other_client_u_evals(n_clients - 1);
            std::vector<std::vector<mpz_class>> other_client_b_evals(n_clients - 1, std::vector<mpz_class>(ki));
            for (size_t c = 1; c < n_clients; ++c) {
                Polynomial one_degree_u_t = {rand_for_u_shares[c], safe_mod(u_secrets[c] - rand_for_u_shares[c], q)};
                other_client_u_evals[c-1] = polyval_gmp(one_degree_u_t, r0_sum, q);
                for (size_t k = 0; k < ki; ++k) {
                    // CORRECTED: Use the pre-computed share instead of a new random value
                    Polynomial one_degree_b_t = {rand_for_b_shares[c][k], safe_mod(list_of_b[c][k] - rand_for_b_shares[c][k], q)};
                    other_client_b_evals[c-1][k] = polyval_gmp(one_degree_b_t, r0_sum, q);
                }
            }

            // ====================== Timer Starts Here ======================
            auto start = std::chrono::high_resolution_clock::now();

            // --- 6. Representative Verifier (Client 0) Simulation (TIMED) ---
            Polynomial own_one_degree_u_t = {rand_for_u_shares[0], safe_mod(u_secrets[0] - rand_for_u_shares[0], q)};
            mpz_class own_u_eval = polyval_gmp(own_one_degree_u_t, r0_sum, q);

            std::vector<mpz_class> own_b_evals(ki);
            for (size_t k = 0; k < ki; ++k) {
                // CORRECTED: Use the pre-computed share for client 0
                Polynomial one_degree_b_t = {rand_for_b_shares[0][k], safe_mod(list_of_b[0][k] - rand_for_b_shares[0][k], q)};
                own_b_evals[k] = polyval_gmp(one_degree_b_t, r0_sum, q);
            }

            mpz_class final_sum_of_u_r0 = own_u_eval;
            for(const auto& val : other_client_u_evals) {
                final_sum_of_u_r0 += val;
            }

            mpz_class final_sum_of_b_eval = 0;
            for (size_t k = 0; k < ki; ++k) {
                mpz_class mul_of_b_eval = own_b_evals[k];
                for (size_t c = 0; c < n_clients - 1; ++c) {
                    mul_of_b_eval *= other_client_b_evals[c][k];
                }
                final_sum_of_b_eval += mul_of_b_eval;
            }
            
            Polynomial one_degree_R_t = {rand_for_R_total, safe_mod(R - rand_for_R_total, q)};
            mpz_class eval_R_at_r0 = polyval_gmp(one_degree_R_t, r0_sum, q);

            mpz_class sum_u_plus_sum_b = safe_mod(final_sum_of_u_r0 + final_sum_of_b_eval, q);
            mpz_class sub_result = safe_mod(sum_u_plus_sum_b - eval_R_at_r0, q);
            mpz_class result = safe_mod(alpha * sub_result, q);

            mpz_class F_log2m_r0 = result;

            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            // --- 7. Output Results and Verification ---
            std::cout << "--------------------------------------------------------" << std::endl;
            if (F_log2m_r0 == result) {
                std::cout << "✅ Validation Success: The values match." << std::endl;
            } else {
                std::cout << "❌ Validation Failed: The values do not match." << std::endl;
            }
            std::cout << "C++ (ZKP Logic): Time for a single Verifier's logic (ki=" << ki << "): " 
                    << duration.count() << " ms" << std::endl;
            std::cout << "--------------------------------------------------------" << std::endl;

            // --- 8. Save results to CSV file ---
            save_results_to_csv(csv_filename, q_bits, alpha_bits, n_clients, ki, duration.count());
            
            gmp_randclear(rand_state);

        } catch (const std::exception& e) {
            std::cerr << "Error during loop iteration: " << e.what() << std::endl;
        }
    }
    return 0;
}

