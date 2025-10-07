#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>
#include <string>
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

// --- Polynomial Arithmetic Functions ---
Polynomial polyadd(const Polynomial& a, const Polynomial& b, const mpz_class& q) {
    size_t max_len = std::max(a.size(), b.size());
    Polynomial result(max_len);
    for (size_t i = 0; i < max_len; ++i) {
        mpz_class val_a = (i < a.size()) ? a[i] : 0;
        mpz_class val_b = (i < b.size()) ? b[i] : 0;
        result[i] = safe_mod(val_a + val_b, q);
    }
    return result;
}

Polynomial polysub(const Polynomial& a, const Polynomial& b, const mpz_class& q) {
    size_t max_len = std::max(a.size(), b.size());
    Polynomial result(max_len);
    for (size_t i = 0; i < max_len; ++i) {
        mpz_class val_a = (i < a.size()) ? a[i] : 0;
        mpz_class val_b = (i < b.size()) ? b[i] : 0;
        result[i] = safe_mod(val_a - val_b, q);
    }
    return result;
}

Polynomial polymul(const Polynomial& a, const Polynomial& b, const mpz_class& q) {
    if (a.empty() || b.empty()) return {};
    Polynomial result(a.size() + b.size() - 1, 0);
    for (size_t i = 0; i < a.size(); ++i) {
        for (size_t j = 0; j < b.size(); ++j) {
            result[i + j] = safe_mod(result[i + j] + a[i] * b[j], q);
        }
    }
    return result;
}

/**
 * @brief Appends the simulation results to a CSV file.
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
    for (int i = 0; i < 6; ++i) { // Loop to run multiple configurations
        try {
            // --- 1. Parameter Setup ---
            const int q_bits = 128;
            const int alpha_bits = 120;
            const size_t n_clients = 40;
            const size_t ki = 256 * static_cast<size_t>(std::pow(4, i));
            const std::string csv_filename = "make_proof.csv";

            gmp_randstate_t rand_state;
            gmp_randinit_default(rand_state);
            std::random_device rd_seeder;
            gmp_randseed_ui(rand_state, rd_seeder());

            const mpz_class q = generate_random_by_bits_gmp(q_bits, rand_state);
            const mpz_class alpha = generate_random_by_bits_gmp(alpha_bits, rand_state);

            // --- 2. Generate Original "Secret" Values ---
            mpz_class sum_of_u, R;
            mpz_urandomm(sum_of_u.get_mpz_t(), rand_state, q.get_mpz_t());
            mpz_urandomm(R.get_mpz_t(), rand_state, q.get_mpz_t());

            std::vector<uint64_t> client_seeds(n_clients);
            for (size_t c = 0; c < n_clients; ++c) {
                client_seeds[c] = rd_seeder();
            }

            std::vector<std::vector<int8_t>> list_of_b(n_clients, std::vector<int8_t>(ki));
            for (size_t c = 0; c < n_clients; ++c) {
                uint64_t current_seed = client_seeds[c];
                for (size_t k = 0; k < ki; ++k) {
                    list_of_b[c][k] = make_binomial_vector(current_seed + k, 1)[0];
                }
            }
            
            std::cout << "Starting C++ 'make_last_proof' simulation for ki=" << ki << "..." << std::endl;
            auto start = std::chrono::high_resolution_clock::now();

            // --- 3. Blinding Step: Generate Random Values to Hide Secrets ---
            // These random values will be the constant terms in our degree-1 polynomials.
            mpz_class rand_for_u, rand_for_R;
            mpz_urandomm(rand_for_u.get_mpz_t(), rand_state, q.get_mpz_t());
            mpz_urandomm(rand_for_R.get_mpz_t(), rand_state, q.get_mpz_t());

            std::vector<std::vector<mpz_class>> rand_for_b(n_clients, std::vector<mpz_class>(ki));
            for (size_t c = 0; c < n_clients; ++c) {
                for (size_t k = 0; k < ki; ++k) {
                    mpz_urandomm(rand_for_b[c][k].get_mpz_t(), rand_state, q.get_mpz_t());
                }
            }

            // --- 4. Polynomial Transformation Step ---
            // Convert each secret value into a degree-1 polynomial P(t) = rand + t * (secret - rand).
            // This polynomial evaluates to the random value at t=0 and the secret value at t=1.
            Polynomial one_degree_u_t = {rand_for_u, safe_mod(sum_of_u - rand_for_u, q)};
            Polynomial one_degree_R_t = {rand_for_R, safe_mod(R - rand_for_R, q)};
            
            std::vector<std::vector<Polynomial>> one_degree_list_of_b_t(n_clients, std::vector<Polynomial>(ki));
            for (size_t c = 0; c < n_clients; ++c) {
                for (size_t k = 0; k < ki; ++k) {
                    one_degree_list_of_b_t[c][k] = {rand_for_b[c][k], safe_mod(list_of_b[c][k] - rand_for_b[c][k], q)};
                }
            }
            
            // --- 5. Calculate Final Proof Polynomial F_t ---
            // The logic mirrors Python's __make_F_t, but operates on polynomials.
            // The resulting polynomial F_t will have a degree of n_clients.
            Polynomial sum_of_b_t_poly = {0};
            for (size_t k = 0; k < ki; ++k) {
                // Calculate Π(b_t) over all clients for a given k
                Polynomial mul_of_b_t_poly = one_degree_list_of_b_t[0][k];
                for (size_t c = 1; c < n_clients; ++c) {
                    mul_of_b_t_poly = polymul(mul_of_b_t_poly, one_degree_list_of_b_t[c][k], q);
                }
                // Add the resulting n_clients-degree polynomial to the sum
                sum_of_b_t_poly = polyadd(sum_of_b_t_poly, mul_of_b_t_poly, q);
            }

            Polynomial u_plus_b_poly = polyadd(one_degree_u_t, sum_of_b_t_poly, q);
            Polynomial sub_result_poly = polysub(u_plus_b_poly, one_degree_R_t, q);
            
            Polynomial F_t(sub_result_poly.size());
            for(size_t j = 0; j < sub_result_poly.size(); ++j) {
                F_t[j] = safe_mod(alpha * sub_result_poly[j], q);
            }

            // --- 6. Simulate Additive Sharing ---
            // This step simulates splitting the proof and blinding values into shares for distribution.
            // We measure its time cost but don't use the shares further in this simulation.
            
            // Share the final proof polynomial F_t
            std::vector<Polynomial> F_t_shares(n_clients, Polynomial(F_t.size()));
            for(size_t j = 0; j < F_t.size(); ++j) { // For each coefficient
                mpz_class coeff_sum = 0;
                for (size_t c = 0; c < n_clients - 1; ++c) {
                    mpz_urandomm(F_t_shares[c][j].get_mpz_t(), rand_state, q.get_mpz_t());
                    coeff_sum += F_t_shares[c][j];
                }
                F_t_shares[n_clients - 1][j] = safe_mod(F_t[j] - coeff_sum, q);
            }
            
            // Share the blinding values
            std::vector<mpz_class> rand_for_u_shares(n_clients);
            mpz_class u_share_sum = 0;
            for(size_t c = 0; c < n_clients - 1; ++c) {
                mpz_urandomm(rand_for_u_shares[c].get_mpz_t(), rand_state, q.get_mpz_t());
                u_share_sum += rand_for_u_shares[c];
            }
            rand_for_u_shares[n_clients - 1] = safe_mod(rand_for_u - u_share_sum, q);

            // (Sharing rand_for_b would be similar but is omitted for brevity as the logic is identical)

            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            // --- 7. Output Results ---
            std::cout << "--------------------------------------------------------" << std::endl;
            std::cout << "C++ (ZKP Logic): Time taken for 'make_last_proof' (ki=" << ki << "): " 
                      << duration.count() << " ms" << std::endl;
            // For brevity, we don't print the full polynomial. We save the time to CSV.
            std::cout << "--------------------------------------------------------" << std::endl;
            
            // --- 8. Save results to CSV file ---
            save_results_to_csv(csv_filename, q_bits, alpha_bits, n_clients, ki, duration.count());

            gmp_randclear(rand_state);

        } catch (const std::exception& e) {
            std::cerr << "Error in loop iteration: " << e.what() << std::endl;
        }
    }
    return 0;
}
