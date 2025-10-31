#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>
#include <string>
#include <fstream> // For file I/O
#include <cmath>   // For std::pow
#include <cmath>   // For log2

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
 * @brief (Unchanged) Calculates the size of an mpz_class number in bytes.
 */
size_t get_mpz_bytes(const mpz_class& num) {
    if (num == 0) return 1;
    size_t bits = mpz_sizeinbase(num.get_mpz_t(), 2);
    return (bits + 7) / 8;
}

// --- Polynomial Arithmetic Functions (Unchanged) ---
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
 * @brief Appends the simulation results, including proof size, to a CSV file.
 * (Renamed ki to kappa and added proof_size_bytes)
 */
void save_results_to_csv(
    const std::string& filename, int q_bits, size_t n_clients, size_t kappa, long long duration_ms, size_t proof_size_bytes
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
        csv_file << "q_bits,n_clients,kappa,time_ms,proof_size_bytes\n";
    }

    csv_file << q_bits << "," << n_clients << "," << kappa << "," << duration_ms << "," << proof_size_bytes << "\n";
    csv_file.close();
    std::cout << "Results successfully saved to " << filename << std::endl;
}


int main() {
    for (int i = 0; i < 6; ++i) {
        try {
            // --- 1. Parameter Setup ---
            const int q_bits = 128;
            const size_t n_clients = 10 + i * 10;
            const size_t kappa = 262144; // Renamed from ki
            const std::string csv_filename = "prover_full_proof.csv"; // New filename

            gmp_randstate_t rand_state;
            gmp_randinit_default(rand_state);
            std::random_device rd_seeder;
            gmp_randseed_ui(rand_state, rd_seeder());

            const mpz_class q = generate_random_by_bits_gmp(q_bits, rand_state);

            // --- 2. Generate Original "Secret" Values ---
            mpz_class sum_of_u, R;
            mpz_urandomm(sum_of_u.get_mpz_t(), rand_state, q.get_mpz_t());
            mpz_urandomm(R.get_mpz_t(), rand_state, q.get_mpz_t());
            std::vector<uint64_t> client_seeds(n_clients);
            for (size_t c = 0; c < n_clients; ++c) client_seeds[c] = rd_seeder();
            std::vector<std::vector<int8_t>> list_of_b(n_clients, std::vector<int8_t>(kappa));
            for (size_t c = 0; c < n_clients; ++c) {
                for (size_t k = 0; k < kappa; ++k) {
                    list_of_b[c][k] = make_binomial_vector(client_seeds[c] + k, 1)[0];
                }
            }
            
            std::cout << "Starting C++ full Prover simulation for kappa=" << kappa << "..." << std::endl;
            
            // ====================== Timer Starts Here ======================
            auto start = std::chrono::high_resolution_clock::now();
            size_t total_proof_size_bytes = 0;

            // --- 3. `kappa_proof` Simulation Step ---
            // Calculate padded length for kappa
            size_t kappa_proof_length = 1;
            while (kappa_proof_length < kappa) kappa_proof_length *= 2;
            int log_kappa_loops = std::log2(kappa_proof_length);

            // Pad the list_of_b values
            std::vector<std::vector<mpz_class>> current_b_values(n_clients, std::vector<mpz_class>(kappa_proof_length, 0));
            for(size_t c = 0; c < n_clients; ++c) {
                for(size_t k = 0; k < kappa; ++k) {
                    current_b_values[c][k] = list_of_b[c][k];
                }
            }
            // `u` and `R` start as constants
            mpz_class current_u_val = sum_of_u;
            mpz_class current_R_val = R;

            for (int k_level = 1; k_level <= log_kappa_loops; ++k_level) {
                size_t current_vec_len = kappa_proof_length / (1 << (k_level - 1));

                // 3a. Convert current constants/vectors to polynomials
                // `u` and `R` are treated as special [0, constant] polynomials
                Polynomial poly_u = {0, current_u_val};
                Polynomial poly_R = {0, current_R_val};

                // `b` vectors are folded into 1st-degree polynomials
                std::vector<std::vector<Polynomial>> b_polys(n_clients, std::vector<Polynomial>(current_vec_len / 2));
                for(size_t c = 0; c < n_clients; ++c) {
                    for(size_t j = 0; j < current_vec_len / 2; ++j) {
                        b_polys[c][j] = {current_b_values[c][j], safe_mod(current_b_values[c][j + current_vec_len / 2] - current_b_values[c][j], q)};
                    }
                }

                // 3b. Calculate `kappa_F_t` (degree n_clients)
                Polynomial sum_of_b_t_poly = {0};
                for (size_t j = 0; j < current_vec_len / 2; ++j) {
                    Polynomial mul_of_b_t_poly = b_polys[0][j];
                    for (size_t c = 1; c < n_clients; ++c) {
                        mul_of_b_t_poly = polymul(mul_of_b_t_poly, b_polys[c][j], q);
                    }
                    sum_of_b_t_poly = polyadd(sum_of_b_t_poly, mul_of_b_t_poly, q);
                }
                Polynomial u_plus_b_poly = polyadd(poly_u, sum_of_b_t_poly, q);
                Polynomial kappa_F_t = polysub(u_plus_b_poly, poly_R, q);

                // 3c. Add `kappa_F_t` size to total proof size
                for(const auto& coeff : kappa_F_t) {
                    total_proof_size_bytes += get_mpz_bytes(coeff);
                }

                // 3d. Simulate `kappa_r_sum` generation and add its broadcast size
                mpz_class kappa_r_sum;
                mpz_urandomm(kappa_r_sum.get_mpz_t(), rand_state, q.get_mpz_t());
                total_proof_size_bytes += get_mpz_bytes(kappa_r_sum) * n_clients;

                // 3e. Evaluate polynomials at `kappa_r_sum` to get constants for the next loop
                current_u_val = polyval_gmp(poly_u, kappa_r_sum, q);
                current_R_val = polyval_gmp(poly_R, kappa_r_sum, q);
                
                std::vector<std::vector<mpz_class>> next_b_values(n_clients, std::vector<mpz_class>(current_vec_len / 2));
                for(size_t c = 0; c < n_clients; ++c) {
                    for(size_t j = 0; j < current_vec_len / 2; ++j) {
                        next_b_values[c][j] = polyval_gmp(b_polys[c][j], kappa_r_sum, q);
                    }
                }
                current_b_values = std::move(next_b_values);
            }
            // End of `kappa_proof`. `current_u_val`, `current_R_val`, and `current_b_values`
            // now hold the final constants. `current_b_values` is size n_clients x 1.
            mpz_class final_u_const = current_u_val;
            mpz_class final_R_const = current_R_val;
            std::vector<mpz_class> final_b_consts(n_clients);
            for(size_t c = 0; c < n_clients; ++c) {
                final_b_consts[c] = current_b_values[c][0];
            }


            // --- 4. `make_last_proof` Simulation Step ---
            // 4a. Blinding Step: Generate random values
            mpz_class rand_for_u, rand_for_R;
            mpz_urandomm(rand_for_u.get_mpz_t(), rand_state, q.get_mpz_t());
            mpz_urandomm(rand_for_R.get_mpz_t(), rand_state, q.get_mpz_t());
            std::vector<mpz_class> rand_for_b(n_clients);
            for (size_t c = 0; c < n_clients; ++c) {
                mpz_urandomm(rand_for_b[c].get_mpz_t(), rand_state, q.get_mpz_t());
            }

            // 4b. Polynomial Transformation
            Polynomial one_degree_u_t = {final_u_const, safe_mod(rand_for_u - final_u_const, q)};
            Polynomial one_degree_R_t = {final_R_const, safe_mod(rand_for_R - final_R_const, q)};
            std::vector<Polynomial> one_degree_list_of_b_t(n_clients);
            for (size_t c = 0; c < n_clients; ++c) {
                one_degree_list_of_b_t[c] = {final_b_consts[c], safe_mod(rand_for_b[c] - final_b_consts[c], q)};
            }

            // 4c. Calculate Final Proof Polynomial F_t (degree n_clients)
            Polynomial mul_of_b_t_poly = one_degree_list_of_b_t[0];
            for (size_t c = 1; c < n_clients; ++c) {
                mul_of_b_t_poly = polymul(mul_of_b_t_poly, one_degree_list_of_b_t[c], q);
            }
            Polynomial u_plus_b_poly = polyadd(one_degree_u_t, mul_of_b_t_poly, q);
            Polynomial F_t = polysub(u_plus_b_poly, one_degree_R_t, q);

            // 4d. Simulate Sharing & r_sum calculation
            mpz_class r_sum;
            mpz_urandomm(r_sum.get_mpz_t(), rand_state, q.get_mpz_t());
            
            // ====================== Timer Stops Here ======================
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            // --- 5. Final Proof Size Calculation ---
            // Add sizes for the 'make_last_proof' stage communication
            for(const auto& coeff : F_t) {
                total_proof_size_bytes += get_mpz_bytes(coeff);
            }
            total_proof_size_bytes += get_mpz_bytes(rand_for_u);
            for (const auto& val : rand_for_b) {
                total_proof_size_bytes += get_mpz_bytes(val);
            }
            total_proof_size_bytes += get_mpz_bytes(rand_for_R) * n_clients;
            total_proof_size_bytes += get_mpz_bytes(r_sum) * n_clients;

            // --- 6. Output Results ---
            std::cout << "--------------------------------------------------------" << std::endl;
            std::cout << "C++ (ZKP Logic): Time for full Prover logic (kappa=" << kappa << "): " 
                      << duration.count() << " ms" << std::endl;
            std::cout << "Total proof size to be transmitted: " << total_proof_size_bytes << " bytes" << std::endl;
            std::cout << "--------------------------------------------------------" << std::endl;
            
            // --- 7. Save results to CSV file ---
            save_results_to_csv(csv_filename, q_bits, n_clients, kappa, duration.count(), total_proof_size_bytes);

            gmp_randclear(rand_state);

        } catch (const std::exception& e) {
            std::cerr << "Error in loop iteration: " << e.what() << std::endl;
        }
    }
    return 0;
}
