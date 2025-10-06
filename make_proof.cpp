#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>
#include <string>

// GMP C++ header
#include <gmpxx.h>

// OpenSSL headers for hashing
#include <openssl/evp.h>

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
 * @brief Generates a random mpz_class integer of a specific bit length using GMP.
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
 * @brief Performs a safe modulo operation for mpz_class, ensuring a non-negative result.
 */
mpz_class safe_mod(const mpz_class& a, const mpz_class& m) {
    return (a % m + m) % m;
}


int main() {
    try {
        // --- 1. Parameter Setup (Hardcoded) ---
        const int q_bits = 128; // Set desired bit length (e.g., 128)
        const int alpha_bits = 120;
        const size_t n_clients = 100;
        const size_t ki = 262144;

        // --- Initialize GMP Random State ---
        gmp_randstate_t rand_state;
        gmp_randinit_default(rand_state);
        std::random_device rd_seeder;
        gmp_randseed_ui(rand_state, rd_seeder());

        // Generate q and alpha using GMP
        const mpz_class q = generate_random_by_bits_gmp(q_bits, rand_state);
        const mpz_class alpha = generate_random_by_bits_gmp(alpha_bits, rand_state);

        // --- 2. Test Data Generation ---
        mpz_class sum_of_u, R;
        // Generate sum_of_u and R in the range [0, q-1]
        mpz_urandomm(sum_of_u.get_mpz_t(), rand_state, q.get_mpz_t());
        mpz_urandomm(R.get_mpz_t(), rand_state, q.get_mpz_t());

        std::cout << "Starting C++ bignum-based proof generation..." << std::endl;
        std::cout << "Generated q (" << q_bits << " bits): " << q << std::endl;
        std::cout << "Generated alpha (" << alpha_bits << " bits): " << alpha << std::endl;

        std::vector<uint64_t> client_seeds(n_clients);
        for (size_t c = 0; c < n_clients; ++c) {
            client_seeds[c] = rd_seeder();
        }   

        auto start = std::chrono::high_resolution_clock::now();

        std::vector<std::vector<int8_t>> list_of_b(n_clients, std::vector<int8_t>(ki));
        for (size_t c = 0; c < n_clients; ++c) {
            uint64_t current_seed = client_seeds[c];
            for (size_t k = 0; k < ki; ++k) {
                list_of_b[c][k] = make_binomial_vector(current_seed + k, 1)[0];
            }
        }
        
        // --- 3. Core Logic to Calculate F (using mpz_class) ---
        mpz_class sum_of_b = 0;
        for (size_t k = 0; k < ki; ++k) {
            // Using int for mul_of_b is safe as it's only ever 1 or -1
            int mul_of_b = 1; 
            for (size_t c = 0; c < n_clients; ++c) {
                mul_of_b *= list_of_b[c][k];
            }
            sum_of_b += mul_of_b;
        }

        sum_of_b = safe_mod(sum_of_b, q);
        mpz_class u_plus_b = safe_mod(sum_of_u + sum_of_b, q);
        mpz_class sub_result = safe_mod(u_plus_b - R, q);
        mpz_class F = safe_mod(alpha * sub_result, q);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        // --- 4. Output Results ---
        std::cout << "--------------------------------------------------------" << std::endl;
        std::cout << "C++ (ZKP Logic): Time taken for " << n_clients 
                  << " clients (ki=" << ki << "): " << duration.count() << " ms" << std::endl;
        std::cout << "Final proof value (F): " << F << std::endl;
        std::cout << "--------------------------------------------------------" << std::endl;
        
        // Clean up GMP random state
        gmp_randclear(rand_state);

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
