#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>
#include <string>
#include <limits>

// OpenSSL headers for hashing
#include <openssl/evp.h>

/**
 * @brief Generates a binomial vector from a seed using SHAKE256.
 * (This function is unchanged)
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
 * @brief Generates a random 64-bit integer of a specific bit length.
 * (This function is unchanged)
 */
uint64_t generate_random_by_bits(int bits, std::mt19937_64& generator) {
    if (bits <= 0) return 0;
    if (bits > 64) throw std::out_of_range("Bit length cannot exceed 64.");
    if (bits == 1) return std::uniform_int_distribution<uint64_t>(0, 1)(generator);

    uint64_t lower_bound = 1ULL << (bits - 1);
    uint64_t upper_bound = (bits == 64) ? std::numeric_limits<uint64_t>::max() : (1ULL << bits) - 1;
    
    std::uniform_int_distribution<uint64_t> distrib(lower_bound, upper_bound);
    return distrib(generator);
}


int main() {
    try {
        // --- 1. Parameter Setup (Hardcoded) ---
        const int q_bits = 60;
        const int alpha_bits = 60;
        const size_t n_clients = 5;
        const size_t ki = 262144;

        std::random_device rd;
        std::mt19937_64 gen(rd());

        // Generate q and alpha using the hardcoded bit lengths
        const int64_t q = generate_random_by_bits(q_bits, gen);
        const int64_t alpha = generate_random_by_bits(alpha_bits, gen);

        // --- 2. Test Data Generation ---
        std::uniform_int_distribution<int64_t> distrib_q(0, q - 1);
        std::uniform_int_distribution<uint64_t> distrib_seed;

        int64_t sum_of_u = distrib_q(gen);
        int64_t R = distrib_q(gen);

        std::cout << "Starting C++ integer-based proof generation..." << std::endl;
        std::cout << "Generated q (" << q_bits << " bits): " << q << std::endl;
        std::cout << "Generated alpha (" << alpha_bits << " bits): " << alpha << std::endl;


        std::vector<uint64_t> client_seeds;
        for (size_t c = 0; c < n_clients; ++c) {
            client_seeds.push_back(distrib_seed(gen));
        }   

        auto start = std::chrono::high_resolution_clock::now();

        std::vector<std::vector<int64_t>> list_of_b(n_clients, std::vector<int64_t>(ki));
        for (size_t c = 0; c < n_clients; ++c) {
            uint64_t current_seed = client_seeds[c];
            for (size_t k = 0; k < ki; ++k) {
                std::vector<int8_t> result_vec = make_binomial_vector(current_seed + k, 1);
                list_of_b[c][k] = result_vec[0];
            }
        }
        

        // --- 3. Core Logic to Calculate F (remains unchanged) ---
        int64_t sum_of_b = 0;
        for (size_t k = 0; k < ki; ++k) {
            int64_t mul_of_b = 1;
            for (size_t c = 0; c < n_clients; ++c) {
                mul_of_b *= list_of_b[c][k];
            }
            sum_of_b += mul_of_b;
        }
        sum_of_b = (sum_of_b % q + q) % q;
        int64_t u_plus_b = (sum_of_u + sum_of_b) % q;
        int64_t sub_result = (u_plus_b - R % q + q) % q;
        int64_t F = (alpha * sub_result) % q;

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        // --- 4. Output Results ---
        std::cout << "--------------------------------------------------------" << std::endl;
        std::cout << "C++ (ZKP Logic): Time taken for " << n_clients 
                  << " clients (ki=" << ki << "): " << duration.count() << " ms" << std::endl;
        std::cout << "Final proof value (F): " << F << std::endl;
        std::cout << "--------------------------------------------------------" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}