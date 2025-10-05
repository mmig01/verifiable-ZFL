#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>

// OpenSSL headers for hashing
#include <openssl/evp.h>

/**
 * @brief Generates a binomial vector from a seed using SHAKE256.
 *
 * This function replicates the behavior of Python's `_make_binomial_vector`.
 * It uses the SHAKE256 extendable-output function (XOF) to generate a stream
 * of pseudo-random bits from a seed. These bits are then mapped to -1 or 1.
 *
 * @param seed A 64-bit integer seed for the random number generator.
 * @param length The desired length of the output vector.
 * @return A std::vector<int8_t> containing values of -1 or 1.
 */
std::vector<int8_t> make_binomial_vector(uint64_t seed, size_t length) {
    // 1. Prepare the seed as a byte array (little-endian, like the Rust code)
    unsigned char seed_bytes[sizeof(uint64_t)];
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        seed_bytes[i] = (seed >> (i * 8)) & 0xFF;
    }

    // 2. Calculate the number of bytes needed from the hash function
    size_t hash_byte_length = (length + 7) / 8;
    std::vector<unsigned char> hash_output(hash_byte_length);

    // 3. Use OpenSSL's EVP interface to perform SHAKE256 hashing
    // This requires OpenSSL version 1.1.1 or newer.
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // Initialize SHAKE256 digest
    if (1 != EVP_DigestInit_ex(md_ctx, EVP_shake256(), NULL)) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to initialize SHAKE256 digest");
    }

    // Update the digest with the seed bytes
    if (1 != EVP_DigestUpdate(md_ctx, seed_bytes, sizeof(seed_bytes))) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to update digest with seed");
    }
    
    // "Squeeze" the extendable output to the desired length
    if (1 != EVP_DigestFinalXOF(md_ctx, hash_output.data(), hash_byte_length)) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to finalize SHAKE256 XOF");
    }
    
    EVP_MD_CTX_free(md_ctx);

    // 4. Convert the generated hash bits into the binomial vector {-1, 1}
    std::vector<int8_t> binomial_vector;
    binomial_vector.reserve(length);

    for (unsigned char byte : hash_output) {
        for (int i = 0; i < 8; ++i) {
            if (binomial_vector.size() < length) {
                // Extract the i-th bit from the byte
                unsigned char bit = (byte >> i) & 1;
                binomial_vector.push_back(bit == 1 ? 1 : -1);
            } else {
                break; // Stop when the vector reaches the desired length
            }
        }
    }

    return binomial_vector;
}

/**
 * @brief Generates a list of binomial vectors.
 *
 * This function replicates the behavior of Python's `make_list_of_binomial_vector`.
 * It calls `make_binomial_vector` `ki` times with incrementing seeds.
 *
 * @param seed The initial 64-bit integer seed.
 * @param length The length of each binomial vector.
 * @param ki The number of binomial vectors to generate.
 * @return A std::vector containing `ki` binomial vectors.
 */
std::vector<std::vector<int8_t>> make_list_of_binomial_vector(uint64_t seed, size_t length, size_t ki) {
    std::vector<std::vector<int8_t>> list_of_vectors;
    list_of_vectors.reserve(ki);
    for (size_t i = 0; i < ki; ++i) {
        // Generate each vector with an incremented seed (seed, seed+1, seed+2, ...)
        list_of_vectors.push_back(make_binomial_vector(seed + i, length));
    }
    return list_of_vectors;
}

int main() {
    try {
        // --- Parameter Setup ---
        // These values match the Rust example.
        const size_t vector_length = 1;
        const size_t client_num = 5;
        const size_t ki = 262144;

        // --- Generate random seeds for each client ---
        std::vector<uint64_t> seed_list;
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> distrib;
        
        std::cout << "Generating " << client_num << " random seeds for clients..." << std::endl;
        for (size_t i = 0; i < client_num; ++i) {
            seed_list.push_back(distrib(gen));
        }

        std::cout << "Starting C++ secure noise generation..." << std::endl;
        auto start = std::chrono::high_resolution_clock::now();

        // --- Core logic from `add_secure_global_noise` ---
        std::vector<std::vector<int8_t>> aggregated_list_of_vectors;

        for (size_t i = 0; i < client_num; ++i) {
            // Generate the list of ki vectors for the current client
            std::vector<std::vector<int8_t>> temp_list = make_list_of_binomial_vector(seed_list[i], vector_length, ki);

            if (i == 0) {
                // For the first client, just copy the generated vectors
                aggregated_list_of_vectors = std::move(temp_list);
            } else {
                // For subsequent clients, perform component-wise multiplication
                for (size_t j = 0; j < ki; ++j) {
                    for (size_t l = 0; l < vector_length; ++l) {
                        aggregated_list_of_vectors[j][l] *= temp_list[j][l];
                    }
                }
            }
        }

        // Sum all the final aggregated vectors to get the noise vector
        // NOTE: A wider type like int64_t is used for the sum to prevent potential overflow,
        // as the sum can range from -ki to +ki.
        std::vector<int64_t> sum_of_binomial_vector(vector_length, 0);
        for (size_t i = 0; i < ki; ++i) {
            for (size_t j = 0; j < vector_length; ++j) {
                sum_of_binomial_vector[j] += aggregated_list_of_vectors[i][j];
            }
        }
        // --- End of core logic ---

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::cout << "--------------------------------------------------------" << std::endl;
        std::cout << "C++ (ZKP_DPFL Logic): Time taken to generate secure noise for "
                  << client_num << " clients (ki=" << ki << ", length=" << vector_length
                  << "): " << duration.count() << " ms" << std::endl;
        
        if (!sum_of_binomial_vector.empty()) {
            std::cout << "Final summed noise value: " << sum_of_binomial_vector[0] << std::endl;
        }

        std::cout << "--------------------------------------------------------" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}