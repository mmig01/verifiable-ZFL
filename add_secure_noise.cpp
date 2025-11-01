#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <random>
#include <stdexcept>
#include <fstream> // For file I/O

// OpenSSL headers for hashing
#include <openssl/evp.h>

/**
 * @brief (Unchanged) Generates a binomial vector from a seed using SHAKE256.
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
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (1 != EVP_DigestInit_ex(md_ctx, EVP_shake256(), NULL)) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to initialize SHAKE256 digest");
    }

    if (1 != EVP_DigestUpdate(md_ctx, seed_bytes, sizeof(seed_bytes))) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to update digest with seed");
    }
    
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
 * @brief (Unchanged) Generates a list of binomial vectors.
 */
std::vector<std::vector<int8_t>> make_list_of_binomial_vector(uint64_t seed, size_t length, size_t ki) {
    std::vector<std::vector<int8_t>> list_of_vectors;
    list_of_vectors.reserve(ki);
    for (size_t i = 0; i < ki; ++i) {
        list_of_vectors.push_back(make_binomial_vector(seed + i, length));
    }
    return list_of_vectors;
}

/**
 * @brief Appends the simulation results to a CSV file.
 * Creates the file and adds a header if it doesn't exist.
 */
void save_results_to_csv(
    const std::string& filename,
    size_t client_num,
    size_t kappa,
    size_t vector_length,
    long long duration_ms,
    int64_t final_value
) {
    // Check if the file exists to determine if we need to write the header
    std::ifstream file_check(filename);
    bool file_exists = file_check.good();
    file_check.close();

    // Open the file in append mode. This will create it if it doesn't exist.
    std::ofstream csv_file(filename, std::ios::app);

    if (!csv_file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << " for writing." << std::endl;
        return;
    }

    // If the file did not exist before, write the header row
    if (!file_exists) {
        csv_file << "client_num,kappa,vector_length,time_ms,final_value\n";
    }

    // Write the data row
    csv_file << client_num << ","
             << kappa << ","
             << vector_length << ","
             << duration_ms << ","
             << final_value << "\n";

    csv_file.close();
    std::cout << "Results successfully saved to " << filename << std::endl;
}


int main() {
    for (int i = 0; i < 6; ++i) {
        try {
            // --- Parameter Setup ---
            const size_t vector_length = 1;
            const size_t client_num = 10 + i * 10;
            const size_t kappa = 262144;
            const std::string csv_filename = "add_secure_noise.csv";

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
                std::vector<std::vector<int8_t>> temp_list = make_list_of_binomial_vector(seed_list[i], vector_length, kappa);
                if (i == 0) {
                    aggregated_list_of_vectors = std::move(temp_list);
                } else {
                    for (size_t j = 0; j < kappa; ++j) {
                        for (size_t l = 0; l < vector_length; ++l) {
                            aggregated_list_of_vectors[j][l] *= temp_list[j][l];
                        }
                    }
                }
            }

            std::vector<int64_t> sum_of_binomial_vector(vector_length, 0);
            for (size_t i = 0; i < kappa; ++i) {
                for (size_t j = 0; j < vector_length; ++j) {
                    sum_of_binomial_vector[j] += aggregated_list_of_vectors[i][j];
                }
            }
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            // --- Output results to console ---
            std::cout << "--------------------------------------------------------" << std::endl;
            std::cout << "C++ (ZKP_DPFL Logic): Time taken to generate secure noise for "
                    << client_num << " clients (kappa=" << kappa << ", length=" << vector_length
                    << "): " << duration.count() << " ms" << std::endl;
            
            int64_t final_sum_value = sum_of_binomial_vector.empty() ? 0 : sum_of_binomial_vector[0];
            std::cout << "Final summed noise value: " << final_sum_value << std::endl;
            std::cout << "--------------------------------------------------------" << std::endl;

            // --- Save results to CSV file ---
            save_results_to_csv(csv_filename, client_num, kappa, vector_length, duration.count(), final_sum_value);

        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    }
    return 0;
}
