# verifiable-ZFL

RLWE, ZKP cpp code 

##  How to use

1. add secure noise.cpp

```c++
// run
./build_and_run.sh add_secure_noise.cpp -lssl -lcrypto
  
// parameter setting
const size_t vector_length = 1;
const size_t client_num = 100;
const size_t ki = 262144;
```

2. make proof.cpp

```c++
// run 
./build_and_run.sh make_proof.cpp -lssl -lcrypto -lgmpxx -lgmp
  
// parameter setting
const int q_bits = 128; // Set desired bit length (e.g., 128)
const int alpha_bits = 120;
const size_t n_clients = 100;
const size_t ki = 262144;
```

3. verify.cpp

```c++
// run
./build_and_run.sh verify.cpp -lgmpxx -lgmp
  
// parameter setting
const int q_bits = 120;
const int alpha_bits = 120;
const size_t n_clients = 100;
const size_t ki = 262144;
```

