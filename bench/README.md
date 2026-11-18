# Benchmarking

OpenFHE uses the [Google microbenchmark support library](https://github.com/google/benchmark#running-benchmarks) to measure performance. Performance testing code can be found in `/benchmark/src`. After building, binaries are written to `/your_build_folder/bin/benchmark`. To build only tests and their dependencies, use the following command in the build folder:

```
make allbenchmark
```

To run the benchmark `benchmark-to-run_fn` from the build folder for linux or macOS, run:

```
./bin/benchmark/benchmark-to-run_fn
```

For Windows run:

 ```
 bin/benchmark/benchmark-to-run_fn.exe
 ```

By default each benchmark is run once and that single result is reported. However benchmarks are often noisy and a single result may not be representative of the overall behavior. For this reason it's possible to repeatedly rerun the benchmark.

The number of runs of each benchmark is specified globally by the `--benchmark_repetitions` command-line flag or on a per benchmark basis by calling Repetitions on the registered benchmark object. When a benchmark is run more than once, the mean, median and standard deviation of the runs are reported.

Additionally the `--benchmark_report_aggregates_only={true|false}`, `--benchmark_display_aggregates_only={true|false}` flags can be used to change how repeated tests are reported. By default the result of each repeated run is reported. When the report aggregates only option is true, only the aggregates (i.e. mean, median and standard deviation, maybe complexity measurements if they were requested) of the runs are reported, to both reporters - standard output (console), and the file. However, when only the display aggregates only option is true, only the aggregates are displayed in the standard output, while the file output still contains everything.

OMP can also affect the benchmarking time. In order to reduce noise, it is advisable to set the number of threads not higher than the number of physical cores (as hyperthreading introduces a lot of variability).

```
export OMP_NUM_THREADS=number_of_cores
```

In order to remove the noise related to multithreading, set the number of threads to 1

```
export OMP_NUM_THREADS=1
```

## lib-benchmark

[lib-benchmark](library.cpp) is the main Cipher library benchmark that contains performance tests for standard operations in the following schemes: BFVrns, CKKS, BGVrns. It also contains several performance tests for NTT and INTT transformations.

An example output after running `lib-benchmark` is as follows:

```
-------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations
-------------------------------------------------------------------
NTTTransform1024               10.1 us         10.1 us        69178
INTTTransform1024              10.6 us         10.6 us        66271
NTTTransform4096               47.6 us         47.6 us        14695
INTTTransform4096              49.3 us         49.3 us        14199
NTTTransformInPlace1024        9.51 us         9.51 us        73678
INTTTransformInPlace1024       10.4 us         10.4 us        67144
NTTTransformInPlace4096        44.9 us         44.9 us        15595
INTTTransformInPlace4096       48.3 us         48.3 us        14501
bfv_rns_key_gen                  2349 us         2349 us          298
bfv_rns_mult_key_gen              3807 us         3807 us          183
bfv_rns_eval_at_index_key_gen       3909 us         3909 us          179
bfv_rns_encryption              2258 us         2258 us          310
bfv_rns_decryption               539 us          539 us         1300
bfv_rns_add                     33.9 us         33.9 us        20603
bfv_rns_add_in_place              24.0 us         24.0 us        29269
bfv_rns_mult_no_relin             7399 us         7398 us           95
bfv_rns_mult_relin               8593 us         8592 us           82
bfv_rns_eval_at_index             1035 us         1034 us          674
CKKS_KeyGen                    2320 us         2320 us          302
CKKS_MultKeyGen                5931 us         5931 us          117
CKKS_EvalAtIndexKeyGen         5846 us         5845 us          118
CKKS_Encryption                2002 us         2002 us          349
CKKS_Decryption                 922 us          922 us          759
CKKS_Add                       35.2 us         35.2 us        19807
CKKS_AddInPlace                23.8 us         23.8 us        29181
CKKS_MultNoRelin                214 us          214 us         3254
CKKS_MultRelin                 3160 us         3160 us          222
CKKS_Relin                     3021 us         3021 us          232
CKKS_RelinInPlace              2958 us         2958 us          236
CKKS_Rescale                    546 us          546 us         1287
CKKS_RescaleInPlace             534 us          534 us         1308
CKKS_EvalAtIndex               2758 us         2758 us          252
bgv_rns_key_gen                  2329 us         2329 us          300
bgv_rns_mult_key_gen              5926 us         5925 us          118
bgv_rns_eval_at_index_key_gen       5987 us         5987 us          117
bgv_rns_encryption              2252 us         2252 us          311
bgv_rns_decryption               398 us          398 us         1754
bgv_rns_add                     44.6 us         44.6 us        15682
bgv_rns_add_in_place              35.9 us         35.9 us        19671
bgv_rns_mult_no_relin              208 us          208 us         3356
bgv_rns_mult_relin               3205 us         3205 us          218
bgv_rns_relin                   3091 us         3091 us          227
bgv_rns_relin_in_place            3029 us         3029 us          231
bgv_rns_mod_switch                549 us          549 us         1275
bgv_rns_mod_switch_in_place         539 us          539 us         1298
bgv_rns_eval_at_index             2806 us         2805 us          249
```

## poly-benchmark

[poly-1k](poly_benchmark_1k.cpp), [poly-4k](poly_benchmark_4k.cpp), [poly-16k](poly_benchmark_16k.cpp), [poly-64k](poly_benchmark_64k.cpp)
contains performance tests for primitive polynomial operations with ring sizes 1k, 4k, 16k, 64k, respectively.

The following operations are used to evaluate the performance: addition, Hadamard (component-wise) multiplication, NTT and INTT. These operations (especially NTT and iNTT) are the main bottleneck operations for all lattice cryptographic capabilities.

All operations are performed for NativePoly and DCRTPoly with settings for 1, 2, 4 and 8 towers (`tower` is the number of residues in the RNS representation of each large integer).

An example output after running `poly-benchmark-xk` is as follows:

```
-------------------------------------------------------------
Benchmark                   Time             CPU   Iterations
-------------------------------------------------------------
Native_add              0.936 us        0.936 us       748048
DCRT_add/towers:1        1.16 us         1.16 us       602138
DCRT_add/towers:2        2.25 us         2.25 us       311691
DCRT_add/towers:4        4.30 us         4.30 us       162618
DCRT_add/towers:8        8.77 us         8.77 us        79828
Native_mul               2.94 us         2.94 us       237968
DCRT_mul/towers:1        3.16 us         3.16 us       221648
DCRT_mul/towers:2        6.22 us         6.22 us       112086
DCRT_mul/towers:4        12.3 us         12.3 us        57139
DCRT_mul/towers:8        24.7 us         24.7 us        28305
Native_ntt               9.61 us         9.61 us        72903
DCRT_ntt/towers:1        9.80 us         9.80 us        71486
DCRT_ntt/towers:2        19.5 us         19.5 us        35900
DCRT_ntt/towers:4        38.8 us         38.8 us        18029
DCRT_ntt/towers:8        77.8 us         77.8 us         9001
Native_intt              10.5 us         10.5 us        66770
DCRT_intt/towers:1       10.7 us         10.7 us        65778
DCRT_intt/towers:2       21.3 us         21.3 us        32912
DCRT_intt/towers:4       42.3 us         42.3 us        16532
DCRT_intt/towers:8       84.9 us         84.9 us         8242
```

## other

There are several other benchmarking tests:
* [bfv-mult-method-benchmark](bfv_mult_method_benchmark.cpp) - Compares the performance of **BFV** multiplication methods for EvalMultMany
* [binfhe-ap](binfhe_ap.cpp) - boolean functions performance tests for **FHEW** scheme with **AP** bootstrapping technique. Please see "Bootstrapping in FHEW-like Cryptosystems" for details on both bootstrapping techniques
* [binfhe-ginx](binfhe_ginx.cpp) - boolean functions performance tests for **FHEW** scheme with **GINX** bootstrapping technique. Please see "Bootstrapping in FHEW-like Cryptosystems" for details on both bootstrapping techniques
* [compare-bfv-hps-leveled-vs-behz](compare_bfv_hps_leveled_vs_behz.cpp) - performance comparison between **HPSPOVERQLEVELED** and **BEHZ** **BFV** variants for similar parameter sets
* [compare-bfvrns-vs-bgvrns](compare_bfvrns_vs_bgvrns.cpp) - performance comparison between **BFVrns** and **BGVrns** schemes for similar parameter sets
* [IntegerMath](integer_math.cpp) - performance tests for the big integer operations
* [Lattice](ring.cpp) - performance tests for the Lattice operations.
* [NbTheory](number_theory.cpp) - performance tests of number theory functions
* [Serialization](serialize_ckks.cpp) - performance tests of **CKKS** serialization
* [VectorMath](vector_math.cpp) - performance tests for the big vector operations
