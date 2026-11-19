Directory Structure
====================================

The high-level structure of the Cipher repository is as follows.

Several of these directories contain a README file with more specific information about the files in the directory.

::

    .
    ├── bench
    ├── cmake
    ├── data
    ├── docker
    ├── docs
    ├── examples
    │   ├── boolean
    │   ├── core
    │   ├── extras
    │   ├── fhe
    │   └── standalone
    ├── extern
    ├── include/cipher
    │   ├── boolean
    │   ├── fhe
    │   ├── math
    │   ├── ring
    │   └── util
    ├── source
    ├── tests
    │   ├── boolean
    │   ├── core
    │   └── fhe
    └── tools

The descriptions of library components are as follows:

.. csv-table:: components
   :header: "Directory", "Description"

   "bench","Benchmarks of Cipher components, built on Google Benchmark"
   "cmake","Build-system modules and the CMake package configuration"
   "data","Data files used by the tests and examples"
   "docker","Dockerfile and documentation"
   "docs","Documentation sources (Sphinx) and static documents"
   "examples","Example programs for the core, fhe and boolean modules; extras/ holds experimental programs and standalone/ a template for projects that use an installed Cipher"
   "extern","Third-party git submodules: cereal, google-test, google-benchmark and gperftools (tcmalloc)"
   "include/cipher","Public headers: math/ (big integers, NTT, sampling), ring/ (polynomial rings, RNS), util/ (serialization, PRNG, exceptions), fhe/ (BFV, BGV, CKKS and their shared base, encoding, key, keyswitch and schemelet code), boolean/ (FHEW/TFHE)"
   "source","Library implementation, mirroring include/cipher/"
   "tests","GoogleTest suites, one executable per module (core, fhe, boolean)"
   "tools","Maintenance scripts (formatting, diagnostic-output check)"
   "build","Build directory (created by the user; not part of the repository)"
