# Notice

Cipher is a derivative work of **OpenFHE** (<https://github.com/openfheorg/openfhe-development>),
version 1.6.1, by NJIT, Duality Technologies Inc. and other contributors, distributed under the
BSD 2-Clause License.

The cryptographic algorithms and their implementations come from OpenFHE. Cipher reorganizes the
source tree, rewrites the build system, and renames the public and internal API (see the naming
conventions in [README.md](README.md)). The OpenFHE copyright notice and license text are kept in
[LICENSE](LICENSE) and in the header of every source file, as the license requires.

Bundled third-party components (under `extern/`) keep their own licenses:

- cereal (BSD 3-Clause)
- GoogleTest (BSD 3-Clause)
- Google Benchmark (Apache 2.0)
- gperftools (BSD 3-Clause)
- BLAKE2 reference code in `source/util/prng/` (CC0 / Apache 2.0 / OpenSSL, at your choice)

Cipher is not affiliated with or endorsed by the OpenFHE project.
