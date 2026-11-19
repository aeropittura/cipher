# Contributing to Cipher

Cipher is developed on GitHub at <https://github.com/aeropittura/cipher>. Bugs, questions and proposals go to the issue
tracker there; code changes arrive as pull requests against the `main` branch. For a large change (a new scheme, a
change of the public API, a restructuring of the build) please open an issue first so the approach can be agreed on
before work starts.

## Prerequisites

Install Python 3 and `pre-commit` (`pip3 install pre-commit`, or `brew install pre-commit` on macOS). That is the only
tool you need: `clang-format` and `cpplint` are pinned in [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) and
downloaded by `pre-commit` on first use, so every contributor formats with the same versions. If your editor formats on
save, `pip3 install clang-format==23.1.1` gives it the same binary the hook uses.

Enable the hooks once per clone:

```bash
pre-commit install
```

They then run on every `git commit`. To check or fix the whole tree, run `pre-commit run --all-files` or
[`tools/format.sh`](../../tools/format.sh).

## Workflow

1. Fork <https://github.com/aeropittura/cipher> and clone your fork:
   ```bash
   git clone https://github.com/<you>/cipher.git && cd cipher
   git remote add upstream https://github.com/aeropittura/cipher.git
   git submodule update --init extern/cereal extern/google-test extern/google-benchmark
   ```
2. Create a feature branch from an up-to-date `main`:
   ```bash
   git fetch upstream
   git checkout -b my-feature upstream/main
   ```
3. Make your changes following the style guidelines below. Add unit tests under `tests/` for new functionality and,
   where it helps, an example under `examples/`.
4. Build and run the tests:
   ```bash
   cmake -S . -B build -G Ninja
   cmake --build build
   ctest --test-dir build --output-on-failure
   ```
5. Commit with a descriptive message (a summary line of at most 72 characters, a blank line, then details). If the
   hooks modify files, review them with `git diff`, `git add` them and commit again.
6. If `main` has moved on, rebase onto it (`git rebase upstream/main`) rather than merging, then push to your fork.
   See [rebasing_off_main.rst](../sphinx_rsts/contributing/rebasing_off_main.rst).
7. Open a pull request against `main` of <https://github.com/aeropittura/cipher> and reference the issue it addresses
   (`Fixes #123`). The [CI workflows](../../.github/workflows/ci.yml) (build and test matrix) and
   [lint](../../.github/workflows/lint.yml) (pre-commit hooks) run automatically; resolve any failures they report.

Changes to the build system are described in
[cmake_in_cipher.rst](../sphinx_rsts/intro/installation/cmake_in_cipher.rst).

## Style Guidelines

* Follow the style of the surrounding code. Formatting is enforced by `clang-format` (4-space indentation, no tabs,
  120-character lines, see [`.clang-format`](../../.clang-format)).
* Types use `PascalCase` (`RnsPoly`, `BooleanContext`); functions, methods and variables use `snake_case`
  (`eval_mult`, `get_ring_dimension`); data members end with an underscore (`params_`). Where the case of a single
  letter carries mathematical meaning it is kept (`get_N()` vs `get_n()`).
* Constants, enumerators and macros use `UPPER_CASE_WITH_UNDERSCORES`; macros and build options carry the `CIPHER_`
  prefix. Everything lives in the `cipher` namespace, whose contents are not indented.
* Header files have an include guard named after the path below `include/`: `include/cipher/fhe/context.h` uses
  `CIPHER_FHE_CONTEXT_H_`, closed by `#endif  // CIPHER_FHE_CONTEXT_H_`.
* Includes are grouped in this order, separated by blank lines: the header this file implements, C system headers,
  C++ system headers, then everything else. A file includes the headers it uses.
* Document classes, methods and members with Doxygen comments, including input requirements and the conditions that
  throw.
* Report errors with `CIPHER_THROW` (`cipher::CipherException`, see `include/cipher/util/exception.h`). Library code
  writes diagnostics through `cipher/util/diagnostic_output.h`, never directly to `std::cout`/`std::cerr`.
* Code may use C++17. Avoid manual memory management; prefer standard containers and smart pointers.
* Avoid defining non-trivial functions in header files, and do not add external dependencies to the public interface.

## License

Cipher is licensed under the BSD 2-Clause license ([LICENSE](../../LICENSE)). By submitting a pull request you agree
that your contribution is released under the same license. Keep existing copyright notices in the files you modify.

## Upstream

Cipher is derived from [OpenFHE](https://github.com/openfheorg/openfhe-development); the governance and contribution
processes of the upstream project are documented by the OpenFHE project itself. This document was originally modeled
on the contribution guide of the Cantera project.
