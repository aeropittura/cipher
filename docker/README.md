# Docker

[Dockerfile](Dockerfile) builds Cipher from this source tree on Ubuntu 24.04, runs the unit tests
and installs the libraries under `/usr/local`. Build it from the repository root:

```sh
git submodule update --init extern/cereal extern/google-test extern/google-benchmark
docker build -f docker/Dockerfile -t cipher .
docker run --rm -it cipher
```

Inside the container the build tree is the working directory, so the programs are at hand:

```sh
./bin/examples/fhe/simple_integers
./tests/fhe_tests --gtest_brief=1
```

Build arguments:

| Argument | Default | Meaning |
|---|---|---|
| `JOBS` | `4` | Parallel build jobs |
| `CMAKE_ARGS` | empty | Extra CMake options, e.g. `--build-arg CMAKE_ARGS="-DCIPHER_MATH_BACKEND=2"` |
| `RUN_TESTS` | `1` | Set to `0` to skip the unit tests during the image build |

To use the installed library from your own code, mount it into the container and build it against
the installed package (see [examples/standalone](../examples/standalone/CMakeLists.txt)):

```sh
docker run --rm -it -v "$PWD/my_app:/my_app" cipher \
    bash -c "cmake -S /my_app -B /tmp/b && cmake --build /tmp/b"
```
