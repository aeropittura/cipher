# Builds, tests and installs Cipher from the checked-out source tree.
#
#   docker build -f docker/Dockerfile -t cipher .
#   docker run --rm -it cipher
#
# Build arguments:
#   JOBS          parallel build jobs (default 4)
#   CMAKE_ARGS    extra CMake options, e.g. "-DCIPHER_MATH_BACKEND=2"
#   RUN_TESTS     set to 0 to skip the unit tests during the image build

FROM ubuntu:24.04

ARG JOBS=4
ARG CMAKE_ARGS=""
ARG RUN_TESTS=1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake ninja-build git libomp-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src/cipher
COPY . .
RUN git submodule update --init --depth 1 extern/cereal extern/google-test extern/google-benchmark 2>/dev/null \
    || test -f extern/cereal/include/cereal/cereal.hpp

RUN cmake -S . -B build -G Ninja -DCIPHER_GIT_SUBMODULES=OFF ${CMAKE_ARGS} \
 && cmake --build build -j ${JOBS} \
 && if [ "${RUN_TESTS}" = 1 ]; then ctest --test-dir build --output-on-failure; fi \
 && cmake --install build \
 && ldconfig

WORKDIR /src/cipher/build
CMD ["/bin/bash"]
