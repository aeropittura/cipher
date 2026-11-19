Installation
====================================

Welcome to the Cipher installation instructions! For OS-specific instructions, follow one of the following links below, or proceed with the high-level platform-independent installation instructions below.


.. note:: By default, the library is built without external dependencies other than the bundled git submodules in
   ``extern/`` (cereal, google-test, google-benchmark). Optional dependencies can be enabled:

   - ``GMP/NTL`` (``-DCIPHER_WITH_NTL=ON``, installed by the user; see :ref:`gmp_ntl_install`)
   - ``tcmalloc`` (``-DCIPHER_WITH_TCM=ON``, built from the bundled ``extern/gperftools`` submodule)

.. toctree::
   :maxdepth: 1
   :caption: Contents:

   linux.rst
   macos.rst
   windows.rst
   cmake_in_cipher.rst
   gmp_ntl.rst
   ../building_user_applications.rst


Build Instructions
##################
We use CMake to build Cipher. Cipher requires CMake 3.16 or later and supports any GNU C++ compiler version 9 or above
and clang C++ compiler version 10 or above. OpenMP is optional (``libomp`` on macOS).


1. Install system prerequisites (if not already installed), including a C++ compiler with OpenMP support, CMake, and
   a build tool (``make`` or ``ninja``).

2. Clone the Cipher repository to your local machine and fetch the submodules it needs: ::

    git submodule update --init extern/cereal extern/google-test extern/google-benchmark

   (By default, ``CIPHER_GIT_SUBMODULES=ON`` makes CMake initialize and update all submodules at configure time.)

3. Configure a build directory. The typical choice is a subfolder ``build``: ::

    cmake -S . -B build                         # add -DCIPHER_WITH_OPENMP=OFF if OpenMP is unavailable

.. note:: ``CMake`` will check for any system dependencies that are needed for the build process

   - If the ``CMake`` configuration does not complete successfully, please review the error ``CMake`` shows at the end.
   - If the error does not go away (even though you installed the dependency), delete the ``build`` directory (or
     ``build/CMakeCache.txt``) and configure again.

4. If you want to use any external libraries, such as NTL/GMP or tcmalloc, install them and enable the corresponding
   option (see :ref:`cmake_in_cipher`).

5. Build Cipher (this will take a few minutes; ``-j <threads>`` speeds up the build) ::

    cmake --build build -j 8

- If you want to build only the library files or some other subset of Cipher, please review :ref:`cmake_in_cipher`.

- After the build completes, the Cipher library files are in ``build/lib``, the examples in ``build/bin/examples``, the
  benchmarks in ``build/bin/bench``, and the unit-test executables in ``build/tests``.

6. Install Cipher to a system directory (if desired or for production purposes) ::

    cmake --install build

You would probably need to run ``sudo cmake --install build`` unless you are specifying some other install location.
You can change the install location with ``-DCMAKE_INSTALL_PREFIX=/your/path`` when configuring, or with
``cmake --install build --prefix /your/path``.

- The header files are placed in the ``include/cipher`` folder of the specified path, and the binaries of the library
  in the ``lib`` folder. For example, if no installation path is provided in Ubuntu (and many other Unix-based OSes), the header and library
  binary files will be placed in ``/usr/local/include/cipher`` and ``/usr/local/lib``, respectively.
  Those two folders can be changed with ``CMAKE_INSTALL_INCLUDEDIR`` and ``CMAKE_INSTALL_LIBDIR``, which is what distribution
  packagers use to install into ``lib64`` or an architecture-specific directory. On Windows the DLLs go to the ``bin`` folder
  (``CMAKE_INSTALL_BINDIR``) and only the import libraries are placed in the library folder.

Testing and cleaning the build
##############################

Run the unit tests to make sure all capabilities operate as expected ::

    ctest --test-dir build                      # or: cmake --build build --target check

Each module has one GoogleTest executable, ``build/tests/core_tests``, ``build/tests/fhe_tests`` and
``build/tests/boolean_tests``, which can also be run directly.

Run sample code to test, e.g., ::

    build/bin/examples/fhe/simple_integers

To remove the files built by the build tool, you can execute ::

    cmake --build build --target clean

Supported Operating Systems
###########################
Cipher's continuous integration (``.github/workflows/ci.yml``) builds and tests on:

* Ubuntu 24.04 with g++ and clang++ (default configuration, math backend 2, 128-bit native integers, static Debug build)
* macOS 15 with Apple clang (without OpenMP)

Upstream OpenFHE, from which Cipher derives, additionally reported successful operation on other Linux distributions,
FreeBSD and MinGW (64-bit) on Windows; these platforms are not tested by Cipher's CI.
