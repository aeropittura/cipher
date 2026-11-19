.. _cmake_in_cipher:

CMake in Cipher
=================

Cipher uses CMake to build and install the Cipher library. This page describes how CMake is used in Cipher, and how contributors should use CMake when adding new files or new components.

Using Cipher's CMake system
-----------------------------

The first step in using CMake is deciding where the build should be performed. This is the "build tree". The "source tree" is where the Cipher source is located. These should be different directories! The build tree can be in a subdirectory of the source directory (such as ``build``) or in some other place.

The project is described in files named ``CMakeLists.txt``; the shared build logic lives in the ``cmake/`` directory
(``CipherOptions.cmake`` lists every option).

Therefore the basic steps are:

.. code-block:: bash

    cmake -S <source-tree> -B <build-tree> {other CMake arguments}
    cmake --build <build-tree>
    ctest --test-dir <build-tree>

Any generator works; Ninja (``-G Ninja``) is used by the CI. CMake does not usually have to be rerun by hand: the build
reruns it if it detects changes to any of the project's CMake files, and source files are collected with
``CONFIGURE_DEPENDS`` globs, so new files are picked up automatically.

Required Compilers
^^^^^^^^^^^^^^^^^^^^^

Cipher requires CMake 3.16 or later and supports any GNU C++ compiler version 9 or above and clang C++ compiler version 10 or above.

A warning is issued if an older version of the compiler is found. The build may run but such compilers are unsupported.

Required Packages
^^^^^^^^^^^^^^^^^^^^^
Cipher requires that certain packages and applications be available on the system. CMake searches for these packages and may either stop if a required package is missing, or disable functionality.

These packages are as follows:

* OpenMP (optional; configure with ``-DCIPHER_WITH_OPENMP=OFF`` if it is unavailable)
* Autoconf tools (only for tcmalloc and NTL/GMP)
* Git (to fetch the submodules in ``extern/``)

Command Line Options
^^^^^^^^^^^^^^^^^^^^^
There are a large number of CMake command line options. Most important for our purposes here is the -D option,
which allows variables to be set, cached, and used in configuring and building Cipher.

Combining multiple CMake flags
**********************************

Different flags can be combined together. For example, to configure cmake with NTL, tcmalloc, math backend 6, and build in debug mode, the following command can be used:

::

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCIPHER_WITH_NTL=ON -DCIPHER_WITH_TCM=ON -DCIPHER_MATH_BACKEND=6

Important CMake Flags Used
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
We point out a number of the standard CMake variables that can be set using -D from the CMake command line, which may be of use to Cipher users. To set one of these variables, use -D*VARIABLE_NAME*=*VALUE* on the command line.

 ========================= ============================ =============================================================================================================================================================================================================================================================================================================================================================================================================================================
  *VARIABLE_NAME*           Definition                   Notes
 ========================= ============================ =============================================================================================================================================================================================================================================================================================================================================================================================================================================
  CMAKE_INSTALL_PREFIX      Base directory for installs  Base directory for installation of Cipher. What goes where underneath it is decided by CMAKE_INSTALL_INCLUDEDIR, CMAKE_INSTALL_LIBDIR and CMAKE_INSTALL_BINDIR below. Cipher is also exported as a CMake package so that applications can locate it with find_package(Cipher CONFIG); those package files are installed next to the libraries (in <libdir>/Cipher; CMake/ on Windows)
  CMAKE_INSTALL_INCLUDEDIR  Header directory name        Directory for header files, taken relative to CMAKE_INSTALL_PREFIX unless given as an absolute path. Defaults to include. Cipher places its own headers in a cipher subdirectory of it (with the bundled cereal headers under cipher/extern), so by default they end up in ${CMAKE_INSTALL_PREFIX}/include/cipher
  CMAKE_INSTALL_LIBDIR      Library directory name       Directory for the libraries and the exported CMake package files, taken relative to CMAKE_INSTALL_PREFIX unless given as an absolute path. Defaults to lib; distribution packagers can set it to lib64 or lib/<arch-triplet>. Cipher seeds this default before including GNUInstallDirs, so the lib64 or multiarch value GNUInstallDirs would otherwise derive is used only when asked for
  CMAKE_INSTALL_BINDIR      Runtime directory name       Directory for runtime binaries, taken relative to CMAKE_INSTALL_PREFIX unless given as an absolute path. Defaults to bin. This is where the DLLs are installed on Windows, with the import libraries going to CMAKE_INSTALL_LIBDIR; on Unix-like systems Cipher installs nothing here. Applications can read the location as Cipher_BINDIR from CipherConfig.cmake
  CMAKE_BUILD_TYPE          Debug, Release, ...          Default is to build Cipher for release, with no debug information; developers may want to specify -DCMAKE_BUILD_TYPE=Debug. RelWithDebInfo and MinSizeRel are also accepted
 ========================= ============================ =============================================================================================================================================================================================================================================================================================================================================================================================================================================


Flags for Cipher Builds
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The Cipher build has a number of options to control
what is built and what features are included/excluded. They are all defined in ``cmake/CipherOptions.cmake`` and
carry the ``CIPHER_`` prefix, so they cannot clash with options of a parent project that adds Cipher with
``add_subdirectory()``.

Each of the options is enabled by saying ``-DOPTION_NAME=ON`` and is disabled by saying ``-DOPTION_NAME=OFF``

The table below shows the current list of options, definition for the option, and a default value.

 ===================================== ===================================================================================================================================================================== =======
  OPTION_NAME                           Description                                                                                                                                                           Default
 ===================================== ===================================================================================================================================================================== =======
  CIPHER_BUILD_SHARED                   Build the shared libraries                                                                                                                                            ON
  CIPHER_BUILD_STATIC                   Build the static libraries                                                                                                                                            OFF
  CIPHER_BUILD_TESTS                    Build the unit tests                                                                                                                                                  ON
  CIPHER_BUILD_EXAMPLES                 Build the example programs                                                                                                                                            ON
  CIPHER_BUILD_BENCHMARKS               Build the benchmarks                                                                                                                                                  ON
  CIPHER_BUILD_EXTRAS                   Build the extra (experimental) programs in examples/extras                                                                                                            OFF
  CIPHER_GIT_SUBMODULES                 Initialize/update the git submodules in extern/ at configure time                                                                                                     ON
  CIPHER_WITH_BE2                       Also compile math backend 2 (fixed-width big integers); always on when it is the default backend                                                                     OFF
  CIPHER_WITH_BE4                       Also compile math backend 4 (dynamic big integers); always on when it is the default backend                                                                         OFF
  CIPHER_WITH_NTL                       Compile math backend 6 (NTL); requires NTL and GMP                                                                                                                    OFF
  CIPHER_WITH_TCM                       Link tcmalloc from the bundled extern/gperftools                                                                                                                      OFF
  CIPHER_WITH_MALLOC_TUNING             Tune glibc malloc to retain freed memory for reuse (higher performance, higher resident memory)                                                                       ON
  CIPHER_WITH_OPENMP                    Parallelize with OpenMP                                                                                                                                               ON
  CIPHER_WITH_NATIVEOPT                 Use machine-specific optimizations (-march/-mcpu=native; major speedup for clang)                                                                                     OFF
  CIPHER_WITH_NUMA_INTERLEAVE           Interleave memory across NUMA nodes at library load (multi-socket Linux only; no effect elsewhere)                                                                    ON
  CIPHER_WITH_DEFAULT_DIAGNOSTIC_SINK   Build the built-in diagnostic sink into the library; OFF leaves it free of std::cerr/std::cout and the application supplies the sink (static builds)                  ON
  CIPHER_WITH_COVERAGE                  Instrument for coverage reports (g++ only; adds the ``coverage`` target)                                                                                              OFF
  CIPHER_WITH_NOISE_DEBUG               Lattice-estimator mode; never use in production                                                                                                                       OFF
  CIPHER_WITH_REDUCED_NOISE             Reduced noise in HKS and BFV HPSPOVERQ modes                                                                                                                          OFF
  CIPHER_USE_MACPORTS                   Look for libomp in MacPorts instead of Homebrew                                                                                                                       OFF
  CIPHER_NATIVE_SIZE                    Word size for native integer arithmetic: 32, 64 or 128 bits                                                                                                           64
  CIPHER_MATH_BACKEND                   Default big-integer backend: 2 (fixed), 4 (dynamic) or 6 (NTL)                                                                                                        4
  CIPHER_CKKS_M_FACTOR                  Parameter used to strengthen the CKKS adversarial model in scenarios where decryption results are shared among multiple parties (see Security.md for more details)   1
  CIPHER_PARTIAL_SUM_RADIX              Radix of the rotation-fold accumulations (bootstrap partial sums, eval_sum); higher powers of two reduce runtime but need more evaluation keys                         4
 ===================================== ===================================================================================================================================================================== =======

The default math backend for the Cipher build is Backend 4 (dynamically-sized big integers). This default can be changed on the CMake command line by setting the ``CIPHER_MATH_BACKEND`` variable. For example, to select backend 6 (high performance integers based on the GMP and NTL libraries), use ``-DCIPHER_MATH_BACKEND=6`` on the CMake command line; this turns ``CIPHER_WITH_NTL`` on. Backend 6 is not available with ``CIPHER_NATIVE_SIZE=128``.

Detecting Local Environments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Cipher detects most of the capabilities of the target machine. It uses the machine's capabilities and the values of the user options to generate a configuration header, ``<build>/include/cipher/config.h`` (from ``cmake/config.h.in``), that controls the build. It is included in the Cipher install as ``cipher/config.h``.

Third-Party Components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Cipher uses some third-party components from Google for testing and benchmarking, and it uses a third-party serialization library called cereal. These libraries are git submodules under ``extern/`` (``extern/cereal``, ``extern/google-test``, ``extern/google-benchmark``; ``extern/gperftools`` provides tcmalloc) and are fully integrated into the build.

Turn on NTL/GMP (Only for Advanced Users)
*********************************************

By default Cipher builds without external dependencies. If you wish to use the ``NTL/GMP`` implementation of ``BigInteger/BigVector``, you can :ref:`install GMP and NTL manually <gmp_ntl_install>` and run cmake with ``-DCIPHER_WITH_NTL=ON``. The complete command is

::

    cmake -S . -B build -DCIPHER_WITH_NTL=ON

If NTL or GMP is installed in a non-default location, add ``-DNTL_INCLUDE_DIR=<dir> -DNTL_LIBRARIES=<file or dir>`` and
``-DGMP_INCLUDE_DIR=<dir> -DGMP_LIBRARIES=<file or dir>``.

Upstream OpenFHE was tested with ``GMP 6.1.2`` and ``6.2.1``, and ``NTL 10.5.0`` and ``11.4.4``.

.. note:: A regular binary install (using tools like ``apt-get``) will not work
   Special compilation flags need to be passed. See :ref:`Instructions for installing GMP and NTL <gmp_ntl_install>`



.. note:: The performance w/o and w `NTL` is almost the same for all schemes/operations

   - `NTL` is used only for multiprecision integer arithmetic. The latter only when ``CIPHER_MATH_BACKEND`` is set to ``6``.
   - Most crypto operations are executed using native arithmetic (employing RNS procedures) and do not use higher-precision capabilities.

Turn on tcmalloc
*********************************************

If you wish to use tcmalloc, you can add ``-DCIPHER_WITH_TCM=ON`` to the cmake command. The complete command is

::

    cmake -S . -B build -DCIPHER_WITH_TCM=ON

tcmalloc can improve performance in the multi-threaded mode (when OMP_NUM_THREADS>1). It provides efficient thread-caching block allocation for all Cipher objects.

.. note:: ``tcmalloc`` only works in Linux and macOS, and is not currently supported in ``MinGW``.

tcmalloc is built from the ``extern/gperftools`` submodule after running cmake and before building Cipher. To build tcmalloc, run

::

    cmake --build build --target tcm

To remove tcmalloc, run

::

    cmake --build build --target tcm_clean

Location of Build Products
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- All Cipher build products are created inside the build tree.

- The libraries (``cipher_core``, ``cipher_boolean``, ``cipher_fhe`` and their ``_static`` variants) are placed in ``lib``; on Windows the DLLs are placed there too.

- tcmalloc, when built, is placed in ``extern/lib``.

- Unit tests are placed in ``tests``: one GoogleTest executable per module, ``core_tests``, ``fhe_tests`` and ``boolean_tests``.

- Benchmarks are placed in ``bin/bench``.

- Examples (of basic Cipher features) are placed in ``bin/examples/{core,fhe,boolean}``, and the extra programs (more complicated and research-oriented examples, built with ``CIPHER_BUILD_EXTRAS=ON``) are placed in ``bin/extras/{core,fhe}``.

- The Sphinx documentation is built separately, from the ``docs`` directory of the source tree (see ``docs/README.md``).

Installing Cipher on your system for use by applications external to the Cipher source tree
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Running ``cmake --install build`` will install all libraries, header files and the CMake package files in the directories designated by ``CMAKE_INSTALL_PREFIX``. Unit tests, benchmarks, examples and extras are not installed. The ``uninstall`` target removes the files listed in ``install_manifest.txt``.

Building applications with an installed Cipher library
************************************************************
A user can create a CMake environment for their own Cipher application development.
Simply copy the file ``examples/standalone/CMakeLists.txt`` from the Cipher source tree to
``CMakeLists.txt`` in your source tree, and add your CMake directives for your own programs to
the end of the file.

This file imports the Cipher package that was built and installed by the Cipher build
(``find_package(Cipher CONFIG REQUIRED)``) and links against the imported targets ``Cipher::fhe``, ``Cipher::boolean``
or ``Cipher::core`` (``Cipher::fhe_static`` etc. for static builds). See :doc:`../building_user_applications` for details.

Cross Compiling with CMake [experimental feature]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Cross compiling Cipher for other target environments is an experimental feature. Cross-compilation for new targets should require the following steps:

1. Obtain and configure  a cross-compiler for your target environment (or use the appropriate command line arguments to your compiler to initiate cross compilation).
2. Specify that CMake should use the cross-compiler.
3. Proceed with the CMake configure and build process.

.. note:: libgmp and NTL will probably need to be built manually for cross compilation using their internal build sequence, and they may not be supported on the target platform at all.
   Configuring Cipher with -DCIPHER_WITH_NTL=OFF (the default) avoids this issue.

Documentation for extending Cipher CMake Files
----------------------------------------------------------

CMake Files for Cipher Components
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The top-level ``CMakeLists.txt`` includes the modules in ``cmake/`` (options, platform detection, compiler flags,
dependencies, install directories, packaging) and then adds the following directories:

1. ``source/CMakeLists.txt`` collects the sources of the three library modules (``core``: ``source/math``,
   ``source/ring``, ``source/util``; ``boolean``: ``source/boolean``; ``fhe``: ``source/fhe``) and builds each with
   ``cipher_add_module()`` from ``cmake/CipherHelpers.cmake``, which creates an object library, the shared and/or
   static library and the ``Cipher::<module>`` alias.
2. ``tests/CMakeLists.txt`` builds one GoogleTest executable per module and registers it with CTest.
3. ``examples/CMakeLists.txt`` and ``bench/CMakeLists.txt`` build one executable per source file with
   ``cipher_add_programs()``.

Adding a new file to Cipher
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
A new file can simply be added to the directory tree, and CMake will add it to the build.

Adding a new component to Cipher
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
When adding a new component to Cipher

1. Add its headers under ``include/cipher/<component>`` and its sources under ``source/<component>``.
2. Add a ``cipher_add_module()`` call for it in ``source/CMakeLists.txt`` (or add its sources to an existing module).
3. Add its tests, examples and the corresponding ``all_*`` targets in ``tests/`` and ``examples/``.

Documentation of build targets created by Cipher CMake system
--------------------------------------------------------------

When ``cmake --build build`` is run without any target specified, it builds:

- all modules,
- unit tests (if ``CIPHER_BUILD_TESTS=ON``),
- examples (if ``CIPHER_BUILD_EXAMPLES=ON``),
- benchmarks (if ``CIPHER_BUILD_BENCHMARKS=ON``),
- and extras (if ``CIPHER_BUILD_EXTRAS=ON``).

.. note:: Cipher also provides more granular control over which components of Cipher are built.

We discuss these options below. Each target is built with ``cmake --build build --target <target>``.

.. note:: for many users, it may be easier to rely on the CMake flags ``CIPHER_BUILD_TESTS``, ``CIPHER_BUILD_EXAMPLES``, and the like,
          to control what is built without specifying a target.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Target
     - What it builds
   * - ``all_libraries``
     - only the library files
   * - ``cipher_core``, ``cipher_boolean``, ``cipher_fhe``
     - a specific module and its dependencies (append ``_static`` for the static variant)
   * - ``all_examples``
     - the library files and all examples (if ``CIPHER_BUILD_EXAMPLES=ON``)
   * - ``core_examples``, ``fhe_examples``, ``boolean_examples``
     - the examples of one module
   * - ``all_extras``, ``core_extras``, ``fhe_extras``
     - the extra programs (if ``CIPHER_BUILD_EXTRAS=ON``)
   * - ``all_tests``
     - all unit-test executables (if ``CIPHER_BUILD_TESTS=ON``)
   * - ``core_tests``, ``fhe_tests``, ``boolean_tests``
     - the unit-test executable of one module
   * - ``test_core``, ``test_fhe``, ``test_boolean``
     - build and run the unit tests of one module
   * - ``check``
     - build and run all unit tests
   * - ``all_benchmarks``
     - all benchmarks (if ``CIPHER_BUILD_BENCHMARKS=ON``)
   * - ``tcm``, ``tcm_clean``
     - build or remove tcmalloc from ``extern/gperftools``
   * - ``coverage``
     - coverage report (if ``CIPHER_WITH_COVERAGE=ON``)
   * - ``uninstall``
     - remove the installed files

The unit tests can also be run through CTest, which runs each module's suite as one test::

    ctest --test-dir build --output-on-failure
