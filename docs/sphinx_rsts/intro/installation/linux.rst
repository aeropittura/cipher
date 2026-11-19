Installing Cipher on Linux
====================================

.. note:: CentOS Installation

    The installation process is the same as in Ubuntu except for using ``yum`` instead of ``apt-get`` in Step 1. Here we provide additional notes specific to CentOS.

    You may need to install cmake v3.x using the following commands:

    ::

        sudo yum install cmake3
        ln -s /usr/bin/cmake3 ~/bin/cmake

    If you need to install a specific version of gcc, do the following (this example is for g++ v10):
    ``sudo yum install devtoolset-10-gcc-c++``

1. Install pre-requisites (if not already installed) and set the default compiler.

.. topic:: g++

    Note that ``sudo apt-get install g++-<version>`` can be used to install a specific version of the compiler. You can use "g++ --version" to check the version of g++ that is found by the system.


    Install ``g++``, ``cmake`` and ``make``. Sample commands using apt-get are listed below. It is possible that these are already installed

    ::

        sudo apt-get install build-essential #this already includes g++
        sudo apt-get install cmake

.. topic:: clang

    Typically g++ is the default compiler for Linux but clang++ can also be installed.

    First install clang++, e.g., ``sudo apt-get install clang-11`` to install clang 11.

    If installing an older version of clang, you may also need to install OpenMP. The commands for this case are

    ::

        sudo apt-get install clang
        sudo apt-get install libomp5
        sudo apt-get install libomp-dev


    Then run the following two commands to configure clang/clang++ as the default compiler for C and C++ (default paths are used here). For clang 11:

    ::

        export CC=/usr/bin/clang-11
        export CXX=/usr/bin/clang++-11


    For a default version of clang, e.g., v6 in Ubuntu 20.04:

    ::

        export CC=/usr/bin/clang
        export CXX=/usr/bin/clang++


2. Clone the repository and fetch the submodules:

    ::

        git submodule update --init extern/cereal extern/google-test extern/google-benchmark

3. Configure a build directory. The typical choice is a subfolder ``build``:

    ::

        cmake -S . -B build


.. note:: Note that cmake will check for any system dependencies that are needed for the build process.


4. Optional dependencies: NTL/GMP (math backend 6) must be installed by the user (see :ref:`gmp_ntl_install`);
   tcmalloc is built from the bundled ``extern/gperftools`` submodule. Both need ``autoconf``:

    ::

        sudo apt-get install autoconf

   Then enable them when you run cmake (``-DCIPHER_WITH_NTL=ON``, ``-DCIPHER_WITH_TCM=ON``; see :ref:`cmake_in_cipher`).
   ``tools/setup/linux_packages.sh`` installs the common prerequisites on Debian/Ubuntu.

5. Build Cipher by running the following command (this will take a few minutes; using the ``-j <threads>`` flag is suggested to speed up the build)

    ::

        cmake --build build -j <threads>

6. Install Cipher in a system directory (if desired or for production purposes)

    ::

        cmake --install build

You would probably need to run ``sudo cmake --install build`` unless you are specifying some other install location. You can change the install location by running
``cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/your/path``

Testing and cleaning the build
------------------------------

Run unit tests to make sure all capabilities operate as expected

    ::

        ctest --test-dir build

Run sample code to test, e.g.,

    ::

        build/bin/examples/fhe/simple_integers

To remove the files built by the build tool, you can execute

    ::

        cmake --build build --target clean

To change the compiler, e.g., from g++ to clang++, or completely remove any CMake build files, delete the ``build`` folder and configure again.
