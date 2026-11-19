Installing Cipher on MacOS
====================================
These instructions are exercised by Cipher's CI on macOS 15 and should also work for other recent releases. It is assumed that the clang compiler that comes with Xcode is used for building Cipher.

1. Install the Mac terminal command line functions if needed (type ``git`` at the command line to trigger the install). Then install home-brew if not already present:

::

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"

2. Install pre-requisites ``cmake`` and ``OpenMP`` library using Homebrew:

::

    brew install cmake
    brew install libomp

3. Clone the repository and fetch the submodules:

::

    git submodule update --init extern/cereal extern/google-test extern/google-benchmark

4. Configure a build directory. The typical choice is a subfolder ``build``. CMake will check for any system
   dependencies that are needed for the build process.

::

    cmake -S . -B build

If CMake cannot find OpenMP (for example, because ``libomp`` is not installed), configure with
``-DCIPHER_WITH_OPENMP=OFF``. If ``libomp`` comes from MacPorts rather than Homebrew, add ``-DCIPHER_USE_MACPORTS=ON``.

.. note:: If you get an error about a missing regular expression backend, run the following commands

    ::

        cmake -S . -B build -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0
        cmake -S . -B build

5. Optional dependencies: NTL/GMP (math backend 6) must be installed by the user (see :ref:`gmp_ntl_install`);
   tcmalloc is built from the bundled ``extern/gperftools`` submodule. Both need ``autoconf``:

    ::

        brew install autoconf

   Then enable them when you run cmake (``-DCIPHER_WITH_NTL=ON``, ``-DCIPHER_WITH_TCM=ON``; see :ref:`cmake_in_cipher`).

6. Build Cipher by running the following command (this will take a few minutes; using the ``-j #`` flag is suggested to speed up the build, where # is the number of cores on your machine).

::

    cmake --build build -j #

7. Install Cipher in a system directory (if desired or for production purposes)

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
