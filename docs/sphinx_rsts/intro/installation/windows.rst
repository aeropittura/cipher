Installing Cipher on Windows
====================================
The preferred way of building Cipher in Windows is using MinGW64. VC++ is no longer supported.

Download and install `MSYS2 <http://www.msys2.org/>`__ using default settings. Start the MSYS2 MINGW 64-bit shell and execute the following command

::

    pacman -Syu

to update all packages (you may need to run it twice as it often fails the first time; just reopen the console and reenter the command. This may also happen for the other installs below).

1. Run the following commands to install all pre-requisites

::

    pacman -S mingw-w64-x86_64-gcc
    pacman -S mingw-w64-x86_64-cmake
    pacman -S make
    pacman -S git

2. Clone the repository and fetch the submodules:

::

    git submodule update --init extern/cereal extern/google-test extern/google-benchmark

3. Configure a build directory. The typical choice is a subfolder ``build``. In this case, the command is:

::

    cmake -S . -B build

Note that cmake will check for any system dependencies that are needed for the build process. ``PreLoad.cmake`` in the
repository root selects the "Unix Makefiles" generator automatically when CMake is run from the MinGW shell.

4. NTL/GMP (math backend 6) are optional and must be installed by the user (see :ref:`gmp_ntl_install`). They need ``autoconf``:

    ::

        pacman -S autoconf

   Then enable them when you run cmake (``-DCIPHER_WITH_NTL=ON``; see :ref:`cmake_in_cipher`).

5. Build Cipher by running the following command (this will take a few minutes; using the ``-j <threads>`` flag is suggested to speed up the build where threads is typically the number of cores or threads on your machine)

::

    cmake --build build -j <threads>

6. Install Cipher in a system directory (if desired or for production purposes)

::

    cmake --install build

You need to run MinGW64 as an administrator unless you are specifying some other install location. You can change the install location by running
``cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/your/path``

To run MinGW64 as an administrator, open Task Manager, go to File -> Run New Task, select the location of the executable for MinGW64, and check the box "Create this task with administrative privileges".

7. Add the directory holding the Cipher DLLs (``build/lib`` in the build tree, ``bin`` under the install prefix) to the
   ``PATH`` variable, plus the directory holding the NTL/GMP DLLs if NTL is used. For example:

Without NTL:

::

    export PATH=$PATH:$PWD/build/lib

With NTL:

::

    export PATH=$PATH:$PWD/build/lib:{PATH_TO_NTL_BINARIES}

Alternatively, add the path(s) to ``ORIGINAL_PATH`` variable in ``c:/msys64/etc/profile`` to make this change permanent.

Testing and cleaning the build
-------------------------------

Run unit tests to make sure all capabilities operate as expected

::

    ctest --test-dir build

Run sample code to test, e.g.,

::

    build/bin/examples/fhe/simple_integers

To remove the files built by the build tool, you can execute

::

    cmake --build build --target clean
