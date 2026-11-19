Building User Applications
##########################

How might you integrate Cipher into your projects?

Cipher installs a CMake package configuration, so a project can locate it with ``find_package(Cipher CONFIG)``. A
complete template is provided in ``examples/standalone/CMakeLists.txt``.

The high-level instructions for building projects that use Cipher are as follows:

1. Build and install Cipher (``cmake --build build`` followed by ``cmake --install build``). This copies the Cipher
   libraries, headers and package configuration to the installation prefix (``CMAKE_INSTALL_PREFIX``).

2. Create the folder for your project on your system.

3. Copy ``examples/standalone/CMakeLists.txt`` from the repository to the folder for your project.

4. Update ``CMakeLists.txt`` to specify the name of the executable and the source code files. For example, add the
   following lines

::

    add_executable(fhe_demo simple_integers.cpp)
    target_link_libraries(fhe_demo PRIVATE ${CIPHER_LIB})

The template sets ``CIPHER_LIB`` to ``Cipher::fhe``, or to ``Cipher::fhe_static`` when configured with
``-DUSE_STATIC=ON``. The targets ``Cipher::core`` and ``Cipher::boolean`` (and their ``_static`` variants) are also
available. A minimal project needs only::

    find_package(Cipher CONFIG REQUIRED)
    target_link_libraries(my_app PRIVATE Cipher::fhe)

5. If using MinGW/Windows (skip this step for other platforms), copy ``PreLoad.cmake`` from the root directory of the
   repository to the folder of your project.

6. Configure and build::

    cmake -S . -B build
    cmake --build build

If Cipher is installed in a non-default location, or you have several versions of Cipher installed, specify the path
to the desired installation::

    cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/cipher/install

7. If Cipher was built as shared libraries and installed in a non-standard location, the dynamic loader must be able
   to find them, for example by adding ``/path/to/cipher/install/lib`` to ``LD_LIBRARY_PATH`` (Linux),
   ``DYLD_LIBRARY_PATH`` (macOS) or ``PATH`` (Windows).

To use a module in your C++ code, include its main header: ``cipher/cipher.h`` for the FHE schemes (BFV, BGV, CKKS),
``cipher/boolean/context.h`` for Boolean FHE (class ``BooleanContext``) and ``cipher/core.h`` for the core math and
lattice layer. If your application uses serialization, additional header files will be needed (see the examples with
serialization, e.g. ``examples/fhe/simple_integers_serial.cpp``, for details).
