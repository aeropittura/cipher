Core Math Documentation
========================

.. toctree::
   :maxdepth: 2
   :caption: Sub-Contents:

   math_backends.rst
   ntl_backend.rst
   sampling.rst

.. contents:: Page Contents
   :local:
   :backlinks: entry

Math Backends
---------------

Cipher (headers in `include/cipher/math <../../../../../include/cipher/math>`_, implementation in `source/math <../../../../../source/math>`_) supports a number of mathematical backends for various usecases.
For more information refer to :doc:`math_backends`

Inheritance Diagram
---------------------

Let Gen. = Generator

.. mermaid::

   flowchart BT
       A[Distribution Generator] --> |Inherited by|B[Ternary Uniform Gen.];
       A[Distribution Generator] --> |Inherited by|C[Discrete Uniform Gen.];
       A[Distribution Generator] --> |Inherited by|D[Binary Uniform Gen.];
       A[Distribution Generator] --> |Inherited by|E[Discrete Gaussian Gen.];
       A[Distribution Generator] --> |Inherited by|F[Discrete Gaussian Generic Gen.];

File Listings
----------------

`Binary Uniform Generator (binary_uniform_gen.h) <../../../../../include/cipher/math/binary_uniform_gen.h>`_

-  Generate ``Uniform`` distribution of binary values (mod 2)
-  Relies on built-in C++ generator for 32-bit unsigned integers defined
   in ``<random>``

`DFT Transform (dft.h) <../../../../../include/cipher/math/dft.h>`_

-  Discrete Fourier Transform (FFT) code

`Discrete Gaussian Generator (discrete_gaussian_gen.h) <../../../../../include/cipher/math/discrete_gaussian_gen.h>`_

-  Generate ``Gaussian`` distribution of discrete values.
-  Relies on built-in C++ generator for 32-bit unsigned integers defined
   in ``<random>``

`Discrete Gaussian Generator Generic (discrete_gaussian_gen_generic.h) <../../../../../include/cipher/math/discrete_gaussian_gen_generic.h>`_

-  Implements the generic sampler by UCSD discussed in `Gaussian
   Sampling over the Integers: Efficient, Generic,
   Constant-Time <https://eprint.iacr.org/2017/259.pdf>`__
-  based heavily on Michael Walter’s original code.
-  2 different “Base Samplers”

   -  Peikert’s inversion method
   -  Knuth-Yao

-  Generic Sampler works independent from standard deviation of the
   distribution

   -  combines an array of aforementioned base samplers centered around
      0 to :math:`\frac{2^{b} - 1}{2^b}` through convolution

`Discrete Uniform Generator (discrete_uniform_gen.h) <../../../../../include/cipher/math/discrete_uniform_gen.h>`_

-  Generate ``Uniform`` distribution of discrete values.
-  Relies on built-in C++ generator for 32-bit unsigned integers defined
   in ``<random>``

`Distributions (distributions.h) <../../../../../include/cipher/math/distributions.h>`_

-  Basic noise generation functionality (includes all the generators)

`Distribution Generator (distribution_gen.h) <../../../../../include/cipher/math/distribution_gen.h>`_

-  Base class for distribution generators

`Hardware Abstraction Layer (HAL) (backend.h) <../../../../../include/cipher/math/backend.h>`_

-  Code to switch between math backends

`Matrix (matrix.h) <../../../../../include/cipher/math/matrix.h>`_

-  Templated matrix implementation for SIMD-compatible matrix code

`Matrix Strassen (matrix_strassen.h) <../../../../../include/cipher/math/matrix_strassen.h>`_

-  Matrix Strassen Operations

`Number Theory Functions (number_theory.h) <../../../../../include/cipher/math/number_theory.h>`_

-  Number theory utilities
-  Check if two numbers are coprime
-  GCD of two numbers
-  Primality testing
-  witness function to test if a number is prime
-  Eulers Totient function phin(n)
-  Generator Algorithm

`Ternary Uniform Generator (ternary_uniform_gen.h) <../../../../../include/cipher/math/ternary_uniform_gen.h>`_

-  Provides generation of uniform distribution of binary values
