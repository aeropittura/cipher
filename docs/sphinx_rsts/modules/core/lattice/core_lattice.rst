Core Lattice Documentation
====================================

Documentation for `include/cipher/ring/ <../../../../../include/cipher/ring>`_ (implementation in `source/ring/ <../../../../../source/ring>`_)

.. contents:: Page Contents
   :local:

Hardware Abstraction Layer
---------------------------

.. note:: Refer to :ref:`HAL Documentation<hal>` to learn more about the hardware abstraction layer. HAL allows users to use a variety of backends while still allowing for high performance.

The Lattice Layer
-----------------

The files in this directory are to support lattice-layer operations in Cipher. The layer is used to represent polynomial rings and support operations over those polynomial rings.

- A polynomial ring is defined as :math:`R_q = \frac{Z_q[X]}{f(X)}`, with f(X) a mononic irreducable polynomial of degree n, and q an integer modulus.

- The current implementations support polynomial rings that are of dimension a power of two (:math:`x^n + 1` where n is a power of 2).

- Support for arbitrary cyclotomic rings is also available but in experimental mode. The case of m = p and m = 2*p, where m is a cyclotomic order and p is a prime, have been tested relatively well. Other cases of m have not been tested.

This lattice layer is a middle layer in the library. The lattice layer supports higher-level calls for operations on ring elements necessary for lattice cryptography. The lattice layer is intended to make calls to lower layers that support math operations, such as modulus and ring arithmetic.

Polynomial representations
^^^^^^^^^^^^^^^^^^^^^^^^^^

The three main data classes in this layer are ``Poly``, ``NativePoly`` and ``RnsPoly``.

-  A ``Poly`` is a single-CRT representation using BigInteger types as coefficients, and supporting a large modulus q.

-  A ``NativePoly`` is a single-CRT representation using NativeInteger types, which limites the size of the coefficients and the modulus q to 64 bits.

-  A ``RnsPoly`` is a double-CRT representation. In practice, this means that Poly uses a single large modulus q, while RnsPoly uses multiple smaller moduli. Hence, Poly runs slower than RnsPoly because RnsPoly operations can be easier to fit into the native bitwidths of commodity processors.

- ``Poly``, ``NativePoly`` and ``RnsPoly`` all implement the interface ``RingElement``. Any new ring polynomial classes should be built to conform to this interface.

The classes ``PolyParams`` (an alias of ``PolyParamsImpl<BigInteger>``) and ``RnsParams`` contain parameters for the ring element representations. The following parameters are available for:

- ``Poly`` and ``NativePoly``:

  - order
  - modulus
  - root of unity

- ``RnsPoly``:

  - order
  - double-CRT width
  - moduli
  - roots of unity

Polynomial Ring Formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The coefficients of the polynomial ring, in their initial form, are just coefficients. Translated into one of ``Poly`` or
``RnsPoly``, can be simply seen as vector's representing polynomial ring elements.


.. note:: We internally represent polynomial ring elements as being either in ``COEFFICIENT`` or ``EVALUATION`` format. It is generally computationally less expensive to carry on all operations in the evaluation form

   However, the CRT and inverse CRT operations take ``O(nlogn)`` time using current best known algorithms, where n is the ring dimension.


COEFFICIENT form
****************

- AKA Raw form
- Converted to ``EVALUATION`` form by applying the Chinese-Remainder-Transform (CRT), which is a Number Theoretic Transform (NTT)  and variant of the Discrete Fourier Transform (DFT), which converts ring elements into ``EVALUATION`` form

EVALUATION FORM
****************

- allows us to do element-wise multiplication on two or more ring polynomials

File Listing
---------------


Parameter Classes
^^^^^^^^^^^^^^^^^^

The interactions can be summarized as:

.. mermaid::

   flowchart BT
       A[ElementParams <br> - base class </br>] --> B[PolyParamsImpl <br> - Ideal Lattice Params </br>];
       B[PolyParamsImpl <br> - Ideal Lattice Params </br>] --> C[RnsParams <br> - Ideal Lattice Double-CRT Params</br>]


`Lattice Element Parameters (element_params.h) <../../../../../include/cipher/ring/backend/element_params.h>`_

-  ``ElementParams``, a simple base class to contain ring element parameters.

`Polynomial Parameters (poly_params.h) <../../../../../include/cipher/ring/backend/standard/poly_params.h>`_

-  ``PolyParamsImpl``, the parameter class for basic single-CRT lattice parameters.
-  Inherits from ``ElementParams``

`RNS (Double-CRT) Parameters (rns_params.h) <../../../../../include/cipher/ring/backend/standard/rns_params.h>`_

-  ``RnsParams``, the parameter class for double-CRT lattice parameters.
-  Inherits from ``ElementParams``

Element Classes
^^^^^^^^^^^^^^^^^^

.. mermaid::

   flowchart BT
       A[RingElement<br> - Ideal Lattice Elements </br>] --> B[PolyImpl <br> - elements from ideal lattices using a single-CRT representation </br>];
       A[RingElement<br> - Ideal Lattice Elements </br>] --> C[RnsPolyImpl <br> - elements from ideal lattices using a double-CRT representation</br>]

`Ring Elements (element.h) <../../../../../include/cipher/ring/element.h>`_

-  ``RingElement``, the basic interface class for elements from ideal lattices.

`Ideal Lattice using Vector Representation (poly.h) <../../../../../include/cipher/ring/backend/standard/poly.h>`_

-  These files present a basic class for ``Poly``, elements from ideal lattices using a single-CRT representation.
-  This class (``PolyImpl``) implements ``PolyInterface``, which derives from ``RingElement``.
-  This file also defines a ``NativePoly``, which is simply a ``Poly`` using ``NativeInteger`` coefficients. A ``NativePoly`` is an important part of an ``RnsPoly``.

Trapdoors
^^^^^^^^^^

`Trapdoor (trapdoor.h) <../../../../../include/cipher/ring/trapdoor.h>`_

-  Provides the utility for sampling trapdoor lattices as described in `Implementing Conjunction Obfuscation under Entropic Ring LWE <https://eprint.iacr.org/2017/844.pdf>`__, `Building an Efficient Lattice Gadget Toolkit: Subgaussian Sampling and More <https://eprint.iacr.org/2018/946>`__, and `Implementing Token-Based Obfuscation under (Ring) LWE <https://eprint.iacr.org/2018/1222.pdf>`__

.. note:: Uses `Discrete Gaussian Sampling (gaussian_sampling.h) <../../../../../include/cipher/ring/gaussian_sampling.h>`_ to implement the algorithms in the aforementioned papers

`Trapdoor Parameters (trapdoor_params.h) <../../../../../include/cipher/ring/trapdoor_params.h>`_

-  Parameter definitions for trapdoor-related schemes (GPV signature, IBE, ABE)
-  Uses ``trapdoor.h``

Misc.
^^^^^

`Discrete Gaussian Sampling (gaussian_sampling.h) <../../../../../include/cipher/ring/gaussian_sampling.h>`_

-  Provides detailed algorithms for G-sampling and perturbation sampling
   as described in `Implementing Conjunction Obfuscation under Entropic
   Ring LWE <https://eprint.iacr.org/2017/844.pdf>`__, `Building an
   Efficient Lattice Gadget Toolkit: Subgaussian Sampling and
   More <https://eprint.iacr.org/2018/946>`__, and `Implementing
   Token-Based Obfuscation under (Ring)
   LWE <https://eprint.iacr.org/2018/1222.pdf>`__

.. note:: Sampling:
   - Refer to :ref:`our sampling documentation for more information<sampling>`

`Power-of-2 fields (field2n.h) <../../../../../include/cipher/ring/field2n.h>`_

-  Represents and defines power-of-2 fields

`Standard Values for Lattice Params (standard_params.h) <../../../../../include/cipher/ring/standard_params.h>`_

-  Header for the standard values for Lattice Parms, as determined by `Homomorphic Encryption Org <https://homomorphicencryption.org>`__

-  Given (distribution type, security level), we can get a ``max_q`` for a given ring dimension, or get a ring dimension given some ``max_q``

`Lattice Backend Switcher (backend.h) <../../../../../include/cipher/ring/backend.h>`_

- contains functionality to switch between lattice backends


Assumptions
-----------

-  It is assumed that any scalar or vector operation such as multiplication, addition etc. done on one or more operations contain the same params. Checks need to be added to the code to test the compatibility of parameters.

-  Multiplication is currently only implemented in the ``EVALUATION`` format. Code needs to be added to implement ``COEFFICIENT`` format multiplication, if desired.
