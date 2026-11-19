Math Backends
=============

.. contents:: Page Contents
   :local:


Design
------

**Goal**: Support choosing, at **run-time**, which math backend to use.

**Currently**: **Compile-time** choice of which backend to use

.. note:: All implementations for Big/Native Integer/Vector are based on the
   interfaces in ``include/cipher/math/backend/integer.h`` and
   ``include/cipher/math/backend/vector.h``

-  By selecting a particular ``CIPHER_MATH_BACKEND``, we are choosing a default
   implementation for:

   -  ``BigInteger``
   -  ``BigVector``
   -  ``Poly`` and ``ciphertext modulus`` used in ``RnsPoly``

-  For native arithmetic, ``NativeInteger`` and ``NativeVector`` is
   available.


Choosing a Backend
------------------

You can either:

-  Add a flag during the ``CMake`` configure step: ``cmake -S . -B build -DCIPHER_MATH_BACKEND=4``

-  Additional backends can be compiled alongside the default one with
   ``CIPHER_WITH_BE2=ON``, ``CIPHER_WITH_BE4=ON`` or ``CIPHER_WITH_NTL=ON``; the
   selection logic is in ``include/cipher/math/backend/big_int_backend.h``

Math Backend Descriptions
-------------------------

CIPHER_MATH_BACKEND 2
~~~~~~~~~~~~~~~~~~~~~

-  Max size of ``BigInteger`` will be ``BigIntegerBitLength`` (defined
   in ``include/cipher/math/backend/fixed/integer.h``) which has a default of
   3500 bits (8000 bits when ``CIPHER_NATIVE_SIZE=128``).

-  It is advisable to select a value for ``BigIntegerBitLength`` larger
   than double the ``bitwidth`` of the largest (ciphertext) modulus.

-  This parameter can be decreased for runtime/space optimization when
   the largest modulus is under 1500 bits.

-  **Note**: The underlying implementation is fixed-size array of native
   ints.

   -  Native integer used is defined by the ``typedef`` using
      ``integral_dtype`` and MUST be ``uint32_t``; using other types is
      an open work item

CIPHER_MATH_BACKEND 4
~~~~~~~~~~~~~~~~~~~~~

-  No Explicit max size of ``BigInteger``
-  Size grows dynamically and is only constrained by memory
-  The implementation is in ``include/cipher/math/backend/dynamic/``; the limb
   type is selected in ``include/cipher/math/backend/dynamic/integer.h``

CIPHER_MATH_BACKEND 6
~~~~~~~~~~~~~~~~~~~~~

-  Integration of the ``NTL`` library with Cipher (``NtlInteger`` and ``NtlModVector``
   in ``include/cipher/math/backend/ntl/``)
-  Only available when Cipher is configured with ``-DCIPHER_WITH_NTL=ON``,
   which requires NTL and GMP to be installed (see :doc:`ntl_backend`)

Supported Math Operations
---------------------------

Modular Multiplication
~~~~~~~~~~~~~~~~~~~~~~~~~~
We use the following naming conventions:

-  ``mod_mul(b, mod_value)``

   -  Naive modular multiplication that uses % operator for modular
      reduction
   -  usually slow.

-  ``mod_mul(b, mod_value, mu)``

   -  Barrett modular multiplication. ``mu`` for Barrett modulo can be
      precomputed by ``mod_value.compute_mu()``.

-  ``mod_mul_fast(b, mod_value)``

   -  Naive modular multiplication w/ operands < mod

-  ``mod_mul_fast(b, mod_value, mu)``

   -  Barrett modular multiplication w/ operands < mod

-  ``mod_mul_fast_const(b, mod_value, bPrecomp)``

   -  modular multiplication using precomputed information on b, w/
      operands < mod_value.
   -  ``bPrecomp`` can be precomputed by ``b.prep_mod_mul_const(mod_value)``.
   -  This method is currently implemented only for NativeInteger class.
   -  The fastest method.

Other Modular Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~

+---------+------------------------+----------------------------+----------------------------+--------------------------------+---------------------------------------------+
| Variant | Naive                  | Barrett                    | Fast Naive                 | Fast Barrett                   | Fast Const                                  |
+=========+========================+============================+============================+================================+=============================================+
| mod     | mod(mod_value)         | mod(mod_value, mu)         | \-                         | \-                             | \-                                          |
+---------+------------------------+----------------------------+----------------------------+--------------------------------+---------------------------------------------+
| mod_add | mod_add(b, mod_value)  | mod_add(b, mod_value, mu)  | mod_add_fast(b, mod_value) | \-                             | \-                                          |
+---------+------------------------+----------------------------+----------------------------+--------------------------------+---------------------------------------------+
| mod_sub | mod_sub(b, mod_value)  | mod_sub(b, mod_value, mu)  | mod_sub_fast(b, mod_value) | \-                             | \-                                          |
+---------+------------------------+----------------------------+----------------------------+--------------------------------+---------------------------------------------+
| mod_mul | mod_mul(b, mod_value)  | mod_mul(b, mod_value, mu)  | mod_mul_fast(b, mod_value) | mod_mul_fast(b, mod_value, mu) | mod_mul_fast_const(b, mod_value, bPrecomp)  |
+---------+------------------------+----------------------------+----------------------------+--------------------------------+---------------------------------------------+
