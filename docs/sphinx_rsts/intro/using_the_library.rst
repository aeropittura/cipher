Using The Library
====================================

Cipher consists of a number of library objects that can be linked into lattice cryptography applications.

The example programs, particularly those in ``examples/fhe``, illustrate the use of the library.

To use Cipher, you must

* select a scheme to use

  * BFV (``ContextParams<BfvRnsContext>``)

  * BGV (``ContextParams<BgvRnsContext>``)

  * CKKS (``ContextParams<CkksRnsContext>``)

* create a ``CryptoContext`` for the scheme with ``make_crypto_context(params)``. This requires that you:

 * run a parameter generation function or, alternatively,

  * decide on lattice parameters (ring dimension, size of moduli)

  * decide on encoding parameters (plaintext modulus)

  * decide on scheme-specific parameters

 * enable the algorithms that you want to use, e.g.,

   * ``enable(PKE)`` - allows for key generation and encrypt/decrypt

   * ``enable(KEYSWITCH)`` - enables key switching (needed for relinearization and rotations)

   * ``enable(LEVELEDSHE)`` - enables leveled SHE operations such as ``eval_add`` and ``eval_mult``

   * ``enable(ADVANCEDSHE)`` - enables advanced operations such as ``eval_sum`` and polynomial evaluation

   * ``enable(PRE)`` - allows for the use of proxy re-encryption

   * ``enable(MULTIPARTY)`` - enables threshold FHE operations

   * ``enable(FHE)`` - enables bootstrapping

   * ``enable(SCHEMESWITCH)`` - enables CKKS to FHEW scheme switching

In order to make this easier for the user, ``make_crypto_context`` generates the remaining parameters from the few that are set on ``ContextParams``.

Streamlining and improving the process of parameter selection and CryptoContext generation is an area that is being actively worked.

Anything done in Cipher is done through the ``CryptoContext``. All operations are ``CryptoContext`` methods. The code only allows operations between objects that were created in the same context, and will generate an error if it finds that this is not the case.

Saving to string or disk file
-----------------------------

Serialization and Deserialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Objects created by a ``CryptoContext`` (and the context itself) can be serialized with cereal, in binary
(``SerType::BINARY``) or JSON (``SerType::JSON``) format, using the functions in ``cipher/util/serial.h``:

* ``serialization::to_stream()``

* ``serialization::serialize_to_file()``

A serialized object can be deserialized using the following functions, respectively:

* ``serialization::from_stream()``

* ``serialization::deserialize_from_file()``

The deserialization process will ensure that the serialized object's parameters match the CryptoContext. If they do, then
the new object "belongs to" the CryptoContext and can be used with other objects from the same CryptoContext.

.. note:: A mismatch of parameters will cause the deserialization to fail.
