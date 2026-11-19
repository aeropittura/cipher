General Public Key Encryption (PKE) documentation
=================================================

The ``Cipher::fhe`` library: headers in `include/cipher/fhe <../../../../include/cipher/fhe>`_, implementation in `source/fhe <../../../../source/fhe>`_.

.. contents:: Page Contents
   :depth: 2
   :local:


File Listings
-----------------------

`Ciphertext (ciphertext.h) <../../../../include/cipher/fhe/ciphertext.h>`__

-  for the representation of ciphertext in Cipher

-  provides ``CiphertextImpl`` which is used to contain encrypted text

`Ciphertext Serialization (ciphertext_ser.h) <../../../../include/cipher/fhe/ciphertext_ser.h>`__

-  exposes serialization methods for ciphertexts to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ciphertext serialization

`Constants (constants.h) <../../../../include/cipher/fhe/constants.h>`__

-  Contains the various constants used throughout the ``PKE`` module

`CryptoContext Factory (context_factory.h) <../../../../include/cipher/fhe/context_factory.h>`__

-  ``ContextFactory`` generates new ``CryptoContext`` objects from user parameters

`CryptoContext (context.h) <../../../../include/cipher/fhe/context.h>`__

-  defines ``CryptoContextImpl``, which is used to access the Cipher
   library

-  all Cipher objects are created “within” a ``CryptoContext`` which
   acts like an object “manager”. Objects can only be used in the
   context they were created in

`CryptoContext Serialization (context_ser.h) <../../../../include/cipher/fhe/context_ser.h>`__

-  exposes serialization methods for ``CryptoContext`` to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ``CryptoContext`` serialization

`CryptoContext Object (crypto_object.h) <../../../../include/cipher/fhe/crypto_object.h>`__

-  ``CryptoObject`` comprises a ``context`` and a ``key_tag``:

   -  ``context``: ``CryptoContext`` this object belongs to
   -  ``key_tag``: tag that is used to find the evaluation key needed for
      various operations

`CryptoContext Generator (context_gen.h) <../../../../include/cipher/fhe/context_gen.h>`__

-  ``make_crypto_context()`` constructs a ``CryptoContext`` from a ``ContextParams<BfvRnsContext>``, ``ContextParams<BgvRnsContext>`` or ``ContextParams<CkksRnsContext>`` object

`Global Values (globals.h) <../../../../include/cipher/fhe/globals.h>`__

-  Global value definitions

`Metadata Container (metadata.h) <../../../../include/cipher/fhe/metadata.h>`__

-  metadata container and helper function definition

`Metadata Serialization (metadata_ser.h) <../../../../include/cipher/fhe/metadata_ser.h>`__

-  exposes serialization methods for ``Metadata`` to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ``Metadata`` serialization

`Cipher Top-Level Include (cipher.h) <../../../../include/cipher/cipher.h>`__

- Top-level ``#include "cipher/cipher.h"`` for access to all FHE capabilities
