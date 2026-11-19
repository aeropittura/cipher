PKE Encoding documentation
====================================

`include/cipher/fhe/encoding <../../../../include/cipher/fhe/encoding>`_: Encoding of plaintext into intermediate form

.. contents:: Page Contents
   :local:
   :backlinks: none


Interactions
------------------------

.. mermaid::

  graph BT
      A[input_value Plaintext] --> |"1) encode"| B(Encoded Plaintext);
      B(Encoded Plaintext) --> |"2) encrypt"| C(Ciphertext);
      C(Ciphertext) --> |"3) decrypt"| B(Encoded Plaintext);
      B(Encoded Plaintext) --> |"4) set_length"| D(Homomorphically Transformed Plaintext);

File Listings
-----------------------

`CKKS Packed Encoding (ckks_packed.h) <../../../../include/cipher/fhe/encoding/ckks_packed.h>`_
    - Describes the CKKS packing. Accepts a ``std::vector<double>`` or a ``std::vector<std::complex>`` (although the double is recommended) unlike the other schemes.

`Coef Packed Encoding (coef_packed.h) <../../../../include/cipher/fhe/encoding/coef_packed.h>`_
    - Packs integers into a vector of size ``n``
    - Element-wise ops: Supports only element-wise addition (``eval_add``), but not multiplication. Thus, typically only works well when no multiplications are necessary
    - Scalar ops: multiplication supported
    .. note:: ``Coef Packed Encoding`` is rarely used.

`Encoding Params (encoding_params.h) <../../../../include/cipher/fhe/encoding/encoding_params.h>`_
    - The object containing the parameters for encoding. These parameters are kept and continually reused (can be modified) during the encoding of new values

`Encodings (encodings.h) <../../../../include/cipher/fhe/encoding/encodings.h>`_
    - “import” file which can be used for a single ``#include``

`Packed Encoding (packed.h) <../../../../include/cipher/fhe/encoding/packed.h>`_
    - Packs integers into a vector of size ``n``
    - Supports element-wise addition and multiplication via ``eval_add`` and ``eval_mult`` respectively
    - Supports automorphisms (commonly known as rotations) via ``eval_at_index``
        - Right Shift: positive index
        - Left Shift: negative index
        - Rotations work cyclically

    .. note:: is almost always what you want to use (other than if you want to deal with floating numbers)

`Plaintext (plaintext.h) <../../../../include/cipher/fhe/encoding/plaintext.h>`_
    - The base plaintext implementation

`Plaintext Factory (plaintext_factory.h) <../../../../include/cipher/fhe/encoding/plaintext_factory.h>`_
    - Factory class that instantiates plaintexts

`String Encoding (string_encoding.h) <../../../../include/cipher/fhe/encoding/string_encoding.h>`_
    - Encodes strings
