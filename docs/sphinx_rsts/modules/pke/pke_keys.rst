PKE Keys documentation
====================================

`include/cipher/fhe/key <../../../../include/cipher/fhe/key>`_: This folder contains the header files of the various keys that are defined within Cipher.


.. contents:: Page Contents
   :local:


File Listings
-------------

`Key Serialization (key_ser.h) <../../../../include/cipher/fhe/key/key_ser.h>`_

- Includes all key types together with their serialization support; ``cipher/cipher.h`` includes it


Keys Class Inheritance
-----------------------

.. mermaid::

   graph BT
      Key[Key: Base Class] --> |Inherited by|EvalKeyImpl;
      EvalKeyImpl --> |Inherited by|EvalKeyRelinImpl;


Key Class File Listings
-----------------------

`Eval Key (eval_key.h) <../../../../include/cipher/fhe/key/eval_key.h>`_

- Inherits from the base ``Key`` class.

- Serves as base class for ``Eval Key Relin``

`Eval Key Relin (relin_key.h) <../../../../include/cipher/fhe/key/relin_key.h>`_

- Get and set relinearization elements

- Inherits from ``Eval Key``

`Key (key.h) <../../../../include/cipher/fhe/key/key.h>`_

- Base Key class

- Serialization of the keys uses `Cereal <https://github.com/USCiLab/cereal>`__ (see ``key_ser.h`` above)

Key Pair
--------

.. mermaid::

   graph BT
      PrivKey[Private Key] --> |container|KP(Key Pair);
      PubKey[Public Key] --> |container|KP(Key Pair);

Key Pair File Listings
-----------------------

`Key Pair (key_pair.h) <../../../../include/cipher/fhe/key/key_pair.h>`_

- Container for the ``private key`` and ``public key`` implementations

`Private Key (private_key.h) <../../../../include/cipher/fhe/key/private_key.h>`_

`Public Key (public_key.h) <../../../../include/cipher/fhe/key/public_key.h>`_
