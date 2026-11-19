PKE Scheme documentation
====================================

This is comprised of the following folders under `include/cipher/fhe <../../../../include/cipher/fhe>`_ (implementations in `source/fhe <../../../../source/fhe>`_):

- `bfv <../../../../include/cipher/fhe/bfv>`_, `bgv <../../../../include/cipher/fhe/bgv>`_ and `ckks <../../../../include/cipher/fhe/ckks>`_, which contain the specifications of the different RNS implementations

- `base <../../../../include/cipher/fhe/base>`_, which contains the base implementations of various functionalities

- `rns <../../../../include/cipher/fhe/rns>`_, which contains the base RNS scheme implementation.

At a high level, this can be thought of as:

.. mermaid::

  graph BT
      A[SchemeBase] --> |Inherited by|B[RnsScheme];
      B[RnsScheme] --> |Inherited by|D[CkksRnsScheme];
      B[RnsScheme] --> |Inherited by|E[BgvRnsScheme];
      B[RnsScheme] --> |Inherited by|F[BfvRnsScheme];
