PKE Key-Switching documentation
====================================

`include/cipher/fhe/keyswitch <../../../../include/cipher/fhe/keyswitch>`_: This folder contains the header files of the key-switching methods present in Cipher.

The documentation is based on `Revisiting Homomorphic Encryption Schemes for Finite Fields <https://eprint.iacr.org/2021/204.pdf>`_

.. contents:: Page Contents
   :local:

Intuition
---------

Let :math:`c_t` be a ciphertext :math:`c_t = (c_0, c_1) \in \mathbb{R}_Q^2`, which can be decrypted with  :math:`s_A`.

Through key-switching, we create a new ciphertext, :math:`c_t'` such that :math:`c_t' = (c_0', c_1') \in \mathbb{R}_Q^2`, which contains the same message as :math:`c_t`, but can be decrypted by a different secret key :math:`s_B`.

Key switching

- This feature is needed to compute automorphisms(rotations) of ciphertexts, or to relinearize ciphertexts


Key-Switching Class Inheritance
---------------------------------

.. mermaid::

   graph BT
      Key[Keyswitch: Base Class] --> |Inherited by|KeyRNS[Keyswitch: RNS];
      KeyRNS[Keyswitch: RNS] --> |Inherited by|KeyBV[Keyswitch: BV];
      KeyRNS[Keyswitch: RNS] --> |Inherited by|KeyHybrid[Keyswitch: Hybrid];


File Listings
-----------------------

`Key-Switch Base (base.h) <../../../../include/cipher/fhe/keyswitch/base.h>`_

- ``KeySwitchBase``, the base class for key switching algorithms.

`Key-Switch RNS (rns.h) <../../../../include/cipher/fhe/keyswitch/rns.h>`_

- ``RnsKeySwitch``, the abstract interface class for key switching algorithms in RNS

`Key-Switch BV (bv.h) <../../../../include/cipher/fhe/keyswitch/bv.h>`_

- ``KeySwitchBv`` implements the BV scheme from `Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages (BV Scheme) <https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf>`_
- Requires the computation of a quadratic number of NTTs.
- See the Appendix of https://eprint.iacr.org/2021/204 for more detailed description of the RNS variant.

`Key-switch Hybrid (hybrid.h) <../../../../include/cipher/fhe/keyswitch/hybrid.h>`_

 - ``KeySwitchHybrid``: hybrid key switching method first introduced in https://eprint.iacr.org/2012/099.pdf
 - RNS version was introduced in https://eprint.iacr.org/2019/688.
 - See the Appendix of https://eprint.iacr.org/2021/204 for more detailed description.
