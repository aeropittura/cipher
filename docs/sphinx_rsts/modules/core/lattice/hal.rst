.. _hal:

Core Lattice Hardware Abstraction Layer Documentation
======================================================


.. contents:: Page Contents
   :local:
   :backlinks: none

Lattice HAL Introduction
----------------------------

.. mermaid::

  graph BT
      a[RnsPolyInterface] --> |Inherited by|b[RnsPoly - HAL Default];

This hardware abstraction layer allows Cipher to use a variety of hardware-integrated backends while still allowing for high performance. Cipher currently ships only the default (standard) backend in `include/cipher/ring/backend/standard <../../../../../include/cipher/ring/backend/standard>`_.

.. note:: Upstream OpenFHE also provides an `Intel HEXL backend <https://github.com/openfheorg/openfhe-hexl>`_; it is not part of Cipher.

File Listing
---------------

`RnsPolyInterface (rns_poly_interface.h) <../../../../../include/cipher/ring/backend/rns_poly_interface.h>`_

-  Base class for ``RnsPoly``

`Backend Aliases (backend_select.h) <../../../../../include/cipher/ring/backend/backend_select.h>`_

-  Defines the aliases for the default lattice backend (``Poly``, ``NativePoly``, ``RnsPoly``, ``PolyParams``, ...)

`RNS Polynomial (rns_poly.h) <../../../../../include/cipher/ring/backend/standard/rns_poly.h>`_

-  ``RnsPolyImpl`` inherits from ``RnsPolyInterface`` and provides the public-facing interface used downstream by the various schemes.

`RNS Params (rns_params.h) <../../../../../include/cipher/ring/backend/standard/rns_params.h>`_

-  Parameter class (``RnsParams``) for the double-CRT (RNS) representation.
