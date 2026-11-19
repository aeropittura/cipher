NTL Backend API
===============

This page exposes Cipher's extensions in ``namespace NTL``. These
classes are only compiled when Cipher is configured with ``CIPHER_WITH_NTL``,
and the documentation build defines that macro so Doxygen can extract
the guarded declarations.

.. contents:: Page Contents
   :local:
   :backlinks: none

Namespace
---------

.. doxygennamespace:: NTL

Integer and Vector Types
------------------------

.. doxygenclass:: NTL::NtlInteger
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::NtlModVector
   :members:
   :protected-members:
   :undoc-members:

Number Theoretic Transform Types
--------------------------------

.. doxygenclass:: NTL::NumberTheoreticTransformNtl
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::ChineseRemainderTransformFTTNtl
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::ChineseRemainderTransformArbNtl
   :members:
   :protected-members:
   :undoc-members:

.. doxygenclass:: NTL::BluesteinFFTNtl
   :members:
   :protected-members:
   :undoc-members:
