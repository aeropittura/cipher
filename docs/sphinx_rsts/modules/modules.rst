Cipher Modules
=================================================

Understanding the various Modules
------------------------------------

.. mermaid::

  graph BT
      A[Cipher::core<br/>- math implementation<br/>- lattice implementation<br/>- serialization] --> B[Cipher::fhe<br/> -generalized FHE];
      A --> C[Cipher::boolean<br/>- boolean FHE];
      B --> D[Application<br/>- encrypted data analysis<br/>- privacy-compliant data sharing];
      C --> D;

Boolean FHE (cipher/boolean)
----------------------------
.. toctree::
   :maxdepth: 2

   binfhe.rst


Core (cipher/math, cipher/ring, cipher/util)
--------------------------------------------
.. toctree::
   :maxdepth: 2

   core/core.rst
   core/lattice/core_lattice.rst
   core/lattice/hal.rst
   core/math/core_math.rst
   core/utils/core_utils.rst


Public-Key Encryption and FHE (cipher/fhe)
------------------------------------------
.. toctree::
   :maxdepth: 2

   pke/pke.rst
   pke/pke_encoding.rst
   pke/pke_keys.rst
   pke/pke_keyswitch.rst
   pke/pke_scheme.rst
