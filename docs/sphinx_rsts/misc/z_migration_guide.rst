How To Migrate A User Project From OpenFHE To Cipher
=====================================================

Cipher is derived from OpenFHE 1.6.1 and keeps its algorithms, parameters and
serialization format; what changed are the header layout, the namespace, the
names of types and functions, and the build options. A typical OpenFHE
application is migrated mechanically with the rules below. The example
``examples/fhe/simple_integers.cpp`` is the migrated form of OpenFHE's
``simple-integers.cpp`` and is a useful side-by-side reference.

.. note::
   The upstream guide for migrating from PALISADE to OpenFHE is part of the
   OpenFHE documentation; it describes OpenFHE's API, not Cipher's.

Build system
------------

Replace the OpenFHE package and its variables with the ``Cipher`` CMake
package and its imported targets:

.. code-block:: cmake

    find_package(Cipher CONFIG REQUIRED)
    target_link_libraries(my_app PRIVATE Cipher::fhe)   # Cipher::fhe_static for static builds

``Cipher::core`` and ``Cipher::boolean`` (plus their ``_static`` variants)
replace the core and binfhe libraries. A complete template is in
``examples/standalone/CMakeLists.txt``. Build options now carry the
``CIPHER_`` prefix, e.g. ``CIPHER_WITH_OPENMP``, ``CIPHER_MATH_BACKEND``,
``CIPHER_NATIVE_SIZE``, ``CIPHER_BUILD_TESTS``; all of them are listed in
``cmake/CipherOptions.cmake``.

Headers and namespace
---------------------

.. list-table::
   :header-rows: 1

   * - OpenFHE
     - Cipher
   * - ``#include "openfhe.h"``
     - ``#include "cipher/cipher.h"``
   * - ``#include "binfhecontext.h"``
     - ``#include "cipher/boolean/context.h"``
   * - ``#include "ciphertext-ser.h"``
     - ``#include "cipher/fhe/ciphertext_ser.h"``
   * - ``#include "cryptocontext-ser.h"``
     - ``#include "cipher/fhe/context_ser.h"``
   * - ``#include "key/key-ser.h"``
     - ``#include "cipher/fhe/key/key_ser.h"``
   * - ``#include "scheme/bfvrns/bfvrns-ser.h"`` (likewise bgvrns, ckksrns)
     - ``#include "cipher/fhe/bfv/ser.h"`` (likewise ``bgv``, ``ckks``)
   * - ``using namespace lbcrypto;``
     - ``using namespace cipher;``

Names
-----

Types are ``PascalCase``, functions, methods and variables ``snake_case``, and
data members end with an underscore. In practice:

.. list-table::
   :header-rows: 1

   * - OpenFHE
     - Cipher
   * - ``DCRTPoly``
     - ``RnsPoly``
   * - ``CCParams<CryptoContextBFVRNS>`` (likewise BGVRNS, CKKSRNS)
     - ``ContextParams<BfvRnsContext>`` (likewise ``BgvRnsContext``, ``CkksRnsContext``)
   * - ``GenCryptoContext(parameters)``
     - ``make_crypto_context(parameters)``
   * - ``parameters.SetMultiplicativeDepth(2)``
     - ``parameters.set_multiplicative_depth(2)``
   * - ``cc->Enable(PKE)``
     - ``cc->enable(PKE)``
   * - ``cc->KeyGen()``, ``cc->EvalMultKeyGen(keys.secretKey)``
     - ``cc->key_gen()``, ``cc->eval_mult_key_gen(keys.secret_key)``
   * - ``cc->MakePackedPlaintext(v)``, ``cc->Encrypt(...)``, ``cc->EvalMult(a, b)``
     - ``cc->make_packed_plaintext(v)``, ``cc->encrypt(...)``, ``cc->eval_mult(a, b)``
   * - ``plaintext->SetLength(n)``, ``cc->GetRingDimension()``
     - ``plaintext->set_length(n)``, ``cc->get_ring_dimension()``
   * - ``Serial::SerializeToFile(...)``, ``Serial::DeserializeFromFile(...)``
     - ``serialization::serialize_to_file(...)``, ``serialization::deserialize_from_file(...)``
   * - ``BinFHEContext``, ``cc.GenerateBinFHEContext(STD128)``
     - ``BooleanContext``, ``cc.generate_boolean_context(STD128)``
   * - ``cc.BTKeyGen(sk)``, ``cc.EvalBinGate(AND, a, b)``
     - ``cc.bt_key_gen(sk)``, ``cc.eval_bin_gate(AND, a, b)``
   * - ``OpenFHEException``, ``OPENFHE_THROW(...)``
     - ``CipherException``, ``CIPHER_THROW(...)``

Enumerations and their values (``PKE``, ``LEVELEDSHE``, ``FLEXIBLEAUTO``,
``HYBRID``, ``STD128``, ``UNIFORM_TERNARY``, ...) keep their names. When a
name is not obvious from these rules, search the headers under
``include/cipher`` for the ``snake_case`` form.

Serialized data
---------------

Serialized contexts, keys and ciphertexts use the same on-disk format and type
names as OpenFHE 1.6.1, so files written by either library can be read by the
other (binary and JSON). No data migration is needed.
