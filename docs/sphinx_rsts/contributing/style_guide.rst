Cipher Style Guide
========================


General Style Guidelines
---------------------------

-  Try to follow the style of surrounding code, and use variable names
   that follow existing patterns. Pay attention to indentation and
   spacing.
-  Configure your editor to use 4 spaces per indentation level, and
   **never to use tabs**.
-  Avoid introducing trailing whitespace
-  Lines are limited to 120 characters (``ColumnLimit`` in ``.clang-format``)
-  Give meaningful variable names to all variables.
-  Every reused discrete block of code has its own method
-  Every discrete line of code, or discrete group of code lines for each task has its own comment.


C++
---

Cipher coding style is based on the official `Google C++ Coding Style Guide <https://google.github.io/styleguide/cppguide.html/>`_.

We explicitly note:

-  Write comments to explain non-obvious operations within the code,
   both in header or source files.

-  All classes, member variables, methods, and constants should have Doxygen-style comments

   - Please document all input and output data characteristics (required lengths of vectors,
   restrictions on combinations of variables) as well as any conditions
   that generate exceptions.

   - e.g comment lines starting with ``//!`` or comment blocks
   starting with ``/*!``

-  Avoid defining non-trivial functions in header files

-  Header files should include an ‘include guard’ named after the file's path
   from the repository root, upper-cased, with every non-alphanumeric character
   replaced by an underscore and a trailing underscore. For
   ``include/cipher/fhe/context.h`` that is
   ``CIPHER_FHE_CONTEXT_H_`` (the path below ``include/``). The closing line reads
   ``#endif  // CIPHER_FHE_CONTEXT_H_``, and the guard wraps the
   whole file, including any feature check such as ``#ifdef CIPHER_WITH_NTL``.

-  Includes are grouped in this order, separated by blank lines: the header this
   file implements, C system headers, C++ system headers, then everything else.
   A file includes the headers it uses rather than relying on another header to
   provide them.

- Operator overloading is allowed, especially for binary operations


Design Principles
^^^^^^^^^^^^^^^^^^

- ``cout`` should never be used for exception handling and should never be used in committed code in the core Cipher library.

- Errors are reported by throwing ``cipher::CipherException`` with the ``CIPHER_THROW`` macro from ``cipher/util/exception.h``. Diagnostic output goes through ``cipher/util/diagnostic_output.h`` (``CIPHER_DIAGNOSTIC_OUT``/``CIPHER_DIAGNOSTIC_ERR``), never directly to ``std::cout``/``std::cerr``; a pre-commit hook enforces this.

- Code may use C++17 features. The minimum required compiler versions are listed in the main README.md file.

- Avoid manual memory management (i.e. ``new`` and ``delete``),
  preferring to use standard library containers, as well as
  ``std::unique_ptr`` and ``std::shared_ptr`` when dynamic allocation
  is required.

- Do not add new external dependencies to the public interface. Bundled
  third-party code lives in ``extern/`` as git submodules.

Naming Conventions
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Class, struct, type alias and enum type names use ``PascalCase``
   (``RnsPoly``, ``CkksRnsScheme``, ``BooleanContext``).

-  Functions, methods and variables use ``snake_case``
   (``eval_mult``, ``get_ring_dimension``, ``key_gen``).

-  Data members end with an underscore (``params_``). For most classes,
   member variables should not be public.

-  Where the case of a single letter carries mathematical meaning it is kept
   (``get_N()`` is the ring dimension, ``get_n()`` the LWE dimension).

-  Constants, enumerators and macros use ``UPPER_CASE_WITH_UNDERSCORES``;
   macros and build options carry the ``CIPHER_`` prefix (``CIPHER_THROW``,
   ``CIPHER_WITH_OPENMP``).

-  Everything lives in the ``cipher`` namespace. Do not indent the contents of
   namespaces.

Additional Resources
^^^^^^^^^^^^^^^^^^^^^

-  While Cipher does not specifically follow these rules, the following
   style guides are useful references for possible style choices and the
   rationales behind them.

   -  `The Google C++ Style Guide: <https://google.github.io/styleguide/cppguide.html>`_
   -  `Geosoft: C++ Programming Style Guidelines <http://geosoft.no/development/cppstyle.html>`_

.. note:: We have automated syntax checking on commit using ``clang-format``,
   so many of the above formatting rules will be automatically made.

Python
------

-  Maintenance scripts (``tools/``, ``docs/conf.py``) are written for Python 3
   and generally follow `PEP8 <https://www.python.org/dev/peps/pep-0008/>`_.
