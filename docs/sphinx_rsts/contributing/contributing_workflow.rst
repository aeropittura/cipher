Contributing to Cipher
=======================

Cipher is developed on GitHub at https://github.com/aeropittura/cipher. Bugs,
questions and proposals go to the issue tracker there; code changes arrive as
pull requests against the ``main`` branch.

.. note::
   For a large change (a new scheme, a change of the public API, a
   restructuring of the build) please open an issue first so the approach can
   be agreed on before work starts.

Prerequisites
-------------

Install Python 3 and ``pre-commit``:

-  Linux: ``pip3 install pre-commit``
-  macOS: ``brew install pre-commit``
-  Windows, from ``git bash``: ``pip3 install pre-commit``

That is the only tool you need. ``clang-format`` and ``cpplint`` are pinned to
specific versions in ``.pre-commit-config.yaml``, and ``pre-commit`` downloads
them into its own cache the first time the hooks run, so every contributor
formats with the same versions.

.. note:: ``clang-format`` output differs between versions, so an editor
   configured to format on save may disagree with the hook. Running
   ``pip3 install clang-format==23.1.1`` gives your editor the same binary the
   hook uses.

Enable the hooks once per clone:

.. code:: bash

   pre-commit install

From then on the hooks run on every ``git commit``. To check or fix the whole
tree, run ``pre-commit run --all-files`` or ``tools/format.sh`` (which applies
the pinned ``clang-format`` to every tracked C and C++ file; arguments are
passed through to ``pre-commit``, e.g. ``tools/format.sh --files source/fhe/context.cpp``).

The hooks also check that library code under ``source/`` and ``include/``
writes diagnostics through ``cipher/util/diagnostic_output.h`` rather than
directly to ``std::cout``/``std::cerr``.

Workflow
--------

1. Fork https://github.com/aeropittura/cipher on GitHub and clone your fork:

   .. code:: bash

      git clone https://github.com/<you>/cipher.git
      cd cipher
      git remote add upstream https://github.com/aeropittura/cipher.git
      git submodule update --init extern/cereal extern/google-test extern/google-benchmark

2. Create a feature branch from an up-to-date ``main``:

   .. code:: bash

      git fetch upstream
      git checkout -b my-feature upstream/main

3. Make your changes. Follow the :doc:`style guide <style_guide>`, add unit
   tests under ``tests/`` for new functionality and, where it helps, an example
   under ``examples/``.

4. Build and run the tests:

   .. code:: bash

      cmake -S . -B build -G Ninja
      cmake --build build
      ctest --test-dir build --output-on-failure

5. Commit with a descriptive message (a summary line of at most 72
   characters, a blank line, then details). Keep related changes in one commit
   and unrelated changes in separate commits, and do not commit build
   products. If the hooks modify files, review the changes with ``git diff``,
   ``git add`` them and commit again.

6. If ``main`` has moved on, rebase your branch onto it rather than merging
   (see :ref:`rebasing <rebasing>`), and push to your fork:

   .. code:: bash

      git push origin my-feature

7. Open a pull request against ``main`` of
   https://github.com/aeropittura/cipher. Reference the issue it addresses
   (``Fixes #123``). The :doc:`CI workflows <user_ci_cd_docs>` run
   automatically; resolve any failures they report.

Changes to the build system are described in
:ref:`Use of CMake in Cipher <cmake_in_cipher>`.

License
-------

Cipher is licensed under the BSD 2-Clause license (see ``LICENSE`` at the
repository root). By submitting a pull request you agree that your
contribution is released under the same license. Keep existing copyright
notices in the files you modify.

Upstream
--------

Cipher is derived from `OpenFHE <https://github.com/openfheorg/openfhe-development>`_.
Governance and contribution processes of the upstream OpenFHE project are
documented by the OpenFHE project itself. This document was originally modeled
on the contribution guide of the Cantera project.
