Cipher CI/CD Developers Guide
==============================

The `GitHub Actions documentation <https://docs.github.com/en/actions>`__ is
the reference for workflow syntax and features. This page describes how
Cipher's own workflows are organized and how to change them. The
:doc:`users guide <user_ci_cd_docs>` lists what each workflow does.

::

   ├── .github
   │   └── workflows
   │       ├── ci.yml      <-- build-and-test matrix
   │       └── lint.yml    <-- pre-commit hooks
   ├── .pre-commit-config.yaml   <-- hook list and pinned tool versions (used locally and by lint.yml)
   └── examples/standalone/CMakeLists.txt   <-- template exercised by the install check in ci.yml

Both workflows are ordinary files on the branch they run from; there are no
reusable workflows, custom actions or self-hosted runners. A pull request that
edits a workflow runs with the edited version, so changes can be tested in the
pull request itself.

Adding a build configuration
----------------------------

``ci.yml`` has a single job, ``build-and-test``, driven by a matrix of
``include`` entries. Each entry sets:

-  **os** - the GitHub-hosted runner image (pinned, e.g. ``ubuntu-24.04``)
-  **compiler** - ``gcc`` or ``clang``; the *Select compiler* step exports
   ``CC``/``CXX`` accordingly
-  **config** - a short name that appears in the job title
-  **cmake** - extra arguments appended to the configure step, typically
   ``CIPHER_*`` options from ``cmake/CipherOptions.cmake``

To test another configuration, add an entry, for example:

.. code:: yaml

   - { os: ubuntu-24.04, compiler: gcc, config: ntl, cmake: "-DCIPHER_WITH_NTL=ON -DCIPHER_MATH_BACKEND=6" }

and install whatever extra packages it needs in the *Install tools* step
(the Linux runners install ``ninja-build`` and ``libomp-dev``; macOS installs
``ninja``).

Changing the hooks
------------------

``lint.yml`` only runs ``pre-commit``; the hooks themselves and the versions of
``clang-format`` and ``cpplint`` are pinned in ``.pre-commit-config.yaml``.
Change the hooks there, then run ``pre-commit run --all-files`` locally and
commit any reformatting together with the version bump, since the lint job
checks the whole tree. Its cache key is derived from
``.pre-commit-config.yaml``, so a version change automatically invalidates
the cached tools.

Conventions
-----------

-  Pin runner images and action major versions rather than tracking
   ``latest``.
-  Fetch only the submodules a job needs (``extern/cereal``,
   ``extern/google-test``, ``extern/google-benchmark``) and configure with
   ``-DCIPHER_GIT_SUBMODULES=OFF`` so CMake does not touch them.
-  Keep the ``concurrency`` groups so that a new push cancels the superseded
   run of the same branch.
