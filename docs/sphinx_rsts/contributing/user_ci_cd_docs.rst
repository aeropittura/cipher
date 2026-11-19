Cipher CI/CD Users Guide
=========================

Introduction
------------

Cipher uses GitHub Actions at https://github.com/aeropittura/cipher. Two
workflows live in the repository:

::

   ├── .github
   │   └── workflows
   │       ├── ci.yml      <-- build, unit tests and install check on Linux and macOS
   │       └── lint.yml    <-- pre-commit hooks (clang-format, cpplint, ...) over the whole tree

Both run on GitHub-hosted runners; there are no self-hosted runners.

CI workflow (ci.yml)
--------------------

Runs on every pull request, on every push to ``main``, and on demand
(``workflow_dispatch``). A newer run on the same branch cancels an older one
that is still in progress.

Every job fetches the ``cereal``, ``google-test`` and ``google-benchmark``
submodules, configures with Ninja and ``-DCIPHER_GIT_SUBMODULES=OFF
-DCIPHER_BUILD_EXTRAS=ON`` plus the job's extra options, builds, runs
``ctest --test-dir build --output-on-failure``, installs the library and
builds a small program against the install with the template in
``examples/standalone/CMakeLists.txt``.

+--------------+--------------+----------+------------------------------------------------------------------------+
| Runner       | Compiler     | Config   | Extra CMake options                                                    |
+==============+==============+==========+========================================================================+
| ubuntu-24.04 | gcc          | default  |                                                                        |
+--------------+--------------+----------+------------------------------------------------------------------------+
| ubuntu-24.04 | clang        | default  |                                                                        |
+--------------+--------------+----------+------------------------------------------------------------------------+
| ubuntu-24.04 | gcc          | backend2 | ``-DCIPHER_MATH_BACKEND=2 -DCIPHER_WITH_BE4=ON``                       |
+--------------+--------------+----------+------------------------------------------------------------------------+
| ubuntu-24.04 | gcc          | native128| ``-DCIPHER_NATIVE_SIZE=128``                                           |
+--------------+--------------+----------+------------------------------------------------------------------------+
| ubuntu-24.04 | gcc          | static-  | ``-DCIPHER_BUILD_STATIC=ON -DCIPHER_BUILD_SHARED=OFF                   |
|              |              | debug    | -DCMAKE_BUILD_TYPE=Debug``                                             |
+--------------+--------------+----------+------------------------------------------------------------------------+
| macos-15     | clang        | default  | ``-DCIPHER_WITH_OPENMP=OFF``                                           |
+--------------+--------------+----------+------------------------------------------------------------------------+

Lint workflow (lint.yml)
------------------------

Runs on pull requests and pushes to ``main`` (and ``dev``). It installs
``pre-commit`` and runs ``pre-commit run --all-files --show-diff-on-failure``,
i.e. the same hooks as ``.pre-commit-config.yaml`` installs locally. When it
fails, the log shows the exact changes the hooks would make; running
``pre-commit run --all-files`` (or ``tools/format.sh``) locally applies them.

Running a workflow manually
---------------------------

The CI workflow can be started for any branch from the GitHub web interface:
open the repository's **Actions** tab, select **CI** on the left, click
**Run workflow**, pick the branch and confirm. With the GitHub CLI the same is
``gh workflow run ci.yml --ref <branch>``.

Reproducing a CI job locally
----------------------------

.. code:: bash

   git submodule update --init extern/cereal extern/google-test extern/google-benchmark
   cmake -S . -B build -G Ninja -DCIPHER_GIT_SUBMODULES=OFF -DCIPHER_BUILD_EXTRAS=ON <extra options from the table>
   cmake --build build
   ctest --test-dir build --output-on-failure
