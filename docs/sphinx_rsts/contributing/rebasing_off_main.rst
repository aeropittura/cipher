.. _rebasing:

Rebasing
====================================

Work happens on feature branches that are submitted as pull requests to
``main``. When ``main`` moves on while your branch is open, rebase the branch
onto it so that your changes are tested against the current code before they
are merged.

Suppose you work on the branch ``issue-123`` in your fork, with ``upstream``
pointing at https://github.com/aeropittura/cipher:

1) Fetch the latest ``main`` and make sure your branch builds and its tests
   pass:

::

    git fetch upstream
    git checkout issue-123

2) Rebase: ``git rebase upstream/main``

- Commits are replayed onto ``main`` one by one and may conflict. Suppose
  there is a conflict in ``include/cipher/math/number_theory.h``: open the file,
  resolve the conflict and stage it with
  ``git add include/cipher/math/number_theory.h``.

3) Continue the rebase: ``git rebase --continue``

4) Repeat until the rebase is finished. Then build and run the tests once more
   (``cmake --build build && ctest --test-dir build``) and push the branch:

::

    git push --force-with-lease origin issue-123

.. note:: ``--force-with-lease`` is needed because the rebase rewrites the
   branch history; without it the push is declined.

The open pull request at https://github.com/aeropittura/cipher/pulls updates
automatically.
