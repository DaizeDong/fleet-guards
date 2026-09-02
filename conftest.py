"""Keep the kit's own 346 tests out of a CONSUMER's test run, without hiding them.

THE PROBLEM THIS SOLVES. Consumed as a submodule at <repo>/guards, this directory is an ordinary
subdirectory as far as pytest is concerned. A bare `pytest` at a consumer's root went from
collecting that repo's tests to collecting its tests plus all of the kit's. Measured on a fixture
repo with one test: 1 collected before adding the submodule, 347 after.

That is not merely slow. Several repos in this fleet gate on a MINIMUM TEST COUNT, precisely so a
suite that stopped being collected cannot pass quietly. Silently adding 346 tests to every one of
those counts is the same defect from the other side: the floor is met by tests that say nothing
about the repo being gated, and a consumer's suite could rot away underneath a number that still
looks healthy.

WHY THE FIX LIVES HERE. The alternative is `norecursedirs = guards` in every consumer's pytest
config. That is 23 edits that must be repeated in every repo created afterwards, and the one that
forgets gets no error, just a number that quietly means something else. One file, shipped with the
thing that causes the problem, is the same reasoning as the rest of this kit.

IT IS NOT A HIDE. Ask for these tests by path and you get them:
    pytest guards/tools/            -> the kit's suite runs, from the consumer, on the pinned commit
That path is exactly what a consumer's CI uses to prove the commit it PINNED still passes here,
which is a different question from whether it passed in this repo's own CI at some other commit.
Running pytest inside the kit itself is likewise untouched.
"""
import os


def _asked_for_explicitly(config):
    """True when some invocation argument points into this directory.

    The discriminator is the ARGUMENT, not the rootdir: a consumer running `pytest guards/tools/`
    still has the consumer as rootdir, so rootdir alone cannot tell "swept up incidentally" from
    "asked for by name", and getting that backwards would break the one command consumers use to
    verify their pinned commit.
    """
    here = os.path.realpath(os.path.dirname(__file__))
    for a in config.invocation_params.args:
        p = os.path.realpath(os.path.abspath(str(a).split("::", 1)[0]))
        if p == here or p.startswith(here + os.sep):
            return True
    # Invoked from inside the kit with no path argument at all.
    return os.path.realpath(config.invocation_params.dir) == here


def pytest_ignore_collect(collection_path, config):
    if _asked_for_explicitly(config):
        return None                      # defer to pytest's normal rules
    return True
