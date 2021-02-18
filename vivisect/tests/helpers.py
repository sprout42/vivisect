import os
import unittest
import functools

import vivisect


class MockVw(object):
    def __init__(self, *args, **kwargs):
        self.psize = 4
        self._locs = {}

    def _addLocation(self, va, size, ltype, tinfo):
        self._locs[va] = (va, size, ltype, tinfo)

    def getLocation(self, va):
        return self._locs.get(va, None)


def getTestPath(*paths):
    '''
    Return the join'd path to a file in the vivtestfiles repo
    by using the environment variable "VIVTESTFILES"

    ( raises SkipTest if env var is not present )
    '''
    testdir = os.getenv('VIVTESTFILES')
    if not testdir:
        raise unittest.SkipTest('VIVTESTFILES env var not found!')

    return os.path.join(testdir, *paths)


@functools.lru_cache()
def getTestWorkspace(*paths):
    testdir = os.getenv('VIVTESTFILES')
    if not testdir:
        raise unittest.SkipTest('VIVTESTFILES env var not found!')
    fpath = os.path.join(testdir, *paths)
    vw = vivisect.VivWorkspace()

    if fpath.endswith('.viv'):
        vw.loadWorkspace(fpath)
    else:
        vw.loadFromFile(fpath)
        vw.analyze()
    return vw
