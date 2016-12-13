#!/usr/bin/env python

"""Unit tests for M2Crypto.BIO.File.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

import os
import sys
import tempfile
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto.BIO import File, openfile


class FileTestCase(unittest.TestCase):

    def setUp(self):
        self.data = 'abcdef' * 64
        self.tmpfile = tempfile.NamedTemporaryFile(delete=False)
        self.fname = self.tmpfile.name

    def tearDown(self):
        try:
            os.unlink(self.fname)
        except OSError:
            pass

    def test_openfile_rb(self):
        # First create the file using Python's open().
        with open(self.fname, 'wb') as f:
            f.write(self.data)

        # Now open the file using M2Crypto.BIO.openfile().
        with openfile(self.fname, 'rb') as f:
            data = f.read(len(self.data))

        self.assertEqual(data, self.data)

    def test_openfile_wb(self):
        # First create the file using M2Crypto.BIO.openfile().
        with openfile(self.fname, 'wb') as f:
            f.write(self.data)

        # Now open the file using Python's open().
        with open(self.fname, 'rb') as f:
            data = f.read(len(self.data))

        self.assertEqual(data, self.data)

    def test_closed(self):
        f = openfile(self.fname, 'wb')
        f.write(self.data)
        f.close()
        with self.assertRaises(IOError):
            f.write(self.data)

    def test_use_pyfile(self):
        # First create the file.
        f = open(self.fname, 'wb')
        f2 = File(f)
        f2.write(self.data)
        f2.close()
        # Now read the file.
        with open(self.fname, 'rb') as f:
            data = f.read(len(self.data))
        self.assertEqual(data, self.data)

    def test_readline(self):
        with open(self.fname, 'w') as f:
            f.write('hello\nworld\n')
        with openfile(self.fname, 'r') as f:
            self.assertTrue(f.readable())
            self.assertEqual(f.readline(), 'hello')
            self.assertEqual(f.readline(), 'world')
        with openfile(self.fname, 'r') as f:
            self.assertEqual(f.readlines(), ['hello', 'world'])

    def test_tell_seek(self):
        with open(self.fname, 'w') as f:
            f.write('hello world')
        with openfile(self.fname, 'r') as f:
            # Seek absolute
            f.seek(6)
            self.assertEqual(f.tell(), 6)

def suite():
    # Python 2.2 warns that os.tmpnam() is unsafe.
    try:
        import warnings
        warnings.filterwarnings('ignore')
    except ImportError:
        pass
    return unittest.makeSuite(FileTestCase)


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())
