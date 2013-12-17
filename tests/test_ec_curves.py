#!/usr/bin/env python
# XXX memory leaks
from __future__ import absolute_import

"""
    Unit tests for M2Crypto.EC, the curves

    There are several ways one could unittest elliptical curves
    but we are going to only validate that we are using the
    OpenSSL curve and that it works with ECDSA.  We will assume
    OpenSSL has validated the curves themselves.

    Also, some curves are shorter than a SHA-1 digest of 160
    bits.  To keep the testing simple, we will take advantage
    of ECDSA's ability to sign any digest length and create a
    digset string of only 48 bits.  Remember we are testing our
    ability to access the curve, not ECDSA itself.

    Copyright (c) 2006 Larry Bugbee. All rights reserved.

"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import EC, Rand


curves = [
    ('X9_62_prime256v1', 256),
    ('secp384r1', 384),
]

# The following two curves, according to OpenSSL, have a
# "Questionable extension field!" and are not supported by
# the OpenSSL inverse function.  ECError: no inverse.
# As such they cannot be used for signing.  They might,
# however, be usable for encryption but that has not
# been tested.  Until thir usefulness can be established,
# they are not supported at this time.
# curves2 = [
#    ('ipsec3', 155),
#    ('ipsec4', 185),
# ]


class ECCurveTests(unittest.TestCase):
    # data = sha.sha('Kilroy was here!').digest()     # 160 bits
    # keep short (48 bits) so lesser curves will work...  ECDSA requires
    # curve be equal or longer than digest
    data = "digest"

    def genkey(self, curve_name, curve_len):
        curve = getattr(EC, 'NID_' + curve_name)
        ec = EC.gen_params(curve)
        self.assertEqual(len(ec), curve_len)
        ec.gen_key()
        self.assertTrue(ec.check_key(),
                        'check_key() failure for "%s"' % curve_name)
        return ec

#    def check_ec_curves_genkey(self):
#        for curveName, curveLen in curves2:
#            self.genkey(curveName, curveLen)
#
#        self.assertRaises(AttributeError, self.genkey,
#                                          'nosuchcurve', 1)

    def sign_verify_ecdsa(self, curve_name, curve_len):
        ec = self.genkey(curve_name, curve_len)
        r, s = ec.sign_dsa(self.data)
        self.assertTrue(ec.verify_dsa(self.data, r, s))
        self.assertFalse(ec.verify_dsa(self.data, s, r))

    def test_ec_curves_ECDSA(self):
        for curveName, curveLen in curves:
            self.sign_verify_ecdsa(curveName, curveLen)

        with self.assertRaises(AttributeError):
            self.sign_verify_ecdsa('nosuchcurve', 1)

#        for curveName, curveLen in curves2:
#            with self.assertRaises(EC.ECError):
#                self.sign_verify_ecdsa(curveName, curveLen)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ECCurveTests))
    return suite


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
