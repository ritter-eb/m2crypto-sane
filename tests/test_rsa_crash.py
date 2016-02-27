# heavily based on https://gist.github.com/eskil/2338529
import time
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import ASN1, EVP, RSA, X509


class TestRSASignedCertCrash(unittest.TestCase):
    def create_rsa_key(self, bits=1024):
        rsa = RSA.gen_key(bits, 65537, lambda: None)
        return rsa

    def create_self_signed_cert(self, rsa, subject=None, san=None):
        """ Creates a self-signed cert
            Pass in an RSA private key object
            Pass in a dict of subject name data, using C ST L O OU CN keys
            Pass in an optional san like 'DNS:example.com'
            Returns a X509.X509 object
        """
        if subject is None:
            subject = {'CN': 'Testing'}

        pk = EVP.PKey()
        pk.assign_rsa(rsa)

        name = X509.X509_Name()
        for key in ['C', 'ST', 'L', 'O', 'OU', 'CN']:
            if subject.get(key, None):
                setattr(name, key, subject[key])

        cert = X509.X509()
        cert.set_serial_number(1)
        cert.set_version(2)
        t = long(time.time())
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)
        expire = ASN1.ASN1_UTCTIME()
        expire.set_time(t + 365 * 24 * 60 * 60)
        cert.set_not_before(now)
        cert.set_not_after(expire)
        cert.set_issuer(name)
        cert.set_subject(name)
        cert.set_pubkey(pk)
        cert.add_ext(X509.new_extension('basicConstraints', 'CA:FALSE'))
        if san:
            cert.add_ext(X509.new_extension('subjectAltName', san))
        cert.add_ext(X509.new_extension('subjectKeyIdentifier',
                     cert.get_fingerprint()))
        cert.sign(pk, 'sha1')
        return cert

    def test_rsa_signed_cert_crash(self):
        for y in range(0, 10):
            for x in range(0, 20):
                key = self.create_rsa_key(bits=256)
                self.create_self_signed_cert(key, {'CN': 'Test'})

        # If we get here without crash, we are good.
        self.assertTrue(True)
