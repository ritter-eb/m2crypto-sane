from __future__ import absolute_import

"""M2Crypto wrapper for OpenSSL Error API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

from M2Crypto import BIO, m2, util  # noqa


def get_error():
    # type: () -> str
    err = BIO.MemoryBuffer()
    m2.err_print_errors(err.bio_ptr())
    return util.py3str(err.read())


def get_error_code():
    # type: () -> int
    return m2.err_get_error()


def peek_error_code():
    # type: () -> int
    return m2.err_peek_error()


def get_error_lib(err):
    # type: (int) -> bytes
    return m2.err_lib_error_string(err)


def get_error_func(err):
    # type: (int) -> bytes
    return m2.err_func_error_string(err)


def get_error_reason(err):
    # type: (int) -> bytes
    return m2.err_reason_error_string(err)


def get_x509_verify_error(err):
    # type: (int) -> bytes
    return m2.x509_get_verify_error(err)


class SSLError(Exception):
    def __init__(self, err, client_addr):
        # type: (int, util.AddrType) -> None
        self.err = err
        self.client_addr = client_addr

    def __str__(self):
        # type: () -> bytes
        if (isinstance(self.client_addr, unicode)):
            s = self.client_addr.encode('utf8')
        else:
            s = self.client_addr
        return "%s: %s: %s" % \
            (m2.err_func_error_string(self.err), s,
             m2.err_reason_error_string(self.err))


class M2CryptoError(Exception):
    pass
