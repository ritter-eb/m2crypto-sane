"""SSL Session

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

__all__ = ['Session', 'load_session']

from M2Crypto import BIO, Err, __m2crypto as m2
from M2Crypto.SSL import SSLError


class Session:

    m2_ssl_session_free = m2.ssl_session_free

    def __init__(self, session, _pyfree=0):
        assert session is not None
        self.session = session
        self._pyfree = _pyfree

    def __del__(self):
        if getattr(self, '_pyfree', 0):
            self.m2_ssl_session_free(self.session)

    def _ptr(self):
        return self.session

    def as_text(self):
        buf = BIO.MemoryBuffer()
        m2.ssl_session_print(buf.bio_ptr(), self.session)
        return buf.read_all()

    def as_der(self):
        buf = BIO.MemoryBuffer()
        m2.i2d_ssl_session(buf.bio_ptr(), self.session)
        return buf.read_all()

    def write_bio(self, bio):
        return m2.ssl_session_write_bio(bio.bio_ptr(), self.session)

    def get_time(self):
        return m2.ssl_session_get_time(self.session)

    def set_time(self, t):
        return m2.ssl_session_set_time(self.session, t)

    def get_timeout(self):
        return m2.ssl_session_get_timeout(self.session)

    def set_timeout(self, t):
        return m2.ssl_session_set_timeout(self.session, t)


def load_session(pemfile):
    with BIO.openfile(pemfile) as f:
        cptr = m2.ssl_session_read_pem(f.bio_ptr())
    if cptr is None:
        raise SSLError(Err.get_error())
    return Session(cptr, 1)
