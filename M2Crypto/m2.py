from __future__ import absolute_import

"""M2Crypto low level OpenSSL wrapper functions.

m2 is the low level wrapper for OpenSSL functions. Typically you would not
need to use these directly, since these will be called by the higher level
objects you should try to use instead.

Naming conventions: All functions wrapped by m2 are all lower case,
words separated by underscores.

Examples:

OpenSSL                   M2Crypto

X509_get_version          m2.x509_get_version
X509_get_notBefore        m2.x509_get_not_before
X509_REQ_verify           m2.x509_req_verify

Exceptions to naming rules:

XXX TDB

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004 OSAF. All Rights Reserved.
"""
from M2Crypto.__m2crypto import SWIGVERSION

# BBB: Compatibility with swig less than 2.0.4. When build is done without
# '-builtin' option (available only with swig 2.0.4+), the use of _m2crypto
# causes NameError:
# NameError: name '_STACK__m2crypto' is not defined
# So I use the __m2crypto.
if SWIGVERSION < 0x20004:
    from M2Crypto.__m2crypto import *
else:
    from M2Crypto._m2crypto import *
lib_init()
