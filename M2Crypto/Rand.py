from __future__ import absolute_import

"""M2Crypto wrapper for OpenSSL PRNG. Requires OpenSSL 0.9.5 and above.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

__all__ = ['dummyrand_set', 'dummyrand_restore', 'rand_seed',
           'rand_add', 'load_file', 'save_file', 'rand_bytes',
           'rand_pseudo_bytes']

from M2Crypto import m2
from typing import Optional  # noqa

rand_seed = m2.rand_seed  # type: (bytes) -> Optional[None]
rand_add = m2.rand_add  # type: (bytes, float) -> None
load_file = m2.rand_load_file  # type: (bytes, int) -> int
save_file = m2.rand_save_file  # type: (bytes) -> int
rand_bytes = m2.rand_bytes  # type: (int) -> Optional[bytes]
rand_pseudo_bytes = m2.rand_pseudo_bytes  # type: (int) -> Optional[tuple(bytes, int)]

dummyrand_seed = m2.dummyrand_seed  # type: (bytes, int) -> None
dummyrand_add = m2.dummyrand_add  # type: (bytes, int, float) -> None
dummyrand_bytes = m2.dummyrand_bytes  # type: (bytes, int) -> Optional[bytes]

dummyrand_set = m2.dummyrand_set  # type: () -> None
dummyrand_restore = m2.dummyrand_restore  # type: () -> None
