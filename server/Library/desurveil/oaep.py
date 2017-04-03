#!/usr/bin/env python3

# desurveil: a cryptography tool with support for RSA and OAEP
# Copyright (C) 2011 Niels Serup

# This file is part of desurveil.
#
# desurveil is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# desurveil is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
# details.
#
# You should have received a copy of the GNU Affero General Public License
# along with desurveil.  If not, see <http://www.gnu.org/licenses/>.

"""
This module contains OAEP-related functions.
"""

import hashlib
import math
import operator
import random

from . import basemath as bmath
from . import misc

_hash_func = hashlib.sha256 # A fairly reasonable choice.

def hash_digest(m=b''):
    return _hash_func(m).digest()

## The length of the output from the hash function.
_b_len = _hash_func().digest_size
_p_hash = hash_digest()


def mgf(seed, o_len):
    """
    mgf(seed : bytes, o_len : int) -> bytes

    Generate and return a mask.
    """
    assert o_len <= misc.e2_32 * _b_len, 'mask too long'
    t = b''
    for i in range(math.ceil(o_len / _b_len)):
        t += hash_digest(seed + bmath.i2osp(i, 4))
    return t[:o_len]

def bytes_xor(strip=True, *b):
    """
    bytes_xor(strip : bool = True, bytes, bytes) -> bytes

    Use XOR on the two byte strings. If strip, remove all leading zeros from
    the final string.
    """
    bl = tuple(map(len, b))
    min_len = min(*bl)
    be = tuple(len(b[i]) - min_len for i in range(2))
    if be[0] > be[1]:
        bs = b[0][:be[0]]
    else:
        bs = b[1][:be[1]]
    bs += bytes(map(lambda ns: operator.xor(*ns),
                    (((b[j][i + be[j]] for j in misc.r2))
                     for i in range(min_len))))
    if strip:
        bs = bs.lstrip(b'\x00')
    return bs

def basic_encode(m, em_len=None):
    """
    basic_encode(m : bytes, em_len : int = minimum) -> bytes

    Create and return an OAEP-encoded byte string with the length em_len of the
    data m.
    """
    m_len = len(m)
    if em_len is None:
        em_len = 2 * _b_len + 33 # Minimum, allows for up to 32 bytes
                                 # (byte no. 33 marks a separation)
    else:
        assert em_len > 2 * _b_len, 'intended message length too small'
    assert m_len <= em_len - 2 * _b_len - 1, 'message too long'
    ps = (em_len - m_len - 2 * _b_len - 1) * b'\x00'
    db = _p_hash + ps + b'\x01' + m
    seed = bytes(random.randint(0, 255) for i in range(_b_len))
    db_mask = mgf(seed, em_len - _b_len)
    masked_db = bytes_xor(False, db, db_mask)
    seed_mask = mgf(masked_db, _b_len)
    masked_seed = bytes_xor(False, seed, seed_mask)
    em = masked_seed + masked_db
    return em

def encode(m):
    """
    encode(m : bytes) -> bytes

    OAEP-encode m without padding by calculating the required length for the
    encoded byte string before OAEP-encoding.
    """
    return basic_encode(m, 2 * _b_len + 1 + len(m))

def decode(em):
    """
    decode(em : bytes) -> bytes

    OAEP-decode data em.
    """
    em_len = len(em)
    masked_seed = em[:_b_len]
    masked_db = em[_b_len:]
    seed_mask = mgf(masked_db, _b_len)
    seed = bytes_xor(False, masked_seed, seed_mask)
    db_mask = mgf(seed, em_len - _b_len)
    db = bytes_xor(False, masked_db, db_mask)
    p_hash_from_db = db[:_b_len]
    assert p_hash_from_db == _p_hash, 'decoding error'
    ps_sep_found = db.find(b'\x01', _b_len)
    assert ps_sep_found != -1, 'decoding error'
    m = db[ps_sep_found + 1:]
    return m
