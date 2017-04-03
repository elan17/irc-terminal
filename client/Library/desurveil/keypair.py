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
The purpose of this module is to generate keys, encrypt, and decrypt.
"""

import math

from . import basemath as bmath
from . import misc
from . import oaep
from . import primes


def generate_keypair(bit_length, e=65537):
    """
    generate_keypair(bit_length : int, e : int = 65537)
      -> (RSAPublicKey, RSAPrivateKey)

    Generate a public key (n, e) and a private key (n, d) with bit length
    bit_length and public exponent e.
    """
    if bit_length < 16:
        # a) a bit length below 16 is not at all safe, b) probalistic primality
        # tests are unsafe at this limit, while brute force tests are still
        # slow, c) desurveil works best with bit lengths above or equal to 16.
        raise ValueError('bit length must be 16 or above')
    p_len = bit_length >> 1
    while True:
        # Pretty much follows the algorithm from the RSAES-OAEP Encryption
        # Scheme.
        p = primes.create_prime_number(p_len)
        q = primes.create_prime_number(bit_length - p_len)
        if p == q or bmath.gcd(e, p - 1) != 1 or bmath.gcd(e, q - 1) != 1:
            continue
        n = p * q
        if n.bit_length() != bit_length:
            continue
        phi = (p - 1) * (q - 1)
        d = bmath.inv_mod(e, phi)
        break

    pub = RSAPublicKey(n=n, e=e)
    priv = RSAPrivateKey(p=p, q=q, n=n, phi=phi, e=e, d=d)

    return pub, priv

class RSAKey:
    """
    This is the super class for RSA keys. This class is not meant to be called
    directly. It contains useful functions which can be utilized by both
    private and public keys.
    """
    def __init__(self, filename=None, data=None, encoding=None, **nums):
        self.numbers = {x: nums.get(x) for x in
                        ('e', 'd', 'p', 'q', 'n', 'phi')}
        if filename or data:
            self.decode(data, filename, encoding)
        self.get_lengths()

    def get_lengths(self):
        if self.numbers['n'] is not None:
            self.bit_length = self.numbers['n'].bit_length()
            self.byte_length = math.ceil(self.bit_length / 8)

    def format_number(self, name):
        a_str = bmath.i2osp(self.numbers[name])
        a_str_len = bmath.i2osp(len(a_str), 4)
        return a_str_len + a_str

    def encode_numbers(self, *nums):
        return b''.join(map(self.format_number, nums))

    def encode(self, filename=None, encoding='base64', *nums):
        """
        encode(filename : str = None, encoding : str = 'base64',
        *numkeys : [str]) -> bytes|None

        Format nums in a decodable way with encoding. If filename is not None,
        write data to file. Else return data.
        """
        data = self.encode_numbers(*nums)
        data = misc.encode(data, encoding)
        if filename is None:
            return data
        else:
            with open(filename, 'wb') as f:
                f.write(data)

    def decode_numbers(self, raw, *nums):
        for x in nums:
            p_len = bmath.os2ip(raw[:4])
            self.numbers[x] = bmath.os2ip(raw[4:p_len + 4])
            raw = raw[p_len + 4:]

    def decode(self, data=None, filename=None, encoding='base64',
               *nums):
        """
        decode(data : bytes = None, filename : str = None, encoding :
        str = None, *numkeys : [int])

        Deformat data and save the read numbers in the object (overwrite
        existing values).
        """
        if data is None:
            data = misc.byte_open_read(filename)
        elif isinstance(data, str):
            data = bytes(data, misc.preferred_encoding)
        data = misc.decode(data, encoding)
        self.decode_numbers(data, *nums)

class RSAPublicKey(RSAKey):
    """
    Public key
    """
    def basic_encrypt(self, m, req_len=None):
        return bmath.i2osp(bmath.sqr_pow(m, self.numbers['e'],
                                         self.numbers['n']), req_len)
    
    def encrypt(self, m, use_oaep=True, overflow=True):
        """
        encrypt(m : int|bytes|str, use_oaep : bool = True,
        use_overflow : bool = True) -> bytes

        Encrypt the data m. If use_oaep, encode the data with OAEP before
        encryption. If overflow, allow numbers of arbitrary size and allow
        bytes of arbitrary size, and encrypt all of the data in blocks that can
        be separated in decryption.
        """
        if isinstance(m, int):
            m_byt = None
        elif isinstance(m, str):
            m_byt = bytes(m, misc.preferred_encoding)
            m = None
        else:
            m_byt = m
            m = None
        assert (isinstance(m_byt, bytes) or m_byt is None) and \
            (isinstance(m, int) or m is None), 'wrong input'

        if m is None:
            m = bmath.os2ip(m_byt)

        if m_byt is None:
            m_byt = bmath.i2osp(m)

        if use_oaep:
            m_byt = oaep.encode(m_byt)
            oaep.decode(m_byt)
            m = bmath.os2ip(m_byt)

        if not overflow:
            assert 0 <= m < self.numbers['n'], 'message representative out of range'
            return self.basic_encrypt(m, None)

        # else:
        # Padding
        m_byt = b'\x01' + m_byt
        m_byt = bytes(self.byte_length - 1 - len(m_byt) % \
                          (self.byte_length - 1)) + m_byt
        f_byt = b''
        # We use chunks of <self.byte_length - 1> length, because there is a
        # risk that a number with {self.byte_length} > self.numbers['n']. If,
        # for example, we have an 18-bit modulus, self.byte_length is
        # 3. Modulus is at maximu 2**18 - 1, but our number can be as high as
        # 2**24 - 1.
        for i in range(0, len(m_byt), self.byte_length - 1):
            m_tmp = bmath.os2ip(m_byt[i:i + self.byte_length - 1])
            f_byt += self.basic_encrypt(m_tmp, self.byte_length)
        return f_byt

    def encode(self, filename=None, encoding='base64'):
        return RSAKey.encode(self, filename, encoding, 'n', 'e')

    def decode(self, data=None, filename=None, encoding='base64'):
        RSAKey.decode(self, data, filename, encoding, 'n', 'e')
        
class RSAPrivateKey(RSAPublicKey):
    def basic_decrypt(self, c, req_len=None):
        return bmath.i2osp(bmath.sqr_pow(c, self.numbers['d'],
                                         self.numbers['n']), req_len)
    
    def decrypt(self, c, use_oaep=True, overflow=True):
        """
        decrypt(c : int|bytes|str, use_oaep : bool = True,
        use_overflow : bool = True) -> bytes

        Decrypt the data c. If use_oaep, decode the data with OAEP after
        decryption. If overflow, remember earlier accept of numbers of
        arbitrary length and bytes of arbitrary length, and decode all of the
        data in blocks.
        """
        if isinstance(c, int):
            c_byt = None
        elif isinstance(c, str):
            c_byt = bytes(c, _pref_enc)
            c = None
        else:
            c_byt = c
            c = None
        assert (isinstance(c_byt, bytes) or c_byt is None) and \
            (isinstance(c, int) or c is None), 'wrong input'

        if not overflow:
            if c is None:
                c = bmath.os2ip(c_byt)
            assert 0 <= c < self.numbers['n'], \
                'ciphertext representative out of range'
            c = self.basic_decrypt(c)
            if use_oaep:
                c = oaep.decode(bmath.i2osp(c))
            return c

        # else:
        if c_byt is None:
            c_byt = bmath.i2osp(c)
        
        f_byt = b''
        for i in range(0, len(c_byt), self.byte_length):
            c_tmp = c_byt[i:i + self.byte_length]
            f_byt += self.basic_decrypt(bmath.os2ip(c_tmp),
                                        self.byte_length - 1)

        c_byt = f_byt[f_byt.find(b'\x01') + 1:]

        if use_oaep:
            c_byt = oaep.decode(c_byt)

        return c_byt

    def encode(self, filename=None, encoding='base64'):
        # We save the private key with all available data. Only (n, d) is
        # necessary, but having the rest as well can make some things
        # easier. And since the two first numbers are n and e, a private key
        # can also be used as its public key counterpart.
        return RSAKey.encode(self, filename,
                             encoding, 'n', 'e', 'd', 'p', 'q', 'phi')

    def decode(self, data=None, filename=None, encoding='base64'):
        RSAKey.decode(self, data, filename,
                      encoding, 'n', 'e', 'd', 'p', 'q', 'phi')

