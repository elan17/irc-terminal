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
This module contains the mathematical functions needed for modern cryptography.
"""

import math
import random

_r2 = tuple(range(2)) # Used a lot.

def create_number(bit_length):
    """create_number(bit_length : int) -> int"""
    return random.randint(sqr_pow(2, (bit_length - 1)),
                          sqr_pow(2, bit_length) - 1)

def gcd(a, b):
    """
    gcd(a : int, b : int) -> int

    Use Euclid's algorithm to find the greatest common divisor.
    """
    if a > b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """
    extended_gcd(a : int, b : int) ->
    (gcd : int, x : int, y : int)

    Use Euclid's extended algorithm to find the greatest common divisor as well
    as x and y so that ax + by = gcd(a, b).
    """
    if b > a:
        a, b = b, a
    x = 0, 1
    y = 1, 0
    while b != 0:
        quotient = a // b
        a, b = b, a % b
        x = x[1] - quotient * x[0], x[0]
        y = y[1] - quotient * y[0], y[0]
    return a, x[1], y[1]

def inv_mod(a, m):
    """
    inv_mod(a : int, m : int) -> int

    Use Euclid's extended algorithm to find the modularly inverse number.
    """
    reverse = m > a
    if reverse:
        a, m = m, a
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('a and m are not coprime')
    elif reverse:
        return y % a
    else:
        return x % m

def integer_sqrt(n):
    """
    integer_sqrt(n : int) -> int

    Return the integer square root of n.
    """
    if n < 0:
        raise ValueError('number must be non-negative: \
cannot calculate complex square roots')
    if n == 0:
        return 0
    elif n < 4:
        return 1
    # We start by dividing with 2 <half of the bit length> times which should
    # give a number close to the square root.
    r = n >> (n.bit_length() >> 1)
    while r < n // r:
        r += 1
    while r * r > n:
        r -= 1
    return r

def log2(n):
    """
    log2(n : int) -> int

    Find the binary integer logarithm to n, so that 2^s = n.
    """
    return n.bit_length() - 1

def sqr_pow(n, exp, m=None):
    """
    sqr_pow(n : int, exp : int, m : int = None) -> int

    If m is None, calculate the power n**exp
    Else, calculate the power n**exp % m

    Use binary exponentiation.
    """
    if exp == 1:
        return n
    elif exp == 0:
        return 1
    elif exp < 1:
        raise ValueError('exponent must be non-negative')
    if m is None:
        return _sqr_pow(n, exp)
    else:
        return _mod_sqr_pow(n, exp, m)

def _sqr_pow(n, exp):
    o = n
    t = 2**(exp.bit_length() - 2)
    # We loop from the most import side through all bits (except for the first,
    # since that one can only be 1 and because of that does not have to be
    # checked). The places where the bit is 1 we multiply the temporary value
    # with the original value, and the new value is then going to be multiplied
    # by itself the rest of the way.
    while t != 0:
        n *= n
        if t & exp != 0:
            n *= o
        t >>= 1
    return n

def _mod_sqr_pow(n, exp, m):
    # We do the same as in _sqr_pow, except every calculation is modulo m. This
    # means that the result will always be lower than m.
    o = n = n % m
    t = 2**(exp.bit_length() - 2)
    while t != 0:
        n = (n * n) % m
        if t & exp != 0:
            n = (n * o) % m
        t >>= 1
    return n

def i2osp(n, l=None):
    """
    i2osp(n : int, l : int = ceil(log(n, 256))) -> bytes

    Convert n to a representation in bytes with l length.
    If l > ceil(log(n + 1, 256)), use leading zeros.
    """
    if l is None:
        l = math.ceil(math.log(n + 1, 256))
    else:
        assert n < sqr_pow(256, l), 'integer too large'
    b = bytearray(l)
    # Loop through the length of the bytes and divide the number continously.
    for i in range(l):
        b[-i - 1] = n % 256
        n >>= 8
    return bytes(b)

def os2ip(b):
    """
    os2ip(b : bytes) -> int

    Convert b to a integer representation.
    """
    if not b:
        return 0
    n = b[-1]
    t = 1
    # Loop through the bytes and multiply with 256**i.
    for x in b[-2::-1]:
        t *= 256
        n += x * t
    return n
