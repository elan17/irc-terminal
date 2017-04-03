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
This module contains functions related to prime numbers.
"""

import math
import random
from . import basemath as bmath

def create_prime_number(bit_length):
    """
    create_prime_number(bit_length : int) -> int
    """
    if bit_length <= 24:
        prime_test = lambda n: is_prime_brute(n)
    else:
        prime_test = lambda n: is_probably_prime(n)
    while True:
        # Keep testing for primality until a prime number is found.
        n = bmath.create_number(bit_length)
        n -= n % 6 - 1
        m = 4
        while not prime_test(n):
            n += m
            m = m == 4 and 2 or 4
        if n.bit_length() == bit_length:
            break
    return n

def is_prime_brute(n):
    """
    is_prime_brute(n : int) -> bool

    Poor, brute force, deterministic primality test.
    """
    if n == 2 or n == 3:
        return True
    elif n < 2 or n & 1 == 0 or n % 3 == 0:
        return False
    i = 5
    m = 2
    while i < bmath.integer_sqrt(n) + 1:
        if n % i == 0:
            return False
        i += m
        m = m == 2 and 4 or 2
    return True

def is_probably_prime(n):
    """
    is_probably_prime(n : int) -> bool

    Probalistic primality test starter.
    """
    if n == 2 or n == 3:
        return True
    elif n < 2 or n & 1 == 0:
        return False
    # Fermats test er hurtig men dårlig; dog er den altid korrekt hvis
    # den påstår et tal ikke er et primtal. Hvis den siger at et tal
    # måske er et primtal, tester vi yderligere med en bedre
    # probalistisk tester.
    if test_prime_fermat(n):
        return test_prime_rabin_miller(n)

def test_prime_fermat(n):
    """
    test_prime_fermat(n : int) -> bool

    Test if n is perhaps prime. Using Fermat's little theorem, return True if n
    is either prime or composite, return False if n is composite.
    """
    return bmath.sqr_pow(random.randint(1, n - 1), n - 1, n) == 1

def test_prime_rabin_miller(n, precision=None):
    """
    test_prime_rabin_miller(n : int, precision : int = lookup(n)) -> bool

    Use the Rabin-Miller primality test. Risk of failure is less than 2**(-80).
    """
    l = n.bit_length()
    if precision is None:
        # Based on limits found in
        # http://cvs.openssl.org/getfile/openssl/crypto/bn/bn.h
        precision = l >= 1300 and 2 or ( \
            l >= 850 and 3 or ( \
            l >= 650 and 4 or ( \
            l >= 550 and 5 or ( \
            l >= 450 and 6 or ( \
            l >= 400 and 7 or ( \
            l >= 350 and 8 or ( \
            l >= 300 and 9 or ( \
            l >= 250 and 12 or ( \
            l >= 200 and 15 or ( \
            l >= 150 and 18 or ( \
            l >= 100 and 27 or 39)))))))))))

    # The following code is based on the algorithm found in the article
    # "Primality Tests Based on Fermat's Little Theorem" by Manindra Agrawal.
    n1 = n - 1
    s = 1
    n1t = n1 >> 1
    while not n1t & 1:
        n1t >>= 1
        s += 1
    d = n1 // bmath.sqr_pow(2, s)

    for i in range(precision):
        a = random.randint(1, n1)
        x = bmath.sqr_pow(a, d, n)
        foreign_values = x != 1
        prev_x = None
        for j in range(s):
            if prev_x == n1 and x == 1:
                break
            prev_x = x
            x = (x * x) % n
            if x != 1:
                foreign_values = True
        if prev_x == n1 and x == 1:
            continue
        elif foreign_values:
            return False
    return True
