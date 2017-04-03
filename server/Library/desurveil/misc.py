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
This module contains miscellaneous shortcut functions and values, making some
things easier.
"""

import sys
import os
import locale
import base64

from . import basemath as bmath

class AttributeDict:
    """A dictionary where x.a == x['a']"""
    def __init__(self, **kwds):
        self._dict = dict(**kwds)
        self.update_attributes()

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, val):
        self._dict[key] = val
        self.__setattr__(key, val)

    def update_attributes(self):
        for key, val in self._dict.items():
            self.__setattr__(key, val)

class PeriodTextTuple(tuple):
    def __init__(self, *args):
        self.text = '.'.join(str(x) for x in self)
        
    def __new__(self, *args):
        return tuple.__new__(self, args)

program = AttributeDict()
program.name = 'desurveil'
program.version = PeriodTextTuple(0, 1, 1)
program.description = 'a cryptography tool with support for RSA and OAEP'
program.author = 'Niels Serup'
program.author_email = 'ns@metanohi.org'
program.url = 'http://metanohi.org/projects/desurveil/'
program.copyright = 'Copyright (C) 2011  Niels Serup'
program.short_license_name = 'AGPLv3+'
program.short_license = '''\
License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.'''
program.version_info = '{} {}\n{}\n{}'.format(
    program.name, program.version.text,
    program.copyright, program.short_license)


r2 = tuple(range(2))
preferred_encoding = locale.getpreferredencoding()
e2_32 = bmath.sqr_pow(2, 32)

default_private_key_path_short = '~/.desurveil_id_rsa'
default_private_key_path = os.path.expanduser(
    default_private_key_path_short)
default_public_key_path_short = '~/.desurveil_id_rsa.pub'
default_public_key_path = os.path.expanduser(
    default_public_key_path_short)

# Open sys.stdout og sys.stdin as bytes
byte_out = open(1, 'wb', closefd=False)
byte_in = open(0, 'rb', closefd=False)

def byte_open_read(filename):
    """
    byte_open_read(filename : str) -> bytes

    Opens and reads bytes from the file. If the filename is '-' sys.stdin is
    used.
    """
    if filename == '-':
        return byte_in.read()
    elif filename is not None:
        with open(filename, 'rb') as f:
            return f.read()

def byte_open_write(filename, text):
    """
    byte_open_write(filename : str, text: bytes)

    Opens and writes byte to the file. If the filename is '-' sys.stdout is
    used.
    """
    if filename == '-':
        byte_out.write(text)
    elif filename is not None:
        with open(filename, 'wb') as f:
            f.write(text)

def state(msg, **kwds):
    """
    state(msg : str, print_kwarg=val, ...)

    Print a message with 'desurveil: ' prefixed.
    """
    print('desurveil: ' + msg, **kwds)

def state_begin(msg):
    """
    state_begin(msg : str)

    Begin a statement.
    """
    state(msg, end='')
    sys.stdout.flush()

def state_done():
    """
    state_end()

    End a statement started by state_begin().
    """
    print('done')

def encode(data, encoding=None):
    """
    encode(data : bytes, encoding : str = None)

    Encode data as base64, decimal, or hex.
    """
    if encoding == 'base64':
        return base64.b64encode(data)
    elif encoding in ('decimal', 'hex'):
        # If data starts with \0 bytes, prepend them to the encoding.
        num = bmath.os2ip(data)
        zeros = (len(data) - len(data.lstrip(b'\x00'))) * b'0'
        if encoding == 'decimal':
            return zeros + bytes(str(num), 'ascii')
        elif encoding == 'hex':
            return zeros + bytes(hex(num)[2:], 'ascii')
    else:
        return data

def decode(data, encoding=None):
    """
    decode(data : bytes, encoding : str = None)

    Decode encoded data as base64, decimal, or hex.
    """
    if encoding == 'base64':
        return base64.b64decode(data)
    elif encoding in ('decimal', 'hex'):
        # Same as in encoding, just the other way round.
        zeros = (len(data) - len(data.lstrip(b'0'))) * b'\x00'
        if encoding == 'decimal':
            return zeros + bmath.i2osp(int(data))
        elif encoding == 'hex':
            return zeros + bmath.i2osp(int(data, base=16))
    else:
        return data
