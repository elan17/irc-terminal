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
This module contains classes and functions targeted at interfacing
(especially via the command line) with key generation, encryption, and
decryption.
"""

import os
import sys
from optparse import OptionParser, OptionGroup

from . import keypair as kp
from . import misc
from . import oaep


class Utility:
    """
    Makes it possible to call cryptography functions with
    understandable text output based on keyword arguments.
    """
    def __init__(self, **kwds):
        # Look at the bottom of this file to find out what keywords
        # are usable.
        self.o = misc.AttributeDict(**kwds)

    def run(self):
        if self.o.command == 'key':
            self._generate_keypair()
        elif self.o.command == 'encrypt':
            self._encrypt()
        elif self.o.command == 'decrypt':
            self._decrypt()

    # The following subfunctions contain a lot of code whose purpose
    # is to present many possibilities to the user and to output
    # coherent messages.
    def _generate_keypair(self):
        misc.state_begin('generating key pair...')
        pub, priv = kp.generate_keypair(self.o.bit_length,
                                        self.o.public_exponent)
        misc.state_done()
        if self.o.output_decimal:
            enc = 'decimal'
        elif self.o.output_hex:
            enc = 'hex'
        elif self.o.output_raw:
            enc = None
        else:
            enc = 'base64'

        if self.o.public_key_output_file != '-':
            pub.encode(filename=self.o.public_key_output_file,
                       encoding=enc)
            misc.state('saving public key in {}'.format(
                    repr(self.o.public_key_output_file)))
        else:
            if enc:
                print(str(pub.encode(encoding=enc), 'ascii'))
            else:
                misc.byte_out.write(pub.encode(encoding=enc))

        if self.o.private_key_output_file != '-':
            priv.encode(filename=self.o.private_key_output_file,
                        encoding=enc)
            misc.state('saving private key in {}'.format(
                    repr(self.o.private_key_output_file)))
        else:
            if enc:
                print(str(priv.encode(encoding=enc), 'ascii'))
            else:
                misc.byte_out.write(priv.encode(encoding=enc))

    def _get_key_enc(self):
        if self.o.key_input_decimal:
            key_enc = 'decimal'
        elif self.o.key_input_hex:
            key_enc = 'hex'
        elif self.o.key_input_raw:
            key_enc = None
        else:
            key_enc = 'base64'

        return key_enc

    def _encrypt(self):
        if self.o.inline_data is not None:
            data = bytes(self.o.inline_data, misc.preferred_encoding)
        else:
            data = misc.byte_open_read(self.o.data_file)

        if self.o.input_decimal:
            enc = 'decimal'
        elif self.o.input_hex:
            enc = 'hex'
        elif self.o.input_base64:
            enc = 'base64'
        else:
            enc = None

        data = misc.decode(data, enc)

        if self.o.use_rsa:
            key_enc = self._get_key_enc()
            if self.o.key_inline_data is not None:
                pub = kp.RSAPublicKey(data=self.o.key_inline_data,
                                      encoding=key_enc)
            else:
                pub = kp.RSAPublicKey(filename=self.o.key_data_file,
                                      encoding=key_enc)
            encrypted = pub.encrypt(data, self.o.use_oaep,
                                    self.o.use_overflow)
        elif self.o.use_oaep:
            encrypted = oaep.encode(data)
        
        if self.o.output_decimal:
            enc = 'decimal'
        elif self.o.output_hex:
            enc = 'hex'
        elif self.o.output_raw:
            enc = None
        else:
            enc = 'base64'

        encrypted = misc.encode(encrypted, enc)
        misc.byte_open_write(self.o.output_file, encrypted)

    def _decrypt(self):
        if self.o.inline_data is not None:
            data = bytes(self.o.inline_data, misc.preferred_encoding)
        else:
            data = misc.byte_open_read(self.o.data_file)

        if self.o.input_decimal:
            enc = 'decimal'
        elif self.o.input_hex:
            enc = 'hex'
        elif self.o.input_raw:
            enc = None
        else:
            enc = 'base64'
        data = misc.decode(data, enc)

        if self.o.use_rsa:
            key_enc = self._get_key_enc()
            if self.o.key_inline_data is not None:
                pub = kp.RSAPrivateKey(data=self.o.key_inline_data,
                                       encoding=key_enc)
            else:
                pub = kp.RSAPrivateKey(filename=self.o.key_data_file,
                                       encoding=key_enc)
            decrypted = pub.decrypt(data, self.o.use_oaep,
                                    self.o.use_overflow)
        elif self.o.use_oaep:
            decrypted = oaep.decode(data)
        
        if self.o.output_decimal:
            enc = 'decimal'
        elif self.o.output_hex:
            enc = 'hex'
        elif self.o.output_base64:
            enc = 'base64'
        else:
            enc = None

        decrypted = misc.encode(decrypted, enc)
        misc.byte_open_write(self.o.output_file, decrypted)
        
def _add_option(self, *args, **kwds):
    try:
        kwds['help'] = kwds['help'].strip()
    except KeyError:
        pass
    return OptionGroup.add_option(self, *args, **kwds)

class _SimplerOptionGroup(OptionGroup):
    """A simplified OptionGroup"""

    add_option = _add_option
    
class _SimplerOptionParser(OptionParser):
    """A simplified OptionParser"""

    add_option = _add_option
    
    def format_description(self, formatter):
        return self.description

    def format_epilog(self, formatter):
        return self.epilog

    def add_option_group(self, *args):
        group = _SimplerOptionGroup(self, *args)
        OptionParser.add_option_group(self, group)
        return group

    def error(self, msg, only_error=False):
        if only_error:
            print('desurveil: error: {}'.format(msg), file=sys.stderr)
        else:
            OptionParser.error(self, msg)

def command_line_entry(args=None):
    """
    command_line_entry(args: [str] = sys.argv[1:]) -> Utility

    Base actions on input from the command line. Create an Utility
    object from the given options.
    """
    if args is None:
        args = sys.argv[1:]
    parser = _SimplerOptionParser(
        prog=misc.program.name,
        usage='Usage: %prog COMMAND [OPTION]... [INPUT FILE]...',
        version=misc.program.version_info,
        description=misc.program.description,
        epilog='''
There are three commands: key, encrypt, and decrypt. Options:

  desurveil key [-t bit length] [-d|-x|-r]
  [-l <output file for public key>] [-a <output file for private key>]

  desurveil encrypt|decrypt [--no-oaep|--no-rsa] [--no-overflow]
  [-d|-x|-b|-r] [-o <output file>] {-D|-X|-B|-R} {filename|-i inline data}
  {-E|-Y|-C|-S} {filename for key|-I inline key data}

When encrypting, a public key is required (default: %s),
and when decrypting, a private key is required (default: %s).
A private key can be used as a public key (all necessary information
is stored in it).

Examples:

  Make a key pair (will be 1024-bit and saved in the default path):
    desurveil key

  Encrypt a file with RSA, OAEP and overflow
  (uses the newly generated public key):
    desurveil encrypt a_file -o a_file-encrypted

  Decrypt a file with RSA, OAEP and overflow (uses the private key)
  ('a_file-new' gets precisely the same contents as 'a_file'):
    desurveil decrypt a_file-encrypted -o a_file-new

  Encrypt and decrypt a number with only RSA, without OAEP and
  overflow:
    desurveil encrypt -i 57 -D -P -W | desurveil decrypt -d -P -W

  Encrypt a hexadecimal number, and save it as raw bytes:
    desurveil encrypt -X -i A4D2 -r -o encrypted_file

  Encrypt 3 times:
    desurveil encrypt -i Hej -r | desurveil encrypt -r | desurveil \\
        encrypt -o triple_encrypted

  Decrypt 3 times:
    desurveil decrypt triple_encrypted | desurveil decrypt -R | \\
        desurveil decrypt -R

  Make a 1337-bit key pair and save the keys in hex:
    desurveil key -t 1337 -l pubhex -a privhex -x

  Encrypt and decrypt with the hex keys:
    desurveil encrypt -Y -i TEST pubhex | desurveil decrypt -Y -privhex

  Use only OAEP and return the encoded data as a decimal number (no
  security):
    desurveil encrypt -A -i "another test" -d
''' % (misc.default_public_key_path_short,
       misc.default_private_key_path_short))
    general_group = parser.add_option_group('General options')
    key_group = parser.add_option_group(
        'Key related options (command: key)')
    crypt_group = parser.add_option_group(
        'Encryption/decryption related options (command: encrypt|decrypt)')
    crypt_data_group = parser.add_option_group(
        'Options for input of data')
    crypt_key_group = parser.add_option_group(
        'Options for input of key data')

    general_group.add_option('-o', '--output', dest='output_file',
                             metavar='FILENAME', help='''

the name of the file that output should be written to (in the case of keypair
generation this option cannot be used as two outputs are necessary) (default: -
(standard out)

''', default='-')
    general_group.add_option('-d', '--output-decimal',
                             dest='output_decimal', action='store_true',
                             help='output data as number in base 10')
    general_group.add_option('-x', '--output-hex', dest='output_hex',
                             action='store_true',
                             help='output data as number in base 16')
    general_group.add_option('-b', '--output-base64', dest='output_base64',
                             action='store_true', help='''output data
in base64-kode (default when generating keys and encrypting)''')
    general_group.add_option('-r', '--output-raw', dest='output_raw',
                             action='store_true',
                             help='''

output data as raw byte data (default when decrypting)

''')
    key_group.add_option('-t', '--bit-length', dest='bit_length',
                         metavar='INTEGER', help='''

the number of bits to use for your key (default: 1024)

''',
                         type='int', default=1024)
    key_group.add_option('-e', '--public-exponent',
                         dest='public_exponent', metavar='INTEGER',
                         help='''

the exponent of the public key (default: 65537)

''', type='int', default=65537)
    key_group.add_option('-l', '--public-key-output',
                         dest='public_key_output_file',
                         metavar='FILENAME', help='''

the name of the file that output from the public key generation should be
written to (default: {})

'''.format(misc.default_public_key_path_short),
                         default=misc.default_public_key_path)
    key_group.add_option('-a', '--private-key-output',
                         dest='private_key_output_file',
                         metavar='FILENAME',
                         help='''

the name of the file that output from the private key generation should be
written to (default: {})

'''.format(misc.default_private_key_path_short),
                         default=misc.default_private_key_path)

    crypt_group.add_option('-P', '--no-oaep', dest='use_oaep',
                         action='store_false', default=True,
                         help='do not use Optimal Asymmetric Encryption Padding')
    crypt_group.add_option('-A', '--no-rsa', dest='use_rsa',
                         action='store_false', default=True,
                         help='do not use RSA')
    crypt_group.add_option('-W', '--no-overflow', dest='use_overflow',
                         action='store_false', default=True,
                         help='''

do not use overflow (turning this off might mean that one's data is too long
for RSA to encrypt and decrypt it.

''')

    crypt_data_group.add_option('-i', '--inline-data',
                                dest='inline_data',
                                metavar='DATA', help='''

specify data directly instead of from a file

''')
    crypt_data_group.add_option('-D', '--input-decimal',
                                dest='input_decimal',
                                action='store_true',
                                help='<en/de>crypt data from number in base 10')
    crypt_data_group.add_option('-X', '--input-hex', dest='input_hex',
                                action='store_true',
                                help='<en/de>crypt data from number in base 16')
    crypt_data_group.add_option('-B', '--input-base64',
                                dest='input_base64',
                                action='store_true',
                                help='''

Encrypt and decrypt data from base64-encoded data (default when decrypting)

''')
    crypt_data_group.add_option('-R', '--input-raw', dest='input_raw',
                                action='store_true',
                                help='''

Encrypt and decrypt data from raw byte data (default when encrypting)

''')
    crypt_key_group.add_option('-I', '--key-inline-data',
                               dest='key_inline_data',
                               metavar='KEYDATA', help='''

specify key data directly instead of from a file

''')
    crypt_key_group.add_option('-E', '--key_input-decimal',
                               dest='key_input_decimal',
                               action='store_true', help='''

read key data as a number in base 10

''')
    crypt_key_group.add_option('-Y', '--key-input-hex',
                               dest='key_input_hex',
                               action='store_true', help='''

read key data as a number in base 16

''')
    crypt_key_group.add_option('-C', '--key-input-base64',
                               dest='key_input_base64',
                               action='store_true', help='''

read key data from base64-encoded data (default)

''')
    crypt_key_group.add_option('-S', '--key-input-raw',
                               dest='key_input_raw',
                               action='store_true',
                               help='read key data from raw byte data')

    options, args = parser.parse_args(args)
    if not args:
        parser.print_help()
        print()
        parser.error('no commando specified', True)
        sys.exit(1)

    options.command = args[0]
    args = args[1:]
    if options.command not in ('key', 'decrypt', 'encrypt'):
        parser.error('command {} unknown'.format(options.command))
    if options.command != 'key':
        if not options.inline_data:
            if not args:
                options.data_file = '-'
            else:
                options.data_file = args[0]
                args = args[1:]
        if options.use_rsa and not options.key_inline_data:
            if not args and ((options.command == 'decrypt' and not
                              os.path.isfile(
                        misc.default_private_key_path)) or (
                    options.command == 'encrypt' and not
                    os.path.isfile(misc.default_public_key_path))):
                parser.error('no key data specified \
(did you remember to generate a key?)')
            else:
                try:
                    options.key_data_file = args[0]
                    args = args[1:]
                except IndexError:
                    if options.command == 'decrypt':
                        options.key_data_file = misc.default_private_key_path
                    elif options.command == 'encrypt':
                        options.key_data_file = misc.default_public_key_path
    if not options.use_rsa and not options.use_oaep:
        parser.error('no encryption specified')

    return Utility(**eval(str(options)))
