#!/usr/bin/env python
"""Generate a Clef constant with some rigidity."""
from __future__ import division, print_function

from binascii import hexlify

import sys
import struct

from rijndael import Rijndael

QW = struct.Struct('QQ').unpack

def mbrpad(s, paddedlen=32):
    """Apply multi-byte-rate padding to input."""
    length = len(s)
    if length == paddedlen:
        return s
    elif length > paddedlen:
        raise Exception("Constant too long")
    s = bytearray(s + '\x00' * (paddedlen - len(s)))
    s[length] ^= 0x80
    s[-1] ^= 0x01
    return bytes(s)

def mkk(s, key):
    key_size = 32
    block_size = 16
    cipher = Rijndael(mbrpad(key, key_size), block_size=block_size)
    block = cipher.encrypt(mbrpad(s, block_size))
    qwords = QW(block)
    return '0x{:016x}'.format(qwords[0])

if __name__ == '__main__':
    constant = mkk(sys.argv[2], sys.argv[1])
    print("flag_t {} = UINT64_C({});  // AES-256[k=pad('{}')](pad('{}')) "
          .format(sys.argv[2], constant, sys.argv[1], sys.argv[2]))
