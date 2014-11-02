#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Pretty Cryptic Privacy (PCP)
Copyright © 2011, 2014 Lorenz Quack

Module to encrypt/decrypt files and directories

TODO: 
 * get password interactively if not provided on the commandline
 * make output optional and print to stdout if not given
"""

# stdlib
import io
import os
import sys
import math
import shutil
import argparse
import tempfile
import tarfile
import hmac
import hashlib

# PyCrypto
import Crypto
import Crypto.Util.number
import Crypto.Random
    

# magic number very similar to PNG:
#    1) high bit set (0x89)
#  2-4) "PCP" (0x706370)
#  5-6) CRLF line-ending conversion detection (0x0D0A)
#    7) end-of-file character (0x1A)
#    8) LF line-ending converion detection (0x0A)
# | Byte        |     1     |  2-4   | 5-6  |  7  | 8  |
# | Meaning     | non-ascii | "PCP"  | CRLF | EOF | LF |
# | Value (hex) |    89     | 706370 | 0D0A | 1A  | 0A |
MAGIC_NUMBER = 0x897063700D0A1A0A

VERSION = 1

ENCRYPTION_SCHEMA_AES_128 = 0x01
ENCRYPTION_SCHEMA_AES_256 = 0x02

PADDING_SCHEMA_PKCS7 = 0x01

CHAINING_MODE_ECB = 0x01
CHAINING_MODE_CBC = 0x02
CHAINING_MODE_CFB = 0x03
CHAINING_MODE_OFB = 0x05
CHAINING_MODE_CRT = 0x06

HASH_FUNCTION_SHA1 = hashlib.sha1


def getRandomBytes(n=1):
    return Crypto.Random.get_random_bytes(n)

## def HMAC(key, msg):
##     hmac = hmac.hmac(key, msg, hashlib.sha1)
##     return hmac.digest()

def padMessage(msg, blockSize, schema):
    paddedMsg = ""
    if schema == PADDING_SCHEMA_PKCS7:
        l = ((blockSize - len(msg) - 1) % blockSize) + 1
        paddedMsg = msg + l * l.to_bytes(1, 'big')
    else:
        raise RuntimeError("unknown padding schema")
    return paddedMsg

def unpadMessage(paddedMsg, schema):
    if schema == PADDING_SCHEMA_PKCS7:
        l = int.from_bytes(paddedMsg[-1:], 'big')
        msg = paddedMsg[:-l]
    else:
        raise RuntimeError("unknown padding schema")
    return msg

def deriveKey(password, salt, iterCount, keyLength, hashFunc):
    """implement PBKDF2 from PKCS #5 v2.0 (RFC 2898 Sec. 5.2)"""
    def HMAC(key, msg):
        return hmac.hmac(key, msg, hashFunc).digest()

    hLen = len(HMAC(b"foo", b"bar"))
    def F(P, S, c, i):
        U = int.from_bytes(HMAC(P, S + i.to_bytes(4, 'big')), 'big')
        for j in range(1, c):
            U ^= int.from_bytes(HMAC(P, U.to_bytes(hLen, 'big')), 'big')
        return U.to_bytes(hLen, 'big')
    if keyLength > (2**32 - 1) * hLen:
        raise RuntimeError("derived key too long")
    l = int(math.ceil(keyLength / hLen))
    r = keyLength - (l - 1) * hLen
    derivedKey = b""
    for i in range(l):
        derivedKey += F(password, salt, iterCount, i)
    return derivedKey[:keyLength]
        

class VersionedCrypter:
    def __init__(self, version, password):
        self.VERSION = version
        self.HEADER_BYTE_SIZE = 8 + 1 # magic number + version number
        if version == 1:
            self.ENCRYPTION_SCHEMA = ENCRYPTION_SCHEMA_AES_256
            self.CHAINING_MODE = CHAINING_MODE_CBC
            self.PADDING_SCHEMA = PADDING_SCHEMA_PKCS7
            self.KEY_BYTE_SIZE = 32
            self.BLOCK_BYTE_SIZE = 16
            self.IV_BYTE_SIZE = self.BLOCK_BYTE_SIZE
            self.SALT_BYTE_SIZE = 16
            self.ITER_COUNT = 1000
            self.HEADER_BYTE_SIZE += 2 + 2 + 1 + 2
            self.HASH_FUNCTION = HASH_FUNCTION_SHA1
            self._password = password
            self._isEncrypter = None
            self.encrypt = self._encrypt_first
        else:
            raise RuntimeError("unknown version number")

    def __setattr__(self, name, value):
        raise RuntimeError("You really shouldn't set any values in the "
                           "VersionedCrypter class!")

class VersionedEncrypter(VersionedCrypter):
    def __init__(self, version, password):
        super(VersionedEncrypter, self).__init__(version)
        if self.VERSION == 1:
            self._salt = getRandomBytes(self.SALT_BYTE_SIZE)
            self._iv = getRandomBytes(self.IV_BYTES_SIZE)
            key = deriveKey(password, self._salt, self.ITER_COUNT,
                            self.KEY_BYTE_LENGTH, self.HASH_FUNCTION)
            # This does *not* guarantee that the password wont show up in memory
            del password
            self._encrypter = Crypto.Cipher.AES.new(key, self.CHAINING_MODE,
                                                    self._iv)
        else:
            raise RuntimeError("unknown verion number")
        
    def encrypt(self, bytes):
        assert(len(bytes) % self.BLOCK_BYTE_SIZE == 0)
        return self._encrypter.encrypt(bytes)

    def writeHeader(self, stream=None):
        header = b""
        if self.VERSION == 1:
            header += self._salt.to_bytes(self.SALT_BYTE_SIZE, 'big')
            header += self._iv.to_bytes(self.IV_BYTE_SIZE, 'big')
        else:
            raise RuntimeError("unknown version number")
        if stream is not None:
            stream.write(header)
        return header


class VersionedDecrypter(VersionedCrypter):
    def __init__(self, version, password, stream):
        super(VersionedDecrypter, self).__init__(version)
        if self.VERSION == 1:
            self._salt = int.from_bytes(stream.read(self.SALT_BYTE_SIZE), 'big')
            self._iv = int.from_bytes(stream.read(self.IV_BYTE_SIZE), 'big')
            key = deriveKey(password, self._salt, self.ITER_COUNT,
                            self.KEY_BYTE_LENGTH, self.HASH_FUNCTION)
            del password
            self._decrypter = Crypto.Cipher.AES.new(key, self.CHAINING_MODE,
                                                    self._iv)
        else:
            raise RuntimeError("unknown version number")

    def decrypt(self, bytes):
        assert(len(bytes) % self.BLOCK_BYTE_SIZE == 0)
        return self._crypter.decrypt(bytes)


class Options:
    def __init__(self, version):
        self.VERSION = version
        self.HEADER_BYTE_SIZE = 8 + 1 # magic number + version number
        if version == 1:
            self.ENCRYPTION_SCHEMA = ENCRYPTION_SCHEMA_AES_256
            self.CHAINING_MODE = CHAINING_MODE_CBC
            self.PADDING_SCHEMA = PADDING_SCHEMA_PKCS7
            self.KEY_BYTE_SIZE = 32
            self.BLOCK_BYTE_SIZE = 16
            self.IV_BYTE_SIZE = self.BLOCK_BYTE_SIZE
            self.SALT_BYTE_SIZE = 16
            self.ITER_COUNT = 1000
            self.HEADER_BYTE_SIZE += 2 + 2 + 1 + 2
        else:
            raise RuntimeError("unknown version number")

    def getHeader(self):
        header = MAGIC_NUMBER.to_bytes(8, 'big')
        header += self.VERSION.to_bytes(1, 'big')
        if self.VERSION == 1:
            header += self.ENCRYPTION_SCHEMA.to_bytes(2, 'big')
            header += self.PADDING_SCHEMA.to_bytes(2, 'big')
            header += self.SALT_BYTE_SIZE.to_bytes(1, 'big')
            header += int(0).to_bytes(2, 'big') # reserved for later use
        else:
            raise RuntimeError("unknown version number")
        return header

    @classmethod
    def fromCiphertext(cls, ciphertext):
        if int.from_bytes(ciphertext.read(8), 'big') != MAGIC_NUMBER:
            raise RuntimeError("wrong magic number")
        options = cls(int.from_bytes(ciphertext.read(1), 'big'))
        if options.VERSION == 1:
            if (int.from_bytes(ciphertext.read(2), 'big') !=
                options.ENCRYPTION_SCHEMA):
                raise RuntimeError("corrupted header")
            if (int.from_bytes(ciphertext.read(2), 'big') !=
                options.PADDING_SCHEMA):
                raise RuntimeError("corrupted header")
            if (int.from_bytes(ciphertext.read(1), 'big') !=
                options.SALT_BYTE_SIZE):
                raise RuntimeError("corrupted header")
            # consume the unused bytes
            ciphertext.read(2)
        else:
            raise RuntimeError("unknown version number")
        return options

    def stripHeader(self, ciphertext):
        try:
            o = Options.fromCiphertext(ciphertext)
        except RuntimeError:
            raise RuntimeError("doesn't seem to be ciphertext with valid header")
        if o.VERSION != self.VERSION:
            raise RuntimeError("version mismatch")
        if self.VERSION == 1:
            return ciphertext[16:]

    

def encrypt(msg, password):
    options = Options(VERSION)
    salt = getRandomBytes(options.SALT_BYTE_SIZE)
    iv = getRandomBytes(options.IV_BYTE_SIZE)
    key = deriveKey(password, salt, options.ITER_COUNT, options.KEY_BYTE_SIZE)
    encrypter = Crypto.Cipher.AES.new(key, options.CHAINING_MODE, iv)
    ciphertext = options.getHeader()
    ciphertext += salt
    ciphertext += iv
    ciphertext += encrypter.encrypt(padMessage(msg, options.BLOCK_BYTE_SIZE,
                                               options.PADDING_SCHEMA))
    return ciphertext

def decrypt(ciphertext, password):
    options = Options.fromCiphertext(ciphertext)
    ciphertext = options.stripHeader(ciphertext)
    salt = ciphertext[:options.SALT_BYTE_SIZE]
    iv = ciphertext[options.SALT_BYTE_SIZE:
                    options.SALT_BYTE_SIZE + options.IV_BYTE_SIZE]
    ciphertext = ciphertext[options.SALT_BYTE_SIZE + options.IV_BYTE_SIZE:]
    key = deriveKey(password, salt, options.ITER_COUNT, options.KEY_BYTE_SIZE)
    decrypter = Crypto.Cipher.AES.new(key, options.CHAINING_MODE, iv)
    paddedMsg = decrypter.decrypt(ciphertext)
    msg = unpadMessage(paddedMsg, options.PADDING_SCHEMA)
    return msg


def encryptFiles(outName, pathList, password):
    tmpFile = tempfile.NamedTemporaryFile("wb", delete=False)
    with tarfile.open(fileobj=tmpFile, mode="w|bz2") as f:
        for path in pathList:
            print(type(path), path)
            f.add(path)
    tmpName = tmpFile.name
    tmpFile.close()
    with open(tmpName, "rb") as fin:
        with open(outName, "wb") as fout:
            fout.write(encrypt(fin.read(), password))
    os.remove(tmpName)

def decryptFile(path, password):
    tmpFile = tempfile.NamedTemporaryFile("wb", delete=False)
    print(tmpFile.name)
    with open(path, "rb") as fin:
        tmpFile.write(decrypt(fin.read(), password))
    tmpName = tmpFile.name
    tmpFile.close()
    f = tarfile.open(tmpName, "r|bz2")
    f.extractall()
    os.remove(tmpName)


class EncryptedFileWriter(io.BufferedIOBase):
    def __init__(self, filename, password):
        super(EncryptedFileWriter, self).__init__()
        self.filename = filename
        self.raw = io.open(filename, "wb")
        self._isClosed = False
        self.raw.write(MAGIC_NUMBER.to_bytes(8, 'big'))
        self.raw.write(VERSION.to_bytes(2, 'big'))
        # pad to 16 bytes; reserved for later use
        self.raw.write(int(0x00).to_bytes(6, 'big'))
        self._buffer = b""
        self._encrypter = VersionedEncrypter(VERSION, password)
        self._encrypter.writeHeader(self.raw)
        self._hash = hashlib.sha256()

    def write(self, bytes):
        if self._isClose:
            raise IOError("stream is closed")
        self._buffer += bytes
        self._hash.update(bytes)
        bufferSize = len(self._buffer)
        blockSize = self._encrypter.BLOCK_BYTE_SIZE
        numOfBytes = 0
        if bufferSize > blockSize:
            numOfBlocks = bufferSize // blockSize
            numOfBytes = numOfBlocks * blockSize
            self.raw.write(self._encrypter.encrypt(self._buffer[:numOfBytes]))
            self._buffer = self._buffer[numOfBytes:]
        return numOfBytes

    def close(self):
        if self._isClosed:
            return
        blockSize = self._encrypter.BLOCK_BYTE_SIZE
        paddingSchema = self._encrypter.PADDING_SCHEMA
        self._buffer += self._hash.digest()
        paddedMessage = padMessage(self._buffer, blockSize, paddingSchema)
        self.raw.write(encrypter.encrypt(paddedMessage))
        self.raw.close()
        self._isClosed = True

    @property
    def closed(self):
        return self._isClosed


class EncryptedFileReader(io.BufferedIOBase):
    def __init__(self, filename):
        super(EncryptedFileReader, self).__init__()
        self.filename = filename
        self.raw = io.open(filename, "rb")
        self._isClosed = False
        self._buffer = b""
        self._hash = hashlib.sha256
        magicNumber = self.raw.read(len(MAGIC_NUMBER))
        if magicNumber != MAGIC_NUMBER:
            raise RuntimeError("wrong magic number")
        version = self.raw.read(2)
        # consume the padding bytes
        self.raw.read(6)
        self._decrypter = VersionedDecrypter(VERSION, password, self.raw)
        self._verificationHash = None
        digestSize = self._decrypter.HASH_FUNCTION.digest_size
        blockSize = self._decrypter.BLOCK_BYTE_SIZE
        self._preBufferSize = int(math.ceil(digestSize / blockSize)) * blockSize
        # fill preBuffer
        self._preBuffer = self.raw.read(self._preBufferSize)
        if len(self._preBuffer) != self._preBufferSize:
            raise RuntimeError("File to small. "
                               "Doesn't comply with specification.")

    def _readFromPreBuffer(self):
        if self._verificationHash is not None:
            # we alread reached and processed the EOF
            return b""
        blockSize = self._decrypter.BLOCK_BYTE_SIZE
        assert(self._preBufferSize % blockSize == 0)
        b = self.raw.read(self._preBufferSize)
        if len(b) == 0:
            # we reached EOF. unpad the preBuffer...
            self._preBuffer = unpadMessage(self._preBuffer)
            # ...and strip the hash
            digestSize = self._decrypter.HASH_FUNCTION.digest_size
            self._verificationHash = self._preBuffer[-digestSize:]
            return self._preBuffer[:-digestSize]
        elif len(b) != self._preBufferSize:
            raise RuntimeError("Could not read entire block. "
                               "The stream might be broker or corrupted.")
        b = self._crypter.decrypt(b)
        self._preBuffer, b = b, self._preBuffer
        return b
        
    def read(self, n):
        if self._isClosed:
            raise IOError("stream is not closed")
        while n > len(self._buffer):
            b = self._readFromPreBuffer()
            self._hash.update(b)
            if len(b) != self._preBufferSize:
                # preBuffer is exhausted. This should mean we also retreived
                # the verification hash
                assert(self._verificationHash is not None)
                if self._hash.digest() != self._verificationHash:
                    raise RuntimeError("Verification Error. "
                                       "File seems to be corrupted")
                break
            self._buffer += b
        tmp, self._buffer = self._buffer[:n], self._buffer[n:]
        return tmp
        


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true",
                       help="encrypt the input")
    group.add_argument("-d", "--decrypt", action="store_true",
                       help="decrypt the input")
    parser.add_argument("-o", "--output", nargs=1,
                        help="output filename")
    parser.add_argument("-p", "--password", nargs=1, required=True,
                        help="the password used for en-/decrypting")
    parser.add_argument("input", nargs="+")
    args = parser.parse_args()
    if args.encrypt:
        if args.output is None:
            parser.error("you must provide the -o/--output option to encrypt")
        encryptFiles(args.output[0], args.input,
                     args.password[0].encode("utf-8"))
    else:
        if len(args.input) != 1:
            parser.error("decrypting more than one file at a time is not supported")
        decryptFile(args.input[0], args.password[0].encode("utf-8"))
    sys.exit(0)
        
                      

def test():
    plaintexts = []
    plaintexts.append( b"foobar")
    plaintexts.append( b"The quick brown fox jumps over the lazy dog" )
    plaintexts.append( b"""Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam laoreet nibh in metus porttitor id pretium leo pretium. Vestibulum tortor enim, aliquet et suscipit vitae, condimentum id lacus. Mauris eget ligula risus. Maecenas vel posuere justo. In hac habitasse platea dictumst. Proin nec nibh nibh. Cras at dui non erat dignissim rhoncus eu auctor quam. Proin nunc ligula, ullamcorper blandit laoreet ut, fringilla non turpis. Donec interdum, nulla vel consequat bibendum, nisi felis laoreet turpis, in mollis eros dolor nec tellus. Suspendisse sodales arcu non tortor feugiat porta. Proin tortor magna, tincidunt a ultricies in, aliquet vel magna. Pellentesque porttitor enim sollicitudin felis condimentum ac interdum sem dignissim. Vestibulum magna massa, commodo at aliquam ut, venenatis a leo. Vivamus vel justo magna, id vestibulum metus. Nulla tellus tortor, consectetur eget eleifend id, venenatis nec tellus.
    
    Donec quis lectus nec ante rhoncus suscipit non ut nunc. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Vivamus lorem justo, convallis ac commodo vitae, faucibus ut enim. Maecenas dui enim, sollicitudin sed semper sit amet, bibendum sit amet diam. Phasellus vel rutrum sapien. Praesent non ante eu quam iaculis pulvinar ac at ipsum. Aliquam vel nulla at dolor imperdiet iaculis at eget arcu. Integer hendrerit justo vel nisi posuere ultrices. Nullam elit elit, blandit aliquet vulputate quis, tempor at mauris. Fusce et fermentum dui. Nulla facilisi. Nullam venenatis dolor non orci volutpat ornare mattis mi porttitor. Proin lobortis, risus in vulputate vestibulum, lectus magna tristique velit, sed posuere sapien ligula a magna.

    Proin condimentum dui at lacus facilisis hendrerit. Sed vitae ipsum ut nibh imperdiet molestie. Aliquam eu dui at leo egestas fermentum vel at leo. Donec et elementum lectus. Fusce aliquam, nunc sed cursus fringilla, turpis justo consequat risus, in dapibus est felis eu dolor. Donec felis leo, semper eget tempus sit amet, sodales ut est. Phasellus elementum consectetur pellentesque. Morbi sit amet nulla ante. Aliquam elit nisi, porta eget facilisis quis, pretium at sapien. Aenean suscipit erat ac ligula tristique ultricies. Fusce nec libero molestie lacus interdum luctus. Pellentesque commodo mauris quis lectus ullamcorper in consequat mi convallis. Fusce quis arcu est. Aenean fringilla, felis eget accumsan consequat, mi velit viverra diam, nec scelerisque enim leo vitae nisi. Fusce cursus eleifend ultricies.""")
    plaintexts.append("Irgendwas mit überflüssigen spaßigen Umlauten".encode("utf-8"))
    
    for p in plaintexts:
        print (len(p), p)
        c = encrypt(p, b"snafu")
        print (len(c), c)
        d = decrypt(c, b"snafu")
        print (len(d), d.decode("utf-8"))
        assert(p == d)

    


## from tkinter import *
## from tkinter import filedialog
## from tkinter import ttk

## def encrypt(*args):
##     try:
##         print("Do IT!")
##     except ValueError:
##         pass

## def pickPath(*args):
##     filename = filedialog.askopenfilename()
##     print(filename)

## def keepOrigChanged(*args):
##     pass

## root = Tk()
## root.title("Encrypt...")

## path = StringVar()
## password1 = StringVar()
## password2 = StringVar()
## keepOrig = StringVar()

## n = ttk.Notebook(root)

## f1 = ttk.Frame(n)
## f2 = ttk.Frame(n)

## n.add(f1, text="foo")
## n.add(f2, text="bar")

## ## mainframe = ttk.Frame(notebook, padding="3 3 12 12")
## ## mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
## ## mainframe.columnconfigure(0, weight=1)
## ## mainframe.rowconfigure(0, weight=1)


## ## notebook.add(mainframe, text="eieie", state="normal")
## ## #notebook.select(0)


## ## ttk.Label(mainframe, text="path:").grid(column=1, row=1, sticky=E)
## ## pathEntry = ttk.Entry(mainframe, textvariable=path)
## ## pathEntry.grid(column=2, row=1, sticky=(W, E))
## ## ttk.Button(mainframe, text="...", command=pickPath).grid(column=3, row=1, sticky=(W, E))


## ## ttk.Label(mainframe, text="password:").grid(column=1, row=2, sticky=E)
## ## password1Entry = ttk.Entry(mainframe, show="*", textvariable=password1)
## ## password1Entry.grid(column=2, row=2, sticky=(W, E))

## ## ttk.Label(mainframe, text="repeate password:").grid(column=1, row=3, sticky=(W, E))
## ## password2Entry = ttk.Entry(mainframe, show="*", textvariable=password2)
## ## password2Entry.grid(column=2, row=3, sticky=(W, E))

## ## ttk.Checkbutton(mainframe, text="Keep Original", command=keepOrigChanged,
## ##                 variable=keepOrig, onvalue="true", offvalue="false").grid(column=2, row=4, sticky=(E, W))
## ## ttk.Button(mainframe, text="Encrypt!", command=encrypt).grid(column=4, row=4, sticky=W)

## ## for child in mainframe.winfo_children():
## ##     child.grid_configure(padx=5, pady=5)

## ## pathEntry.focus()
## ## root.bind('<Return>', encrypt)

## root.mainloop()
