#!/usr/bin/python3

import sys
import os
import struct
import hashlib
import subprocess
import getpass
from typing import Tuple

from Crypto.Random import random
from Crypto.Cipher import AES, Blowfish


def read_file(path: str) -> bytes:
    file = open(path, 'rb')
    data = file.read()
    file.close()
    return data


def write_file(path: str, data: bytes):
    file = open(path, 'wb')
    file.write(data)
    file.close()


def getfilehash(data: bytes, algorithm='sha1') -> bytes:
    if algorithm == 'sha1':
        hash = hashlib.sha1()
    elif algorithm == 'md5':
        hash = hashlib.md5()
    elif algorithm == 'sha256':
        hash = hashlib.sha256()
    else:
        print('Invalid hash algorithm.')
        sys.exit()
    hash.update(data)
    return hash.digest()


def encrypt(plain_text: bytes, password: str):
    key = hashlib.sha256(password.encode()).digest()
    mode = AES.MODE_CBC
    IV = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    IV = IV.encode()[:16]
    encryptor = AES.new(key, mode, IV)

    header = struct.pack('<Q', len(plain_text))
    hash = getfilehash(plain_text, 'sha256')
    padding = b'\0' * (AES.block_size - (len(plain_text) % AES.block_size))
    encrypted = encryptor.encrypt(plain_text + padding)
    return header + IV + hash + encrypted


def decrypt(encrypted: bytes, password: str):
    pointer = struct.calcsize('Q')
    origsize = struct.unpack('<Q', encrypted[:pointer])[0]
    key = hashlib.sha256(password.encode()).digest()
    mode = AES.MODE_CBC
    IV = encrypted[pointer:pointer+16]
    pointer += 16
    filehash = encrypted[pointer:pointer+32]
    pointer += 32
    decryptor = AES.new(key, mode, IV)

    plain_text = decryptor.decrypt(encrypted[pointer:])[:origsize]
    if not getfilehash(plain_text, 'sha256') == filehash:
        raise RuntimeError('Hashes do not match. Wrong password?')
    return plain_text


def super_encrypt(plain_text: bytes, password: str):
    key0 = hashlib.sha256(password.encode()).digest()
    key = hashlib.sha256(key0[:12]).digest(), hashlib.sha256(key0[12:22]).digest(), \
          hashlib.sha256(key0[22:]).digest()
    cipher = AES, Blowfish, AES
    mode = AES.MODE_CBC, Blowfish.MODE_CBC, AES.MODE_CBC
    IV = ''.join(chr(random.randint(0, 0xFF)) for i in range(16)).encode()[:16], \
         ''.join(chr(random.randint(0, 0xFF)) for i in range(16)).encode()[:8], \
         ''.join(chr(random.randint(0, 0xFF)) for i in range(16)).encode()[:16]

    header = struct.pack('<Q', len(plain_text))
    hash = getfilehash(plain_text, 'sha256')
    padding = b'\0' * (AES.block_size - (len(plain_text) % AES.block_size))  # AES, Blowfish -> 16, 8
    data = plain_text + padding

    for i in range(3):
        encryptor = cipher[i].new(key[i], mode[i], IV[i])
        data = encryptor.encrypt(data)
    return header + IV[0] + IV[1] + IV[2] + hash + data


def super_decrypt(encrypted: bytes, password: str):
    pointer = struct.calcsize('Q')
    origsize = struct.unpack('<Q', encrypted[:pointer])[0]
    key0 = hashlib.sha256(password.encode()).digest()
    key = hashlib.sha256(key0[22:]).digest(), hashlib.sha256(key0[12:22]).digest(), \
          hashlib.sha256(key0[:12]).digest()
    cipher = AES, Blowfish, AES
    mode = AES.MODE_CBC, Blowfish.MODE_CBC, AES.MODE_CBC
    IV0 = encrypted[pointer:pointer+40]
    pointer += 40
    IV = IV0[24:], IV0[16:24], IV0[:16]
    filehash = encrypted[pointer:pointer+32]
    pointer += 32
    data = encrypted[pointer:]

    for i in range(3):
        decryptor = cipher[i].new(key[i], mode[i], IV[i])
        data = decryptor.decrypt(data)

    plain_text = data[:origsize]
    if not getfilehash(plain_text, 'sha256') == filehash:
        print(getfilehash(plain_text, 'sha256'))
        print(filehash)
        raise RuntimeError('Hashes do not match. Wrong password?')
    return plain_text


def parse_args() -> Tuple[bool, str]:
    super_encryption = False
    args = sys.argv[1:]
    if '-s' in args:
        super_encryption = True
        args.remove('-s')
    if not args:
        print(f'Usage: {sys.argv[0]} [-s] FILE')
        sys.exit()
    path = args[-1]
    return super_encryption, path


def main():
    super_encryption, path = parse_args()

    plain_text = b''
    if os.path.exists(path):
        password = getpass.getpass('Password: ')
        encrypted = read_file(path)
        if encrypted:
            plain_text = super_decrypt(encrypted, password) if super_encryption else decrypt(encrypted, password)
    else:
        password = getpass.getpass('New Password: ')
        if not getpass.getpass('Confirm: ') == password:
            print('Passwords do not match.')
            sys.exit()

    plain_fd = os.memfd_create('nano_interface')
    if plain_text:
        os.write(plain_fd, plain_text)

    subprocess.run(['nano', f'/proc/{os.getpid()}/fd/{plain_fd}'])

    os.lseek(plain_fd, 0, os.SEEK_SET)
    plain_text = os.read(plain_fd, 0x1000000)
    os.close(plain_fd)
    write_file(path, super_encrypt(plain_text, password) if super_encryption else encrypt(plain_text, password))


if __name__ == '__main__':
    main()

