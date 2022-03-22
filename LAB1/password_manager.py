#!/usr/bin/env python3

import argparse
import hashlib
import json
from os.path import exists

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import scrypt

kdf_params = {'N': 2 ** 14, 'r': 8, 'p': 1}
kdf_byte_size = 32
kdf_salt = 'SRS-LAB1'

password_manager_file_name = 'passwords.txt'
max_password_length = 256


class PasswordManagerNotInitialized(Exception):
    def __init__(self):
        self.message = 'invalid master password'
        super().__init__(self.message)


class InvalidMasterPassword(Exception):
    def __init__(self):
        self.message = 'invalid master password'
        super().__init__(self.message)


class PasswordNotFound(Exception):
    def __init__(self, site_address):
        self.message = 'password not found for site address: {}'.format(site_address)
        super().__init__(self.message)


class SwapAttackDetected(Exception):
    def __init__(self):
        self.message = 'database entries have been swapped'
        super().__init__(self.message)


class RollbackAttackDetected(Exception):
    def __init__(self, expected_sha256, actual_sha256):
        self.message = 'rollback attack has been detected, expected sha256: {}, actual sha256: {}'.format(
            expected_sha256,
            actual_sha256,
        )
        super().__init__(self.message)


def check_rollback_attack(password_file_hash):
    actual_file_hash = get_file_sha256()
    if password_file_hash != actual_file_hash:
        raise RollbackAttackDetected(password_file_hash, actual_file_hash)


def check_if_initialized():
    file_exists = exists(password_manager_file_name)
    if not file_exists:
        raise PasswordManagerNotInitialized()


def get_file_sha256():
    sha256_hash = hashlib.sha256()
    block_size = 4096
    with open(password_manager_file_name, 'rb') as file:
        for byte_block in iter(lambda: file.read(block_size), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.digest().hex()


def get(master_password, site_address, password_file_hash=None):
    check_if_initialized()

    if password_file_hash is not None:
        check_rollback_attack(password_file_hash)

    with open(password_manager_file_name, 'r') as file:
        password_dictionary = json.load(file)

    kdf_key = scrypt(master_password, kdf_salt, kdf_byte_size, **kdf_params)
    kdf_hmac = HMAC.new(kdf_key, str.encode(kdf_salt), digestmod=SHA256)

    if kdf_hmac.digest().hex() != password_dictionary['verification_hmac']:
        raise InvalidMasterPassword()

    expected_site_address_hmac = HMAC.new(kdf_key, str.encode(site_address), digestmod=SHA256)

    if expected_site_address_hmac.digest().hex() in password_dictionary['passwords']:
        encrypted_entry = bytes.fromhex(password_dictionary['passwords'][expected_site_address_hmac.digest().hex()])
    else:
        raise PasswordNotFound(site_address)

    site_address_and_password = encrypted_entry[:288]
    tag = encrypted_entry[288:304]
    nonce = encrypted_entry[304:]

    cipher = AES.new(kdf_key, AES.MODE_GCM, nonce=nonce)
    site_address_and_password = cipher.decrypt_and_verify(site_address_and_password, tag)

    actual_site_address_hmac = site_address_and_password[:32]
    if actual_site_address_hmac != expected_site_address_hmac.digest():
        raise SwapAttackDetected()
    password = site_address_and_password[32:].lstrip(b'\x00')

    return password.decode()


def put(master_password, site_address, site_password, password_file_hash=None):
    check_if_initialized()

    if password_file_hash is not None:
        check_rollback_attack(password_file_hash)

    with open(password_manager_file_name, 'r') as file:
        password_dictionary = json.load(file)

    kdf_key = scrypt(master_password, kdf_salt, kdf_byte_size, **kdf_params)
    site_address_hmac = HMAC.new(kdf_key, str.encode(site_address), digestmod=SHA256)
    site_password_padded = str.encode(site_password).rjust(max_password_length, b'\x00')
    site_address_and_password = site_address_hmac.digest() + site_password_padded

    cipher = AES.new(kdf_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(site_address_and_password)
    # site_address_hmac - 32 bytes
    # site_password_padded - 256 bytes
    # ciphertext - 288 bytes
    # tag - 16 bytes
    # nonce - 16 bytes
    # total 320
    password_dictionary['passwords'][site_address_hmac.digest().hex()] = ciphertext.hex()+tag.hex()+cipher.nonce.hex()

    with open(password_manager_file_name, 'w') as file:
        json.dump(password_dictionary, file)

    return get_file_sha256()


def init(master_password):
    key = scrypt(master_password, kdf_salt, kdf_byte_size, **kdf_params)
    hmac = HMAC.new(key, str.encode(kdf_salt), digestmod=SHA256)

    password_dictionary = {
        "verification_hmac": hmac.digest().hex(),
        "passwords": {},
    }

    with open(password_manager_file_name, 'w') as file:
        json.dump(password_dictionary, file)

    print(get_file_sha256())


def main():
    password_manager_mode_argument = 'mode'
    init_argument = 'init'
    put_argument = 'put'
    get_argument = 'get'
    master_password_argument = 'master_password'
    site_address_argument = 'site_address'
    site_password_argument = 'site_password'
    password_file_hash_argument = 'password_file_hash'

    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest=password_manager_mode_argument)

    init_parser = subparsers.add_parser(init_argument)
    init_parser.add_argument(master_password_argument)

    put_parser = subparsers.add_parser(put_argument)
    put_parser.add_argument(master_password_argument)
    put_parser.add_argument(site_address_argument)
    put_parser.add_argument(site_password_argument)
    put_parser.add_argument(password_file_hash_argument, nargs='?')

    put_parser = subparsers.add_parser(get_argument)
    put_parser.add_argument(master_password_argument)
    put_parser.add_argument(site_address_argument)
    put_parser.add_argument(password_file_hash_argument, nargs='?')

    args = parser.parse_args()

    password_manager_mode = getattr(args, password_manager_mode_argument)

    if password_manager_mode == init_argument:
        init(getattr(args, master_password_argument))
    elif password_manager_mode == put_argument:
        password_file_hash = put(getattr(args, master_password_argument),
                                 getattr(args, site_address_argument),
                                 getattr(args, site_password_argument),
                                 getattr(args, password_file_hash_argument))
        print(password_file_hash)
    elif password_manager_mode == get_argument:
        password = get(getattr(args, master_password_argument),
                       getattr(args, site_address_argument),
                       getattr(args, password_file_hash_argument))
        print(password)


if __name__ == '__main__':
    main()
