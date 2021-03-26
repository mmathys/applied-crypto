import os
import hashlib
from Crypto.Hash import SHA, HMAC, SHA256
from Crypto.Random import get_random_bytes


def pw_hash_one(password):
    hash = hashlib.md5()
    hash.update(password)
    return hash.digest()


def pw_hash_two(password, salt=get_random_bytes(10)):
    hash = HMAC.new(password, salt, SHA)
    hash.update(password)
    return hash.digest()


def pw_hash_three(password):
    key = "".encode()
    hash = HMAC.new(key, password, SHA256)
    return hash.digest()


def pw_hash_four(password, key):
    hash = HMAC.new(key, password, SHA256)
    return hash.digest()


def pw_hash_five(password, salt=get_random_bytes(32)):
    hashed_password = hashlib.scrypt(password, salt=salt, n=2 ** 10, r=32, p=2)
    return hashed_password


# consider dropping: MD5 and SHA-1 HMAC is not worth keeping: they don't increase the security.
#
def fb_pw_onion(password):
    h1 = pw_hash_one(password)
    salt = get_random_bytes(20)
    h2 = pw_hash_two(h1, salt=salt)
    h3 = pw_hash_three(h2)
    h4 = pw_hash_five(h3, salt=salt)
    h5 = pw_hash_three(h4)
    return salt, h5


print("hello")
