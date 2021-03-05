from Crypto.Cipher import AES
from collections import Counter

from Crypto.Hash import SHA256

CIPHERTEXT = bytes.fromhex("05b4a85063e12931ce340321eb5141b24ee81ed6c10e9eae8991198ac796"
                           "f4ff019aa75aabdd24ec2c6145d879c88faefb38563b870b65b87f3ce522"
                           "e065fcf93bd0c6b60398724364ed7da5b17a2c042205628330e42e4a9c5b"
                           "ccfc3645b54d")
CONST_IV = bytes.fromhex("e764ea639dc187d058554645ed1714d8")


def generate_aes_key_from_int(integer, key_length):
    seed = integer.to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_keys = aes_key[:key_length]
    return trunc_keys


def aes_cbc_encryption(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def aes_cbc_decryption(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


# generate possible keys

for i in range(2 ** 16):
    key = generate_aes_key_from_int(i, 16)
    res = aes_cbc_decryption(CIPHERTEXT, key, CONST_IV)
    if res.isascii():
        print(res.decode("ascii"))
