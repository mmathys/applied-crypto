import binascii

from Crypto.Cipher import AES

# block size: 16 bytes.
from Crypto.Random import get_random_bytes

const_key = bytes.fromhex("dd59418c90d52a811da90535dc2654fc")
msg_ciphertext = bytes.fromhex(
    "fb5e756b677cca8e4fbc36ca155e6703891157cba968755c44f2a612cf8800c5c0779a414595def312e114a733394191")
cipher = AES.new(const_key, AES.MODE_ECB)


def padded_oracle(prepend_pad, append_pad, ciphertext, key):
    plaintext = cipher.decrypt(ciphertext)
    padded_plaintext = prepend_pad + plaintext + append_pad
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext


def create_single_char_string(char, length):
    char_set = []
    for i in range(length):
        char_set.append(chr(ord(char)))
    string = "".join(char_set)
    return string


def create_dict():
    i_dict = {}
    for i in range(256):
        arr = bytes([0] * 15 + [i])
        value = cipher.encrypt(arr)
        i_dict[value] = bytes([i])
    return i_dict


d = create_dict()
pad1 = bytes.fromhex(create_single_char_string("0", 2 * 15))
pad2 = bytes.fromhex(create_single_char_string("0", 2 * 17))
res = padded_oracle(pad1, pad2, msg_ciphertext, const_key)
first_block = res[:16]
print(f"first byte: 0x{binascii.hexlify(d[first_block]).decode('utf-8')}")
