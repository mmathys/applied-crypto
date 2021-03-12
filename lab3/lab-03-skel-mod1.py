from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY_SIZE = 16
BLOCK_SIZE = 16

CONST_PLAINTEXT = "Hey, I just met you and this is crazy but here's my number so call me maybe"


def generate_aes_key(key_length):
    """
    Use get_random_bytes to generate a key of the
    appropriate length
    """
    return get_random_bytes(key_length)


def create_single_char_string(char, length):
    char_set = []
    for i in range(length):
        char_set.append(chr(ord(char)))
    string = "".join(char_set)
    return string


def add_padding(plaintext, block_length):
    """
    Adds padding to the plaintext, making the length of the
    padding + plaintext a multiple of the block length (16 bytes)
    Note that if the length of the plaintext is already a multiple
    of the block-length, a full block of padding is added
    """
    padding_len = len(plaintext) % block_length
    if padding_len == 0:
        padding_len = 16
    else:
        padding_len = block_length - padding_len
    return plaintext + padding_len.to_bytes(1, byteorder='big') * padding_len


def remove_padding(padded_plaintext, block_length):
    """
    Removes padding from the padded_plaintext
    """
    padding_len = padded_plaintext[-1]
    return padded_plaintext[:-padding_len]


def aes_ecb_encryption(plaintext, key, block_length):
    """
    Pads the plaintext using add_padding, and then
    initialises a new AES cipher object in ECB mode.
    Encrypt the plaintext under the given key, and
    return the ciphertext
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded = add_padding(plaintext, block_length)
    return cipher.encrypt(padded)


def aes_ecb_decryption(ciphertext, key, block_length):
    """
    Decrypt the ciphertext under the given key, and
    remove the padding from the padded_plaintext
    using remove_padding. Return the plaintext.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    return remove_padding(padded, block_length)


def aes_cbc_encryption(plaintext, key, block_length):
    """
    Generate an IV, then pad the plaintext using
    add_padding. Initialise a new AES cipher object
    in CBC mode. Encrypt the plaintext using the key
    and the IV, and concatenate the ciphertext and the
    iv. Return the ciphertext.
    """
    iv = get_random_bytes(block_length)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = add_padding(plaintext, block_length)
    return iv + cipher.encrypt(padded)


def aes_cbc_decryption(ciphertext, key, block_length):
    """
    Recover the IV from the ciphertext, then inialise
    a new AES cipher object in CBC mode. Decrypt the
    ciphertext using the key and the IV, and remove
    the padding. Return the plaintext.
    """
    iv = ciphertext[:block_length]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext[block_length:])
    return remove_padding(padded, block_length)


def aes_ctr_encryption(plaintext, key, block_length, ctr):
    """
    Pad the plaintext using add_padding. Initialise a new
    AES cipher object in CTR mode using the given ctr.
    Encrypt the padded plaintext using the key, and return
    the ciphertext.
    """
    padded = add_padding(plaintext, block_length)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(padded)


def aes_ctr_decryption(ciphertext, key, block_length, ctr):
    """
    Inialise a new AES cipher object in CTR mode. Decrypt the
    ciphertext using the key, and remove the padding.
    Return the plaintext.
    """
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    padded = cipher.decrypt(ciphertext)
    return remove_padding(padded, block_length)


"""
Use the above functions to encrypt CONST_PLAINTEXT.
Ensure that you recover the same plaintext after
you encrypt and decrypt
"""

# test padding
padded = add_padding(CONST_PLAINTEXT.encode(), BLOCK_SIZE)
unpadded = remove_padding(padded, BLOCK_SIZE)
print(unpadded)

key = generate_aes_key(KEY_SIZE)

# test ecb
ecb_cipher = aes_ecb_encryption(CONST_PLAINTEXT.encode(), key, BLOCK_SIZE)
ecb_plain = aes_ecb_decryption(ecb_cipher, key, BLOCK_SIZE)
print(ecb_plain)

# test cbc
cbc_cipher = aes_cbc_encryption(CONST_PLAINTEXT.encode(), key, BLOCK_SIZE)
cbc_plain = aes_cbc_decryption(cbc_cipher, key, BLOCK_SIZE)
print(cbc_plain)

# test ctr
ctr = Counter.new(128)
ctr_cipher = aes_ctr_encryption(CONST_PLAINTEXT.encode(), key, BLOCK_SIZE, ctr)
ctr_plain = aes_ctr_decryption(ctr_cipher, key, BLOCK_SIZE, ctr)
print(ctr_plain)
