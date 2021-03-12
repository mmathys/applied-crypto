from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

KEY_SIZE = 16
BLOCK_SIZE = 16
XOR_CONST = (ord(b'x') ^ ord(b';'))


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


def aes_cbc_encryption(plaintext, key, block_length):
    """
    Generate an IV, then pad the plaintext using
    add_padding. Initialise a new AES cipher object
    in CBC mode. Encrypt the plaintext using the key
    and the IV, and concatenate the ciphertext and the
    iv. Return the ciphertext.
    """
    plaintext = plaintext.encode()
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


def prepend_and_append(prepend_string, string, append_string):
    plaintext = prepend_string + string + append_string
    plaintext = remove_admin(plaintext)
    return plaintext


def remove_admin(string):
    string = string.replace(";admin;", "")
    return string


def concatenate_and_encrypt(prepend_string, mid_string, append_string, aes_key, block_length):
    plaintext = prepend_and_append(prepend_string, mid_string, append_string)
    ciphertext = aes_cbc_encryption(plaintext, aes_key, block_length)
    return ciphertext


def encryption_oracle(plaintext, key, block_length):
    prepend_string = "username=ILoveToBakePie;userdata="
    append_string = ";username=ILoveToBakeCakes;userdata=Mod"
    ciphertext = concatenate_and_encrypt(prepend_string, plaintext, append_string, key, block_length)
    return ciphertext


def decryption_oracle(ciphertext, key, block_length):
    plaintext = aes_cbc_decryption(ciphertext, key, block_length)
    return plaintext


def is_admin(ciphertext, key, block_length):
    plaintext = decryption_oracle(ciphertext, key, block_length)
    print(plaintext)
    result = str(plaintext).find(';admin;')
    if result == -1:
        answer = "Not Admin"
    else:
        answer = "Admin"
    return answer


def make_admin(ciphertext, block_length, pos_one, pos_two):
    """
    Here you implement the CBC bitflipping attack. Choose
    positions (or a single position) in which you will target
    to create a ciphertext that will decrypt with the string
    ";admin;" contained within. Return the ciphertext.
    """

    pos = pos_one
    mask = ([0x00] * pos) + [XOR_CONST] + ([0x00] * (len(ciphertext) - 1 - pos))
    masked = bytes([_a ^ _b for _a, _b in zip(ciphertext, mask)])
    return masked


aes_key = generate_aes_key(KEY_SIZE)
ciphertext_test = encryption_oracle(";admin;", aes_key, BLOCK_SIZE)
test_answer = is_admin(ciphertext_test, aes_key, BLOCK_SIZE)
print(test_answer)

"""

Now create the bit-flipped ciphertext and implement the attack :)

"""
userdata = ";admin"
userdata_enc = userdata.encode()
mask = [XOR_CONST] + [0x00] * (len(userdata_enc) - 1)
masked = bytes([_a ^ _b for _a, _b in zip(userdata_enc, mask)])
ciphertext_hack = encryption_oracle(masked.decode(), aes_key, BLOCK_SIZE)
pos1 = len("username=ILoveToBakePie;userdata=".encode())  # start pos in byte
ciphertext_hack = make_admin(ciphertext_hack, BLOCK_SIZE, pos1, -1)
hack_answer = is_admin(ciphertext_hack, aes_key, BLOCK_SIZE)
print(hack_answer)
