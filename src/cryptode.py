import struct
import os
import shutil
import tarfile
import multiprocessing
import sys
import io
from io import StringIO
from cffi import FFI
import fernet
from typing import List, Dict, Tuple, Callable, Optional
from abc import ABC, abstractmethod
import ctypes
from ctypes import c_char_p, c_int, c_ulonglong, create_string_buffer, byref, CDLL
import bcrypt
import base64
import hashlib
import clr
import numpy as np
import random
import argon2

script_dir = os.path.dirname(os.path.realpath(__file__))

clr.AddReference(os.path.join(script_dir, 'Sigmath.dll'))

from Sigmath import Nums, Matrix, Computing

# ------------------------------------------- #

def another_rot13(text):
    input_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    output_str = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    return ''.join(output_str[input_str.find(c)] if c in input_str else c for c in text)

# -------------------------------------------- #

Word = int

BB = 128

U64BYTES = 8

Block = [Word] * (BB // U64BYTES)

KK_MAX = 64
NN_MAX = 64

RC = [32, 24, 16, 63]

IV = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]

SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]


def blank_block() -> Block:
    return [0] * (BB // U64BYTES)


def add(a: Word, b: Word) -> Word:
    return (a + b) & 0xFFFFFFFFFFFFFFFF


def ceil(dividend: int, divisor: int) -> int:
    return (dividend // divisor) + (dividend % divisor != 0)


def g(v: List[Word], a: int, b: int, c: int, d: int, x: Word, y: Word) -> None:
    for m, r in zip([x, y], RC):
        v[b] = add(v[b], v[a])
        v[a] = add(v[a], m)

        v[d] = ((v[d] ^ v[a]) >> (64 - r)) | ((v[d] ^ v[a]) << r)

        v[c] = add(v[c], v[d])

        v[b] = ((v[b] ^ v[c]) >> (64 - r)) | ((v[b] ^ v[c]) << r)


def f(h: List[Word], m: Block, t: int, flag: bool) -> None:
    v = h + IV[:8]

    v[12] ^= (t & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    v[13] ^= (t >> 64).to_bytes(8, "little")

    if flag:
        v[14] = ~v[14] & 0xFFFFFFFFFFFFFFFF

    for i in range(12):
        s = SIGMA[i % 10]

        s_index = 0
        for j in range(4):
            g(
                v,
                j,
                j + 4,
                j + 8,
                j + 12,
                m[s[s_index]],
                m[s[s_index + 1]],
            )

            s_index += 2

        def i1d(col: int, row: int) -> int:
            col = col % 4
            row = row % 4

            return (row * 4) + col

        for j in range(4):
            idx = [i1d(j + n, n) for n in range(4)]

            g(
                v,
                idx[0],
                idx[1],
                idx[2],
                idx[3],
                m[s[s_index]],
                m[s[s_index + 1]],
            )

            s_index += 2

    for i, n in enumerate(h):
        h[i] = n ^ v[i] ^ v[i + 8]


def blake2(d: List[Block], ll: int, kk: Word, nn: Word) -> List[int]:
    h = List(IV[:8])

    h[0] ^= 0x01010000 ^ (kk << 8) ^ nn

    if len(d) > 1:
        for i, w in enumerate(d[:-1]):
            f(h, w, (i + 1) * BB, False)

    ll = ll + BB if kk > 0 else ll
    f(h, d[-1], ll, True)

    output = bytearray()
    for n in h:
        output.extend(struct.pack("<Q", n))

    return List(output)[: nn // 8]


def bytes_to_word(bytes_: bytes) -> Word:
    return struct.unpack("<Q", bytes_.ljust(U64BYTES, b"\x00"))[0]


def blake2b(m: bytes, k: bytes, nn: int) -> List[int]:
    kk = min(len(k), KK_MAX)
    nn = min(nn, NN_MAX)

    k = k[:kk]

    dd = max(ceil(kk, BB) + ceil(len(m), BB), 1)

    blocks = [blank_block() for _ in range(dd)]

    for w, c in zip(blocks[0], struct.iter_unpack("<Q", k)):
        w[:] = c

    first_index = int(kk > 0)

    for i, c in enumerate(struct.iter_unpack("<Q", m)):
        block_index = first_index + (i // (BB // U64BYTES))
        word_in_block = i % (BB // U64BYTES)

        blocks[block_index][word_in_block] = c[0]

    return blake2(blocks, len(m), kk, nn)

# -------------------------------- # 

def quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d = (d ^ a) & 0xFFFFFFFF
    d = (d << 16 | d >> 16) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b = (b ^ c) & 0xFFFFFFFF
    b = (b << 12 | b >> 20) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF
    d = (d ^ a) & 0xFFFFFFFF
    d = (d << 8 | d >> 24) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF
    b = (b ^ c) & 0xFFFFFFFF
    b = (b << 7 | b >> 25) & 0xFFFFFFFF
    return a, b, c, d

C = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

def chacha20(input, output):
    output[:] = input[:]
    for _ in range(10):
        output[0], output[4], output[8], output[12] = quarter_round(output[0], output[4], output[8], output[12])
        output[1], output[5], output[9], output[13] = quarter_round(output[1], output[5], output[9], output[13])
        output[2], output[6], output[10], output[14] = quarter_round(output[2], output[6], output[10], output[14])
        output[3], output[7], output[11], output[15] = quarter_round(output[3], output[7], output[11], output[15])
        output[0], output[5], output[10], output[15] = quarter_round(output[0], output[5], output[10], output[15])
        output[1], output[6], output[11], output[12] = quarter_round(output[1], output[6], output[11], output[12])
        output[2], output[7], output[8], output[13] = quarter_round(output[2], output[7], output[8], output[13])
        output[3], output[4], output[9], output[14] = quarter_round(output[3], output[4], output[9], output[14])
    
    for i in range(len(output)):
        output[i] = (output[i] + input[i]) & 0xFFFFFFFF

# ---------------------------------- #

def create_tar_gz(folder_name):
    fname = folder_name + ".tar.wdc"
    with tarfile.open(fname, "w:gz") as tar:
        print(f"Tarring {folder_name} to {fname}")
        tar.add(folder_name, arcname=os.path.basename(folder_name))
    shutil.rmtree(folder_name)
    print(f"Tarred {folder_name} to {fname}")

def tar_all_dirs():
    entries = os.scandir(".")
    processes = []
    for entry in entries:
        if entry.is_dir():
            pth = entry.path
            if not pth.startswith("."):
                print(f"{pth} is a directory!")
                processes.append(multiprocessing.Process(target=create_tar_gz, args=(pth,)))
    for process in processes:
        process.start()
    for process in processes:
        process.join()

def encrypt_file(fname, key):
    in_file = open(fname, "rb")
    encrypted_bytes = encrypt_bytes_to_string(key, in_file.read())
    in_file.close()
    out_file = open(encrypted_bytes, "wb")
    print(f"Encrypting {fname}")
    encrypt_file_to_file_buffered(key, open(fname, "rb"), out_file)
    out_file.close()
    os.remove(fname)

def decrypt_file(fname, key):
    in_file = open(fname, "rb")
    decrypted_file_name = decrypt_from_string(key, fname[2:])
    if not warn_if_file_exists(decrypted_file_name):
        return
    out_file = open(decrypted_file_name, "wb")
    print(f"Decrypting {decrypted_file_name}")
    decrypt_file_to_file_buffered(key, in_file, out_file)
    out_file.close()
    in_file.close()
    os.remove(fname)

def encrypt_all_files(fernet_key):
    entries = os.scandir(".")
    processes = []
    for entry in entries:
        if entry.is_file():
            file_name = entry.path
            if file_name != "./.secret.key":
                print(f"Encrypting {file_name}")
                processes.append(multiprocessing.Process(target=encrypt_file, args=(file_name, fernet_key)))
    for process in processes:
        process.start()
    for process in processes:
        process.join()

def decrypt_all_files(fernet_key):
    entries = os.scandir(".")
    processes = []
    for entry in entries:
        if entry.is_file():
            file_name = entry.path
            if file_name != "./.secret.key":
                print(f"Decrypting {file_name}")
                processes.append(multiprocessing.Process(target=decrypt_file, args=(file_name, fernet_key)))
    for process in processes:
        process.start()
    for process in processes:
        process.join()

def untar_dir(dir_name):
    print(dir_name)
    with tarfile.open(dir_name, "r:gz") as tar:
        print(f"Untarring {dir_name}")
        tar.extractall()
    os.remove(dir_name)

def untar_all_dirs():
    entries = os.scandir(".")
    processes = []
    for entry in entries:
        if entry.is_file() and entry.name.endswith(".tar.wdc"):
            pth = entry.path
            processes.append(multiprocessing.Process(target=untar_dir, args=(pth,)))
    for process in processes:
        process.start()
    for process in processes:
        process.join()


# -------------------------------- #

FERNET_FILE = ".secret.key"

def encrypt_bytes_to_string(key, content):
    fernet_instance = fernet.Fernet(key)
    return fernet_instance.encrypt(content).decode()

def encrypt_file_to_file_buffered(key, reader, writer):
    fernet_instance = fernet.Fernet(key)
    buffer = bytearray(8192)
    while True:
        n = reader.readinto(buffer)
        if n == 0:
            break
        encrypted_data = fernet_instance.encrypt(buffer[:n])
        writer.write(encrypted_data)
        writer.write(b"\n")
    writer.flush()

def decrypt_from_string(key, ciphertext):
    fernet_instance = fernet.Fernet(key)
    decrypted_data = fernet_instance.decrypt(ciphertext.encode())
    return decrypted_data.decode()

def decrypt_file_to_file_buffered(key, reader, writer):
    fernet_instance = fernet.Fernet(key)
    buffer = StringIO()
    while True:
        line = reader.readline()
        if not line:
            break
        buffer.write(line.rstrip())
    decrypted_data = fernet_instance.decrypt(buffer.getvalue().encode())
    writer.write(decrypted_data)
    writer.flush()

def write_fernet_key_to_file(key):
    if os.path.exists(FERNET_FILE):
        print(f"{FERNET_FILE} already exists")
        if ask_bool("Do you want to use the existing key?", False):
            return read_fernet_key_from_file()
        sys.exit(1)
    with open(FERNET_FILE, "w") as file:
        file.write(key)
    return key

def read_fernet_key_from_file():
    if not os.path.exists(FERNET_FILE):
        print(f"{FERNET_FILE} doesn't exist")
        sys.exit(1)
    with open(FERNET_FILE, "r") as file:
        key = file.read()
    return key


# --------------------------- #

class Hasher:
    def __init__(self, DIGEST_BYTES):
        self.DIGEST_BYTES = DIGEST_BYTES

    def new_default(self):
        pass

    def update(self, data):
        pass

    def get_hash(self):
        pass


class HMAC:
    def __init__(self, KEY_BYTES, DIGEST_BYTES, H):
        self.KEY_BYTES = KEY_BYTES
        self.DIGEST_BYTES = DIGEST_BYTES
        self.inner_internal_state = H()
        self.outer_internal_state = H()

    def new_default(self):
        hmac = HMAC(self.KEY_BYTES, self.DIGEST_BYTES, self.H)
        hmac.inner_internal_state = self.inner_internal_state.new_default()
        hmac.outer_internal_state = self.outer_internal_state.new_default()
        return hmac

    def add_key(self, key):
        if len(key) <= self.KEY_BYTES:
            tmp_key = bytearray([0] * self.KEY_BYTES)
            for i, b in enumerate(key):
                tmp_key[i] = b
            for i in range(len(tmp_key)):
                tmp_key[i] ^= 0x36
            self.inner_internal_state.update(tmp_key)
            for i in range(len(tmp_key)):
                tmp_key[i] ^= 0x6a
            self.outer_internal_state.update(tmp_key)
            return None
        else:
            return "Key is longer than `KEY_BYTES`."

    def update(self, data):
        self.inner_internal_state.update(data)

    def finalize(self):
        self.outer_internal_state.update(self.inner_internal_state.get_hash())
        return self.outer_internal_state.get_hash()


# -------------------------------- #

def kerninghan(n):
    count = 0

    while n > 0:
        n = n & (n - 1)
        count += 1

    return count

# ------------------------------------ #

import argparse

def main():
    parser = argparse.ArgumentParser(prog="wdcrypt", description="Encrypt your current working directory")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the current working directory")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the current working directory")
    args = parser.parse_args()

    if args.encrypt:
        encryption_key = write_fernet_key_to_file(fernet.Fernet.generate_key())
        tar_all_dirs()
        encrypt_all_files(encryption_key)

    if args.decrypt:
        encryption_key = read_fernet_key_from_file()
        decrypt_all_files(encryption_key)
        untar_all_dirs()

# ------------------------------------ #

UNKNOWN_CHARACTER = "........"
UNKNOWN_MORSE_CHARACTER = "_"

def encode(message):
    dictionary = _morse_dictionary()
    return ' '.join(dictionary.get(char.upper(), UNKNOWN_CHARACTER) for char in message)

def _morse_dictionary():
    return {
        "A": ".-",      "B": "-...",    "C": "-.-.",
        "D": "-..",     "E": ".",       "F": "..-.",
        "G": "--.",     "H": "....",    "I": "..",
        "J": ".---",    "K": "-.-",     "L": ".-..",
        "M": "--",      "N": "-.",      "O": "---",
        "P": ".--.",    "Q": "--.-",    "R": ".-.",
        "S": "...",     "T": "-",       "U": "..-",
        "V": "...-",    "W": ".--",     "X": "-..-",
        "Y": "-.--",    "Z": "--..",

        "1": ".----",   "2": "..---",   "3": "...--",
        "4": "....-",   "5": ".....",   "6": "-....",
        "7": "--...",   "8": "---..",   "9": "----.",
        "0": "-----",

        "&": ".-...",   "@": ".--.-.",  ":": "---...",
        ",": "--..--",  ".": ".-.-.-",  "'": ".----.",
        "\"": ".-..-.", "?": "..--..",  "/": "-..-.",
        "=": "-...-",   "+": ".-.-.",   "-": "-....-",
        "(": "-.--.",   ")": "-.--.-",  " ": "/",
        "!": "-.-.--",
    }

def _check_part(string):
    return all(c in ".- " for c in string)

def _check_all_parts(string):
    return all(_check_part(part) for part in string.split('/'))

def _decode_token(string):
    return _morse_to_alphanumeric_dictionary().get(string, UNKNOWN_MORSE_CHARACTER)

def _decode_part(string):
    return ''.join(_decode_token(token) for token in string.split(' '))

def decode(string):
    if not _check_all_parts(string):
        raise io.Error("Invalid morse code")
        
    partitions = [_decode_part(part) for part in string.split('/')]
    return ' '.join(partitions)

def _morse_to_alphanumeric_dictionary():
    return {
        ".-": "A",      "-...": "B",    "-.-.": "C",
        "-..": "D",     ".": "E",       "..-.": "F",
        "--.": "G",     "....": "H",    "..": "I",
        ".---": "J",    "-.-": "K",     ".-..": "L",
        "--": "M",      "-.": "N",      "---": "O",
        ".--.": "P",    "--.-": "Q",    ".-.": "R",
        "...": "S",     "-": "T",       "..-": "U",
        "...-": "V",    ".--": "W",     "-..-": "X",
        "-.--": "Y",    "--..": "Z",

        ".----": "1",   "..---": "2",   "...--": "3",
        "....-": "4",   ".....": "5",   "-....": "6",
        "--...": "7",   "---..": "8",   "----.": "9",
        "-----": "0",

        ".-...": "&",   ".--.-.": "@",  "---...": ":",
        "--..--": ",",  ".-.-.-": ".",  ".----.": "'",
        ".-..-.": "\"", "..--..": "?",  "-..-.": "/",
        "-...-": "=",   ".-.-.": "+",   "-....-": "-",
        "-.--.": "(",   "-.--.-": ")",  "/": " ",
        "-.-.--": "!",  "": ""
    }

# -------------------------------------------------- #

def encode_ascii(string):
    mapping = {
        'a': '11', 'A': '11',
        'b': '12', 'B': '12',
        'c': '13', 'C': '13',
        'd': '14', 'D': '14',
        'e': '15', 'E': '15',
        'f': '21', 'F': '21',
        'g': '22', 'G': '22',
        'h': '23', 'H': '23',
        'i': '24', 'I': '24',
        'j': '24', 'J': '24',
        'k': '25', 'K': '25',
        'l': '31', 'L': '31',
        'm': '32', 'M': '32',
        'n': '33', 'N': '33',
        'o': '34', 'O': '34',
        'p': '35', 'P': '35',
        'q': '41', 'Q': '41',
        'r': '42', 'R': '42',
        's': '43', 'S': '43',
        't': '44', 'T': '44',
        'u': '45', 'U': '45',
        'v': '51', 'V': '51',
        'w': '52', 'W': '52',
        'x': '53', 'X': '53',
        'y': '54', 'Y': '54',
        'z': '55', 'Z': '55'
    }
    return ''.join(mapping.get(c, '') for c in string)

def decode_ascii(string):
    mapping = {
        '11': 'A',
        '12': 'B',
        '13': 'C',
        '14': 'D',
        '15': 'E',
        '21': 'F',
        '22': 'G',
        '23': 'H',
        '24': 'I',
        '25': 'K',
        '31': 'L',
        '32': 'M',
        '33': 'N',
        '34': 'O',
        '35': 'P',
        '41': 'Q',
        '42': 'R',
        '43': 'S',
        '44': 'T',
        '45': 'U',
        '51': 'V',
        '52': 'W',
        '53': 'X',
        '54': 'Y',
        '55': 'Z'
    }
    return ''.join(mapping.get(string[i:i+2], ' ') for i in range(0, len(string), 2) if not string[i:i+2].isspace()).replace(' ', '')

# --------------------------------------------- #

def rail_fence_encrypt(plain_text, key):
    cipher = [''] * key
    index = 0
    direction = 1

    for c in plain_text:
        cipher[index] += c
        index += direction

        if index == 0 or index == key - 1:
            direction *= -1

    return ''.join(cipher)

def rail_fence_decrypt(cipher, key):
    indices = List(range(key)) + List(range(key - 2, 0, -1))
    cipher_text = [''] * len(cipher)

    for i, c in zip(indices, cipher):
        cipher_text[i] = c

    return ''.join(cipher_text)

def zigzag(n):
    return List(range(n - 1)) + List(range(n - 1, 0, -1))

# ------------------------------------------------- #

def rot13(text):
    to_enc = text.upper()
    encoded = []

    for c in to_enc:
        if 'A' <= c <= 'M':
            encoded.append(chr(ord(c) + 13))
        elif 'N' <= c <= 'Z':
            encoded.append(chr(ord(c) - 13))
        else:
            encoded.append(c)

    return ''.join(encoded)

# -------------------------------------------------- #

x, y, z = None, None, None

def quarter_round(v1, v2, v3, v4):
    v2 ^= ((v1 + v4) & 0xFFFFFFFF) << 7 | ((v1 + v4) & 0xFFFFFFFF) >> (32 - 7)
    v3 ^= ((v2 + v1) & 0xFFFFFFFF) << 9 | ((v2 + v1) & 0xFFFFFFFF) >> (32 - 9)
    v4 ^= ((v3 + v2) & 0xFFFFFFFF) << 13 | ((v3 + v2) & 0xFFFFFFFF) >> (32 - 13)
    v1 ^= ((v4 + v3) & 0xFFFFFFFF) << 18 | ((v4 + v3) & 0xFFFFFFFF) >> (32 - 18)

def salsa20(input_data, output):
    output[:] = input_data[:]

    for _ in range(10):
        quarter_round(output[0], output[4], output[8], output[12])
        quarter_round(output[5], output[9], output[13], output[1])
        quarter_round(output[10], output[14], output[2], output[6])
        quarter_round(output[15], output[3], output[7], output[11])
        quarter_round(output[0], output[1], output[2], output[3])
        quarter_round(output[5], output[6], output[7], output[4])
        quarter_round(output[10], output[11], output[8], output[9])
        quarter_round(output[15], output[12], output[13], output[14])

    for i in range(len(output)):
        output[i] = (output[i] + input_data[i]) & 0xFFFFFFFF

# --------------------------------------- #

B = 1600
W = B // 25
L = int(W.bit_length())
U8BITS = 8

def iterate(x, y, z, b):
    for y in range(5):
        for x in range(5):
            for z in range(W):
                b

def state_new():
    return [[[False] * W for _ in range(5)] for _ in range(5)]

def state_fill(dest, bits):
    i = 0

    def b():
        nonlocal i
        if i >= len(bits):
            return
        dest[x][y][z] = bits[i]
        i += 1

    iterate(0, 0, 0, b)

def state_copy(dest, src):
    def b():
        dest[x][y][z] = src[x][y][z]

    iterate(0, 0, 0, b)

def state_dump(state):
    bits = [False] * B
    i = 0

    def b():
        nonlocal i
        bits[i] = state[x][y][z]
        i += 1

    iterate(0, 0, 0, b)
    return bits

def theta(state):
    c = [[False] * W for _ in range(5)]
    d = [[False] * W for _ in range(5)]

    for x in range(5):
        for z in range(W):
            c[x][z] = state[x][0][z]

            for y in range(1, 5):
                c[x][z] ^= state[x][y][z]

    for x in range(5):
        for z in range(W):
            x1 = (x - 1) % 5
            z2 = (z - 1) % W

            d[x][z] = c[x1][z] ^ c[(x + 1) % 5][z2]

    def b():
        state[x][y][z] ^= d[x][z]

    iterate(0, 0, 0, b)

def rho(state):
    new_state = state_new()

    for z in range(W):
        new_state[0][0][z] = state[0][0][z]

    x = 1
    y = 0

    for t in range(24 + 1):
        for z in range(W):
            z_offset = ((t + 1) * (t + 2)) // 2
            new_z = (z - z_offset) % W

            new_state[x][y][z] = state[x][y][new_z]

        old_y = y
        y = (2 * x + 3 * y) % 5
        x = old_y

    state_copy(state, new_state)

def pi(state):
    new_state = state_new()

    def b():
        new_state[x][y][z] = state[(x + 3 * y) % 5][x][z]

    iterate(0, 0, 0, b)
    state_copy(state, new_state)

def chi(state):
    new_state = state_new()

    def b():
        new_state[x][y][z] = state[x][y][z] ^ ((state[(x + 1) % 5][y][z] ^ True) & state[(x + 2) % 5][y][z])

    iterate(0, 0, 0, b)
    state_copy(state, new_state)

def rc(t):
    r = 0x80

    for _ in range(t % 255):
        b1 = r >> 8
        b2 = r & 1
        r |= (b1 ^ b2) << 8

        b1 = (r >> 4) & 1
        r &= 0x1EF
        r |= (b1 ^ b2) << 4

        b1 = (r >> 3) & 1
        r &= 0x1F7
        r |= (b1 ^ b2) << 3

        b1 = (r >> 2) & 1
        r &= 0x1FB
        r |= (b1 ^ b2) << 2

        r >>= 1

    return (r >> 7) != 0

def iota(state, i_r):
    rc_arr = [False] * W

    for j in range(L + 1):
        rc_arr[(1 << j) - 1] = rc(j + 7 * i_r)

    for z, bit in enumerate(rc_arr):
        state[0][0][z] ^= bit

def rnd(state, i_r):
    theta(state)
    rho(state)
    pi(state)
    chi(state)
    iota(state, i_r)

def keccak_f(bits):
    n_r = 12 + 2 * L

    state = state_new()
    state_fill(state, bits)

    for i_r in range(n_r):
        rnd(state, i_r)

    return state_dump(state)

def pad101(x, m):
    j = -m - 2

    while j < 0:
        j += x

    j %= x

    ret = [False] * (j + 2)
    ret[0] = True
    ret[-1] = True

    return ret

def sponge(f, pad, r, n, d):
    p = n.copy()
    p.extend(pad(r, len(n)))

    assert r < B

    s = [False] * B

    for i in range(0, len(p), r):
        chunk = p[i:i+r]
        for s_i, c_i in zip(s, chunk):
            s_i ^= c_i

        s = f(s)

    z = []
    while len(z) < d:
        z.extend(s)
        s = f(s)

    return z[:d]

def keccak(c, n, d):
    return sponge(keccak_f, pad101, B - c, n, d)

def h2b(h, n):
    bits = []

    for byte in h:
        for i in range(U8BITS):
            mask = 1 << i
            bits.append((byte & mask) != 0)

    assert len(bits) == len(h) * U8BITS

    return bits[:n]

def b2h(s):
    m = (len(s) + U8BITS - 1) // U8BITS
    bytes_ = [0] * m

    for i, bit in enumerate(s):
        byte_index = i // U8BITS
        mask = (bit & 1) << (i % U8BITS)
        bytes_[byte_index] |= mask

    return bytes_

def sha3_224(m):
    temp = h2b(m, len(m) * U8BITS)
    temp += [False, True]

    temp = keccak(448, temp, 224)

    ret = bytearray((len(temp) + U8BITS - 1) // U8BITS)

    temp = b2h(temp)
    assert len(temp) == len(ret)

    for i, byte in enumerate(temp):
        ret[i] = byte

    return ret

def sha3_256(m):
    temp = h2b(m, len(m) * U8BITS)
    temp += [False, True]

    temp = keccak(512, temp, 256)

    ret = bytearray((len(temp) + U8BITS - 1) // U8BITS)

    temp = b2h(temp)
    assert len(temp) == len(ret)

    for i, byte in enumerate(temp):
        ret[i] = byte

    return ret

def sha3_384(m):
    temp = h2b(m, len(m) * U8BITS)
    temp += [False, True]

    temp = keccak(768, temp, 384)

    ret = bytearray((len(temp) + U8BITS - 1) // U8BITS)

    temp = b2h(temp)
    assert len(temp) == len(ret)

    for i, byte in enumerate(temp):
        ret[i] = byte

    return ret

def sha3_512(m):
    temp = h2b(m, len(m) * U8BITS)
    temp += [False, True]

    temp = keccak(1024, temp, 512)

    ret = bytearray((len(temp) + U8BITS - 1) // U8BITS)

    temp = b2h(temp)
    assert len(temp) == len(ret)

    for i, byte in enumerate(temp):
        ret[i] = byte

    return ret

# ------------------------------------ #

H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

def ch(x, y, z):
    return (x & y) ^ ((~x) & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def bsig0(x):
    return x >> 2 ^ x >> 13 ^ x >> 22

def bsig1(x):
    return x >> 6 ^ x >> 11 ^ x >> 25

def ssig0(x):
    return x >> 7 ^ x >> 18 ^ (x << 3)

def ssig1(x):
    return x >> 17 ^ x >> 19 ^ (x << 10)

class SHA256:
    def __init__(self):
        self.buffer = [0] * 16
        self.length = 0
        self.h = H0.copy()
        self.w = [0] * 64
        self.finalized = False
        self.round = [0] * 8

    def process_block(self, buf):
        self.w[:len(buf)] = buf
        for i in range(len(buf), len(self.w)):
            self.w[i] = ssig1(self.w[i - 2]) + self.w[i - 7] + ssig0(self.w[i - 15]) + self.w[i - 16]

        self.round[:] = self.h.copy()
        for i in range(len(self.w)):
            t1 = self.round[7] + bsig1(self.round[4]) + ch(self.round[4], self.round[5], self.round[6]) + K[i] + self.w[i]
            t2 = bsig0(self.round[0]) + maj(self.round[0], self.round[1], self.round[2])
            self.round[7] = self.round[6]
            self.round[6] = self.round[5]
            self.round[5] = self.round[4]
            self.round[4] = self.round[3] + t1
            self.round[3] = self.round[2]
            self.round[2] = self.round[1]
            self.round[1] = self.round[0]
            self.round[0] = t1 + t2

        for i in range(len(self.h)):
            self.h[i] += self.round[i]

    def update(self, data):
        if len(data) == 0:
            return

        offset = (((32 - (self.length & 31)) & 31) >> 3)
        buf_ind = ((self.length & 511) >> 5)

        for i, byte in enumerate(data[:offset]):
            self.buffer[buf_ind] ^= (byte << ((offset - i - 1) << 3))
        
        self.length += (len(data) << 3)

        if offset > len(data):
            return
        
        if offset > 0:
            buf_ind += 1
        
        if len(data) > 3:
            for i in range(offset, len(data) - 3, 4):
                if buf_ind & 16 == 16:
                    self.process_block(self.buffer)
                    buf_ind = 0

                self.buffer[buf_ind] = (data[i] << 24) ^ (data[i + 1] << 16) ^ (data[i + 2] << 8) ^ data[i + 3]
                buf_ind += 1
        
        if buf_ind & 16 == 16:
            self.process_block(self.buffer)
            buf_ind = 0
        
        self.buffer[buf_ind] = 0

        rem_ind = offset + ((len(data) - offset) & ~0b11)

        for i, byte in enumerate(data[rem_ind:]):
            self.buffer[buf_ind] ^= (byte << ((3 - i) << 3))

    def get_hash(self):
        if not self.finalized:
            self.finalized = True
            clen = (self.length + 8) & 511
            num_0 = (448 + 512 - clen) >> 3 if clen > 448 else (448 - clen) >> 3
            padding = bytes([0x80]) + bytes(num_0 + 9)
            padding[-8:] = self.length.to_bytes(8, 'big')
            self.update(padding)
        
        assert self.length & 511 == 0

        result = bytearray(32)
        for i in range(0, 32, 4):
            result[i] = (self.h[i >> 2] >> 24) & 0xFF
            result[i + 1] = (self.h[i >> 2] >> 16) & 0xFF
            result[i + 2] = (self.h[i >> 2] >> 8) & 0xFF
            result[i + 3] = self.h[i >> 2] & 0xFF
        
        return result

    @staticmethod
    def new_default():
        return SHA256()

# ---------------------------------- #


class TeaContext:
    def __init__(self, key):
        self.key0 = key[0]
        self.key1 = key[1]
    
    def encrypt_block(self, block):
        b0, b1 = divide_u64(block)
        k0, k1 = divide_u64(self.key0)
        k2, k3 = divide_u64(self.key1)
        sum = 0

        for _ in range(32):
            sum += 0x9E3779B9
            b0 += ((b1 << 4) + k0) ^ (b1 + sum) ^ ((b1 >> 5) + k1)
            b1 += ((b0 << 4) + k2) ^ (b0 + sum) ^ ((b0 >> 5) + k3)

        return (b1 & 0xFFFFFFFF) << 32 | (b0 & 0xFFFFFFFF)
    
    def decrypt_block(self, block):
        b0, b1 = divide_u64(block)
        k0, k1 = divide_u64(self.key0)
        k2, k3 = divide_u64(self.key1)
        sum = 0xC6EF3720

        for _ in range(32):
            b1 -= ((b0 << 4) + k2) ^ (b0 + sum) ^ ((b0 >> 5) + k3)
            b0 -= ((b1 << 4) + k0) ^ (b1 + sum) ^ ((b1 >> 5) + k1)
            sum -= 0x9E3779B9

        return (b1 & 0xFFFFFFFF) << 32 | (b0 & 0xFFFFFFFF)


def divide_u64(n):
    return n & 0xFFFFFFFF, n >> 32


def tea_encrypt(plain, key):
    tea = TeaContext([to_block(key[:8]), to_block(key[8:16])])
    result = []

    for i in range(0, len(plain), 8):
        block = to_block(plain[i:i + 8])
        result.extend(from_block(tea.encrypt_block(block)))

    return result


def tea_decrypt(cipher, key):
    tea = TeaContext([to_block(key[:8]), to_block(key[8:16])])
    result = []

    for i in range(0, len(cipher), 8):
        block = to_block(cipher[i:i + 8])
        result.extend(from_block(tea.decrypt_block(block)))

    return result


def to_block(data):
    return (
        data[0] |
        data[1] << 8 |
        data[2] << 16 |
        data[3] << 24 |
        data[4] << 32 |
        data[5] << 40 |
        data[6] << 48 |
        data[7] << 56
    )


def from_block(block):
    return [
        block & 0xFF,
        (block >> 8) & 0xFF,
        (block >> 16) & 0xFF,
        (block >> 24) & 0xFF,
        (block >> 32) & 0xFF,
        (block >> 40) & 0xFF,
        (block >> 48) & 0xFF,
        (block >> 56) & 0xFF
    ]


# ------------------------------------------ #

def theoretical_rot13(text):
    result = ""
    pos = 0
    npos = 0

    for c in text:
        if c.islower():
            pos = ord(c) - ord('a')
            npos = (pos + 13) % 26
            c = chr(npos + ord('a'))

        result += c

    return result

# ------------------------------------------------ #

def transposition(decrypt_mode, msg, key):
    key_uppercase = key.upper()
    cipher_msg = msg

    keys = key_uppercase.split() if not decrypt_mode else reversed(key_uppercase.split())

    for cipher_key in keys:
        key_order = []
        counter = 0

        cipher_msg = cipher_msg.upper()
        cipher_msg = "".join(filter(str.isalpha, cipher_msg))

        key_ascii = [(i, ord(c)) for i, c in enumerate(cipher_key.encode())]
        key_ascii.sort(key=lambda x: x[1])

        for i, key in key_ascii:
            key_ascii[i] = (i, counter)
            counter += 1

        key_ascii.sort(key=lambda x: x[0])

        for i, key in key_ascii:
            key_order.append(key)

        cipher_msg = encrypt(cipher_msg, key_order) if not decrypt_mode else decrypt(cipher_msg, key_order)

    return cipher_msg


def encrypt(msg, key_order):
    encrypted_msg = ""
    encrypted_vec = []
    msg_len = len(msg)
    key_len = len(key_order)
    msg_index = msg_len
    key_index = key_len

    while msg:
        chars = ""
        index = 0
        key_index -= 1

        while index < msg_index:
            ch = msg[index]
            chars += ch

            index += key_index
            msg_index -= 1

        encrypted_vec.append(chars)

    indexed_vec = [(key_index, encrypted_vec[i]) for i, key_index in enumerate(key_order)]
    indexed_vec.sort()

    indexed_msg = "".join([column for _, column in indexed_vec])

    msg_div = int(msg_len / key_len) + (msg_len % key_len > 0)
    counter = 0
    for c in indexed_msg:
        encrypted_msg += c
        counter += 1
        if counter == msg_div:
            encrypted_msg += ' '
            counter = 0

    return encrypted_msg.rstrip()


def decrypt(msg, key_order):
    decrypted_msg = ""
    decrypted_vec = []
    indexed_vec = []
    msg_len = len(msg)
    key_len = len(key_order)
    split_size = msg_len // key_len
    msg_mod = msg_len % key_len
    counter = msg_mod
    key_split = key_order.copy()
    split_large, split_small = key_split[:msg_mod], key_split[msg_mod:]

    split_large.sort(reverse=True)
    split_small.sort()

    for key_index in split_large:
        counter -= 1
        start = key_index * split_size + counter
        end = (key_index + 1) * split_size + counter + 1
        slice = msg[start:end]
        indexed_vec.append((key_index, slice))
        msg = msg[:start] + msg[end:]

    for key_index in split_small:
        slice = msg[:split_size]
        indexed_vec.append((key_index, slice))
        msg = msg[split_size:]

    indexed_vec.sort()

    for key in key_order:
        column = next((column for k, column in indexed_vec if k == key), None)
        if column:
            decrypted_vec.append(column)

    for _ in range(split_size):
        for i, column in enumerate(decrypted_vec):
            decrypted_msg += column[0]
            decrypted_vec[i] = column[1:]

    decrypted_msg += "".join(decrypted_vec)

    return decrypted_msg

# -------------------------------------- #

def read_line():
    return input()


def ask_bool(question, default):
    print(f"{question} {'[Y/n]' if default else '[y/N]'}: ", end="")
    input_str = read_line().lower()

    if input_str in ["y", "yes", "true"]:
        return True
    elif input_str in ["n", "no", "false"]:
        return False
    elif input_str == "":
        return default
    else:
        print(f"Invalid choice: '{input_str}'")
        return ask_bool(question, default)


def warn_if_file_exists(name):
    if os.path.exists(name):
        return ask_bool(f"File {name} already exists! Overwrite?", True)
    return True

# ---------------------------------------------- #

def xor_bytes(text, key):
    return [c ^ key for c in text]

def xor(text, key):
    return xor_bytes(text.encode(), key)

# ------------------------------------------------- #

ALPHABET_LOWER = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
]

ALPHABET_UPPER = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
]

NUMERIC = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']


class Alphabet:
    def find_position(self, c):
        raise NotImplementedError()

    def get_letter(self, index, is_uppercase):
        raise NotImplementedError()

    def modulo(self, i):
        return (((i % self.length() + self.length()) % self.length()) % self.length())

    def is_valid(self, text):
        return all(self.find_position(c) is not None for c in text)

    def scrub(self, text):
        return ''.join(c for c in text if self.find_position(c) is not None)

    def multiplicative_inverse(self, a):
        for x in range(1, self.length()):
            if self.modulo(a * x) == 1:
                return x
        return None

    def length(self):
        raise NotImplementedError()


class Standard(Alphabet):
    def find_position(self, c):
        if c in ALPHABET_LOWER:
            return ALPHABET_LOWER.index(c)
        elif c in ALPHABET_UPPER:
            return ALPHABET_UPPER.index(c)
        return None

    def get_letter(self, index, is_uppercase):
        if index > self.length():
            raise ValueError("Invalid index to the alphabet: {}.".format(index))

        if is_uppercase:
            return ALPHABET_UPPER[index]
        else:
            return ALPHABET_LOWER[index]

    def length(self):
        return 26


class Alphanumeric(Alphabet):
    def find_position(self, c):
        pos = Standard().find_position(c)
        if pos is not None:
            return pos
        elif c in NUMERIC:
            return NUMERIC.index(c) + 26
        return None

    def get_letter(self, index, is_uppercase):
        if index > self.length():
            raise ValueError("Invalid index to the alphabet: {}.".format(index))

        if index > 25:
            return NUMERIC[index - 26]
        elif is_uppercase:
            return ALPHABET_UPPER[index]
        else:
            return ALPHABET_LOWER[index]

    def length(self):
        return 36


class Playfair(Alphabet):
    def find_position(self, c):
        if c == 'J' or c == 'j':
            return None

        pos = Standard().find_position(c)
        if pos is not None:
            return pos - 1 if pos > 8 else pos

        return None

    def get_letter(self, index, is_uppercase):
        if index > self.length():
            raise ValueError("Invalid index to the alphabet: {}.".format(index))

        if is_uppercase:
            if index <= 8:
                return ALPHABET_UPPER[index]
            return ALPHABET_UPPER[index + 1]
        else:
            if index <= 8:
                return ALPHABET_LOWER[index]
            return ALPHABET_LOWER[index + 1]

    def length(self):
        return 25


def is_numeric(c):
    return c in NUMERIC


# Tests
import unittest


class TestAlphabet(unittest.TestCase):
    def test_valid_standard_char(self):
        valid_chars = list(ALPHABET_LOWER) + list(ALPHABET_UPPER)
        standard = Standard()
        for c in valid_chars:
            self.assertTrue(standard.is_valid(c))

    def test_invalid_standard_char(self):
        invalid_chars = "!🗡️@#$%^&*()!~-+=`':;.,<>?/}{][|]}0123456789"
        standard = Standard()
        for c in invalid_chars:
            self.assertFalse(standard.is_valid(c))

    def test_valid_alphanumeric_char(self):
        valid_chars = list(ALPHABET_LOWER) + list(ALPHABET_UPPER) + list(NUMERIC)
        alphanumeric = Alphanumeric()
        for c in valid_chars:
            self.assertTrue(alphanumeric.is_valid(c))

    def test_invalid_alphanumeric_char(self):
        invalid_chars = "!🗡️@#$%^&*()!~-+=`':;.,<>?/}{][|]}"
        alphanumeric = Alphanumeric()
        for c in invalid_chars:
            self.assertFalse(alphanumeric.is_valid(c))

    def test_find_j_in_playfiar(self):
        playfair = Playfair()
        self.assertIsNone(playfair.find_position('j'))

    def test_check_playfair_positions(self):
        playfair = Playfair()
        for i, former in enumerate("abcdefghi"):
            self.assertEqual(playfair.find_position(former), i)

        for i, latter in enumerate("klmnopqrstuvwxyz"):
            self.assertEqual(playfair.find_position(latter), 9 + i)

    def test_check_playfair_retrieval(self):
        playfair = Playfair()
        for i, former in enumerate("abcdefghi"):
            self.assertEqual(playfair.get_letter(i, False), former)
            self.assertEqual(playfair.get_letter(i, True), former.upper())

        for i, latter in enumerate("klmnopqrstuvwxyz"):
            self.assertEqual(playfair.get_letter(9 + i, False), latter)
            self.assertEqual(playfair.get_letter(9 + i, True), latter.upper())

# --------------------------------- # 

class Cipher(ABC):
    @staticmethod
    @abstractmethod
    def new(key):
        pass

    @abstractmethod
    def encrypt(self, message):
        pass

    @abstractmethod
    def decrypt(self, message):
        pass

# ---------------------------------- #

ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyz0123456789"
PLAYFAIR = "abcdefghiklmnopqrstuvwxyz"
STANDARD = "abcdefghijklmnopqrstuvwxyz"


def keyed_alphabet(key: str, alpha_type: str, to_uppercase: bool) -> str:
    if not all(c.isalpha() for c in key):
        raise ValueError("Key contains a non-alphabetic symbol.")

    keyed_alphabet = ""
    for c in key:
        if c.lower() not in keyed_alphabet.lower():
            add = c.upper() if to_uppercase else c.lower()
            keyed_alphabet += add

    for index in range(len(alpha_type)):
        c = alpha_type[index].upper() if to_uppercase else alpha_type[index].lower()
        if c.lower() not in keyed_alphabet.lower():
            keyed_alphabet += c

    return keyed_alphabet


def columnar_key(keystream: str) -> List[Tuple[str, List[str]]]:
    unique_chars = set(keystream)

    if not keystream:
        raise ValueError("The keystream is empty.")
    elif len(keystream) - len(unique_chars) > 0:
        raise ValueError("The keystream cannot contain duplicate alphanumeric characters.")
    elif any(not c.isalnum() for c in keystream):
        raise ValueError("The keystream cannot contain non-alphanumeric symbols.")

    return [(c, []) for c in keystream]


def polybius_square(key: str, column_ids: List[str], row_ids: List[str]) -> Dict[str, str]:
    unique_chars = set(key)

    if len(key) != 36:
        raise ValueError("The key must contain each character of the alphanumeric alphabet a-z 0-9.")
    elif len(key) - len(unique_chars) > 0:
        raise ValueError("The key cannot contain duplicate alphanumeric characters.")
    elif any(not c.isalnum() for c in key):
        raise ValueError("The key cannot contain non-alphanumeric symbols.")

    if any(not c.isalpha() for c in column_ids + row_ids):
        raise ValueError("The column and row ids cannot contain non-alphabetic symbols.")

    unique_cols = {c.lower(): c for c in column_ids}
    unique_rows = {c.lower(): c for c in row_ids}

    if len(column_ids) - len(unique_cols) > 0 or len(row_ids) - len(unique_rows) > 0:
        raise ValueError("The column or row ids cannot contain repeated characters.")

    polybius_square = {}
    values = iter(key)

    for row in row_ids[:6]:
        for column in column_ids[:6]:
            k = row + column
            v = next(values, None)

            if v is None:
                raise ValueError("Alphabet square is invalid.")

            if v.isnumeric():
                polybius_square[k.upper()] = v.upper()
            else:
                polybius_square[k.lower()] = v.lower()
                polybius_square[k.upper()] = v.upper()

    return polybius_square

PLAYFAIR = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

def playfair_table(keystream: str) -> Tuple[List[str], List[str]]:
    if len(keystream) == 0:
        raise ValueError("The keystream cannot be empty.")
    elif len(keystream) > len(PLAYFAIR):
        raise ValueError("The keystream length cannot exceed 25 characters.")
    elif not all(c.isalpha() and c.upper() != 'J' for c in keystream):
        raise ValueError("The keystream cannot contain non-alphabetic symbols or the letter 'J'.")

    unique = []
    upper = keystream.upper()
    keystream_iter = iter(upper + PLAYFAIR)

    for c in keystream_iter:
        if c not in unique:
            unique.append(c)

    rows = ["".join(r) for r in zip(*[iter(unique)] * 5)]
    cols = ["".join(r) for r in zip(*[iter(unique[i:])] * 5)]

    return (rows, cols)

# ---------------------------------------------------- #

def shift_substitution(text: str, calc_index: Callable[[int], int]) -> str:
    s_text = ""
    for c in text:
        pos = STANDARD.find_position(c)
        if pos is not None:
            si = calc_index(pos)
            s_text += STANDARD.get_letter(si, c.isupper())
        else:
            s_text += c
    return s_text


def key_substitution(text: str, keystream: str, calc_index: Callable[[int, int], int]) -> str:
    s_text = ""
    keystream_iter = iter(keystream)
    for tc in text:
        tpos = STANDARD.find_position(tc)
        if tpos is not None:
            try:
                kc = next(keystream_iter)
                ki = STANDARD.find_position(kc)
                if ki is not None:
                    si = calc_index(tpos, ki)
                    s_text += STANDARD.get_letter(si, tc.isupper())
                else:
                    raise ValueError("Keystream contains a non-alphabetic symbol.")
            except StopIteration:
                raise ValueError("Keystream is not large enough for full substitution of message.")
        else:
            s_text += tc
    return s_text

# ------------------------------------------- #

class ADFGVX:
    ADFGVX_CHARS = ['A', 'D', 'F', 'G', 'V', 'X']

    def __init__(self, key):
        p_key = self.keyed_alphabet(key[0], self.ALPHANUMERIC, False)
        self.polybius_cipher = Polybius((p_key, self.ADFGVX_CHARS, self.ADFGVX_CHARS))
        self.columnar_cipher = ColumnarTransposition((key[1], key[2]))

    def encrypt(self, message):
        step_one = self.polybius_cipher.encrypt(message)
        return self.columnar_cipher.encrypt(step_one)

    def decrypt(self, ciphertext):
        step_one = self.columnar_cipher.decrypt(ciphertext)
        return self.polybius_cipher.decrypt(step_one)

# -------------------------------------------- # 

class Affine:
    def __init__(self, key):
        a, b = key
        if not (1 <= a <= 26) or not (1 <= b <= 26):
            raise ValueError("The keys a & b must be within the range 1 <= n <= 26.")

        if Nums.Nums.Gcd(a, 26) > 1:
            raise ValueError("The key 'a' cannot share a common factor with 26.")

        self.a = a
        self.b = b

    def encrypt(self, message):
        return shift_substitution(message, lambda idx: (self.a * idx + self.b) % 26)

    def decrypt(self, ciphertext):
        a_inv = self.multiplicative_inverse(self.a)
        return shift_substitution(ciphertext, lambda idx: (a_inv * (idx - self.b)) % 26)

    @staticmethod
    def multiplicative_inverse(a):
        for x in range(1, 26):
            if (a * x) % 26 == 1:
                return x
        raise ValueError("Multiplicative inverse for 'a' could not be calculated.")
    
# ----------------------------------------- #

class Autokey:
    def __init__(self, key):
        if len(key) == 0:
            raise ValueError("The key must contain at least one character.")
        elif not self.is_valid(key):
            raise ValueError("The key cannot contain non-alphabetic symbols.")

        self.key = key

    @staticmethod
    def is_valid(key):
        return all(char.isalpha() for char in key)

    def encrypt(self, message):
        keystream = self.concatenated_keystream(self.key, message)
        return self.key_substitution(message, keystream, lambda mi, ki: (mi + ki) % 26)

    def decrypt(self, ciphertext):
        plaintext = ""
        keystream = list(self.key)
        stream_idx = 0

        for ct in ciphertext:
            ctpos = self.find_position(ct)
            if ctpos is not None:
                decrypted_character = ""
                if stream_idx < len(keystream):
                    kc = keystream[stream_idx]
                    ki = self.find_position(kc)
                    if ki is not None:
                        si = (ctpos - ki) % 26
                        decrypted_character = self.get_letter(si, ct.isupper())
                    else:
                        raise ValueError("Keystream contains a non-alphabetic symbol.")
                else:
                    raise ValueError("Keystream is not large enough for full substitution of message.")

                plaintext += decrypted_character
                keystream.append(decrypted_character)
                stream_idx += 1
            else:
                plaintext += ct

        return plaintext
    
# ----------------------------------------------------- #

CODE_LEN: int = 5

CODE_MAP = {
    "A": "AAAAA",
    "B": "AAAAB",
    "C": "AAABA",
    "D": "AAABB",
    "E": "AABAA",
    "F": "AABAB",
    "G": "AABBA",
    "H": "AABBB",
    "I": "ABAAA",
    "J": "ABAAB",
    "K": "ABABA",
    "L": "ABABB",
    "M": "ABBAA",
    "N": "ABBAB",
    "O": "ABBBA",
    "P": "ABBBB",
    "Q": "BAAAA",
    "R": "BAAAB",
    "S": "BAABA",
    "T": "BAABB",
    "U": "BABAA",
    "V": "BABAB",
    "W": "BABBA",
    "X": "BABBB",
    "Y": "BBAAA",
    "Z": "BBAAB",
}

ITALIC_CODES = {
    "A": r"\u{1D434}",
    "B": r"\u{1D435}",
    "C": r"\u{1D436}",
    "D": r"\u{1D437}",
    "E": r"\u{1D438}",
    "F": r"\u{1D439}",
    "G": r"\u{1D43a}",
    "H": r"\u{1D43b}",
    "I": r"\u{1D43c}",
    "J": r"\u{1D43d}",
    "K": r"\u{1D43e}",
    "L": r"\u{1D43f}",
    "M": r"\u{1D440}",
    "N": r"\u{1D441}",
    "O": r"\u{1D442}",
    "P": r"\u{1D443}",
    "Q": r"\u{1D444}",
    "R": r"\u{1D445}",
    "S": r"\u{1D446}",
    "T": r"\u{1D447}",
    "U": r"\u{1D448}",
    "V": r"\u{1D449}",
    "W": r"\u{1D44a}",
    "X": r"\u{1D44b}",
    "Y": r"\u{1D44c}",
    "Z": r"\u{1D44d}",
    "a": r"\u{1D622}",
    "b": r"\u{1D623}",
    "c": r"\u{1D624}",
    "d": r"\u{1D625}",
    "e": r"\u{1D626}",
    "f": r"\u{1D627}",
    "g": r"\u{1D628}",
    "h": r"\u{1D629}",
    "i": r"\u{1D62a}",
    "j": r"\u{1D62b}",
    "k": r"\u{1D62c}",
    "l": r"\u{1D62d}",
    "m": r"\u{1D62e}",
    "n": r"\u{1D62f}",
    "o": r"\u{1D630}",
    "p": r"\u{1D631}",
    "q": r"\u{1D632}",
    "r": r"\u{1D633}",
    "s": r"\u{1D634}",
    "t": r"\u{1D635}",
    "u": r"\u{1D636}",
    "v": r"\u{1D637}",
    "w": r"\u{1D638}",
    "x": r"\u{1D639}",
    "y": r"\u{1D63a}",
    "z": r"\u{1D63b}",
}


def get_code(use_distinct_alphabet: bool, key: str) -> str:
    code = ""
    key_upper = key.upper()
    if not use_distinct_alphabet:
        if key_upper == "J":
            key_upper = "I"
        elif key_upper == "U":
            key_upper = "V"
    
    if key_upper in CODE_MAP:
        code = CODE_MAP[key_upper]
    
    return code


def get_key(code: str) -> str:
    key = ""
    for _key, val in CODE_MAP.items():
        if val == code:
            key += _key
    
    return key


class Baconian:
    def __init__(self, key: Tuple[bool, Optional[str]]):
        self.use_distinct_alphabet = key[0]
        self.decoy_text = key[1] if key[1] is not None else self.generate_decoy_text()
    
    @staticmethod
    def generate_decoy_text() -> str:
        decoy_text = ""
        letters = list(ITALIC_CODES.keys())
        for _ in range(160):
            decoy_text += random.choice(letters)
        return decoy_text
    
    def encrypt(self, message: str) -> str:
        num_non_alphas = sum(1 for c in self.decoy_text if not c.isalpha())

        if (len(message) * CODE_LEN) > len(self.decoy_text) - num_non_alphas:
            raise ValueError("Message too long for supplied decoy text.")

        secret = "".join(get_code(self.use_distinct_alphabet, c) for c in message)

        num_alphas = 0
        num_non_alphas = 0
        for c in self.decoy_text:
            if num_alphas == len(secret):
                break
            if c.isalpha():
                num_alphas += 1
            else:
                num_non_alphas += 1

        decoy_slice = self.decoy_text[:num_alphas + num_non_alphas]

        decoy_msg = ""
        secret_iter = iter(secret)
        for c in decoy_slice:
            if c.isalpha():
                sc = next(secret_iter, None)
                if sc == "B":
                    italic = ITALIC_CODES[c]
                    decoy_msg += italic
                else:
                    decoy_msg += c
            else:
                decoy_msg += c

        return decoy_msg
    
    def decrypt(self, message: str) -> str:
        ciphertext = "".join("B" if c in ITALIC_CODES.values() else "A" for c in message if c.isalpha())

        plaintext = ""
        code = ""
        for c in ciphertext:
            code += c
            if len(code) == CODE_LEN:
                plaintext += get_key(code)
                code = ""
        
        return plaintext
    
# ------------------------------------------------- #

class Caesar(Cipher):
    def __init__(self, shift: int):
        if shift < 1 or shift > 26:
            raise ValueError("The shift factor must be within the range 1 <= n <= 26.")
        super().__init__(shift)

    def encrypt(self, message: str) -> str:
        return self._shift_substitution(message, lambda idx: Alphabet.STANDARD[(idx + self.shift) % 26])

    def decrypt(self, ciphertext: str) -> str:
        return self._shift_substitution(ciphertext, lambda idx: Alphabet.STANDARD[(idx - self.shift) % 26])

    @staticmethod
    def _shift_substitution(text: str, shift_fn: Callable[[int], str]) -> str:
        result = ""
        for char in text:
            if char.isalpha():
                index = Alphabet.STANDARD.index(char.upper())
                shifted_index = shift_fn(index)
                shifted_char = Alphabet.STANDARD[shifted_index]
                if char.islower():
                    shifted_char = shifted_char.lower()
                result += shifted_char
            else:
                result += char
        return result

# -------------------------------------------------- #


class ColumnarTransposition(Cipher):
    def __init__(self, key):
        if key[1] is not None:
            if key[0].find(key[1]) != -1:
                raise ValueError("The `keystream` contains a `null_char`.")
        derived_key = self.columnar_key(key[0])
        super().__init__(derived_key, key[0], key[1])

    def encrypt(self, message):
        if self.null_char is not None:
            if self.null_char in message:
                return "Message contains null characters."
        key = self.derived_key.copy()
        i = 0
        chars = iter(message.rstrip())
        while True:
            try:
                c = next(chars)
                key[i][1].append(c)
            except StopIteration:
                if i > 0:
                    if self.null_char is not None:
                        key[i][1].append(self.null_char)
                else:
                    break
            i = (i + 1) % len(key)

        key.sort(key=lambda x: Alphabet.STANDARD.find(x[0]))
        ciphertext = ''.join(''.join(column[1]) for column in key)
        return ciphertext

    def decrypt(self, ciphertext):
        key = self.derived_key.copy()
        chars = iter(ciphertext)
        max_col_size = int((len(ciphertext) / len(self.keystream)) + 0.5)
        offset = len(key) - (len(ciphertext) % len(key))
        offset_cols = ''.join(reversed(key[i][0] for i in range(len(key) - 1, len(key) - 1 - offset, -1)))
        if self.null_char is None and offset != len(key):
            offset_cols = ''
        key.sort(key=lambda x: Alphabet.STANDARD.find(x[0]))

        plaintext = ""
        for i in range(max_col_size):
            for chr in self.keystream:
                column = next((c for c in key if c[0] == chr), None)
                if column is not None:
                    if i < len(column[1]):
                        c = column[1][i]
                        if self.null_char is not None:
                            if c == self.null_char and not c.isspace():
                                break
                        plaintext += c
                else:
                    return "Could not find column during decryption."

        return plaintext.rstrip()

    @staticmethod
    def columnar_key(keystream):
        key = []
        for char in keystream:
            key.append((char, []))
        return key
    
# ------------------------------------------------ #

class FractionatedMorse(Cipher):
    TRIGRAPH_ALPHABET = [
        "...", "..-", "..|", ".-.", ".--", ".-|", ".|.", ".|-", ".||", "-..", "-.-", "-.|", "--.",
        "---", "--|", "-|.", "-|-", "-||", "|..", "|.-", "|.|", "|-.", "|--", "|-|", "||.", "||-"
    ]

    def __init__(self, key):
        if len(key) == 0:
            raise ValueError("Key is empty.")
        keyed_alphabet = self.keyed_alphabet(key)
        super().__init__(keyed_alphabet)
        self.keyed_alphabet = keyed_alphabet

    def encrypt(self, message):
        morse = self.encode_to_morse(message)
        self.pad(morse)
        return self.encrypt_morse(self.keyed_alphabet, morse)

    def decrypt(self, ciphertext):
        seq = self.decrypt_morse(self.keyed_alphabet, ciphertext)
        return self.decode_morse(seq)

    @staticmethod
    def encode_to_morse(message):
        if any(morse.encode_character(c) is None for c in message):
            return "Unsupported character detected in message."
        morse = ''.join(f"{morse.encode_character(c)}|" for c in message)
        morse += '|'
        return morse

    @staticmethod
    def encrypt_morse(key, morse):
        ciphertext = ''
        for i in range(0, len(morse), 3):
            trigraph = morse[i:i+3]
            pos = next((idx for idx, t in enumerate(FractionatedMorse.TRIGRAPH_ALPHABET) if t == trigraph), None)
            if pos is not None:
                ciphertext += key[pos]
            else:
                return "Unknown trigraph sequence within the morse code."
        return ciphertext

    @staticmethod
    def decrypt_morse(key, ciphertext):
        if any(c.upper() not in key for c in ciphertext):
            return "Ciphertext cannot contain non-alphabetic symbols."
        return ''.join(FractionatedMorse.TRIGRAPH_ALPHABET[key.index(c.upper())] for c in ciphertext)

    @staticmethod
    def decode_morse(sequence):
        plaintext = ''
        trigraphs = sequence.lstrip('|')
        for morse_seq in trigraphs.split('|'):
            if morse_seq == '':
                break
            c = decode(morse_seq)
            if c is not None:
                plaintext += c
            else:
                return "Unknown morsecode sequence in trigraphs."
        return plaintext

    @staticmethod
    def pad(morse_sequence):
        while len(morse_sequence) % 3 != 0:
            morse_sequence += '.'

    @staticmethod
    def keyed_alphabet(key):
        return keyed_alphabet(key, STANDARD, True)

# ------------------------------------- #

class Hill(Cipher):
    def __init__(self, key):
        if key.cols() != key.rows():
            raise ValueError("The key is not a square matrix.")

        m = key.clone().try_into().astype(float)
        if not np.allclose(np.linalg.inv(m), np.round(np.linalg.inv(m))):
            raise ValueError("The inverse of this matrix cannot be calculated for decryption.")

        if Nums.Gcd(int(m.det()), 26) != 1:
            raise ValueError("The inverse determinant of the key cannot be calculated.")

        super().__init__(key)

    def encrypt(self, message):
        return self.transform_message(self.key.clone().try_into().astype(float), message)

    def decrypt(self, ciphertext):
        inverse_key = self.calc_inverse_key(self.key.clone().try_into().astype(float))
        return self.transform_message(inverse_key, ciphertext)

    @staticmethod
    def from_phrase(phrase, chunk_size):
        if chunk_size < 2:
            raise ValueError("The chunk size must be greater than 1.")

        if chunk_size * chunk_size != len(phrase):
            raise ValueError("The square of the chunk size must equal the length of the phrase.")

        if not all(c in STANDARD for c in phrase):
            raise ValueError("Phrase cannot contain non-alphabetic symbols.")

        matrix = [STANDARD.find_position(c) for c in phrase]
        return Hill(Matrix(chunk_size, chunk_size, matrix))

    @staticmethod
    def transform_message(key, message):
        if not all(c in STANDARD for c in message):
            return "Message cannot contain non-alphabetic symbols."

        transformed_message = ""
        buffer = message

        chunk_size = key.rows()
        if len(buffer) % chunk_size > 0:
            padding = chunk_size - (len(buffer) % chunk_size)
            buffer += "a" * padding

        i = 0
        while i < len(buffer):
            chunk = buffer[i:i + chunk_size]
            transformed_chunk = Hill.transform_chunk(key, chunk)
            if transformed_chunk is None:
                return None

            transformed_message += transformed_chunk
            i += chunk_size

        return transformed_message

    @staticmethod
    def transform_chunk(key, chunk):
        transformed = ""

        if not all(c in STANDARD for c in chunk):
            raise ValueError("Chunk contains a non-alphabetic symbol.")

        if key.rows() != len(chunk):
            return "Cannot perform transformation on unequal vector lengths"

        index_representation = [STANDARD.find_position(c) for c in chunk]

        product = key * Matrix(len(index_representation), 1, index_representation)
        product = Computing.Round(product % 26.0)

        for i, pos in enumerate(product):
            orig = chunk[i]

            transformed += STANDARD.get_letter(int(pos), orig.isupper())

        return transformed

    @staticmethod
    def calc_inverse_key(key):
        det = key.det()

        det_inv = STANDARD.multiplicative_inverse(int(det))
        if det_inv is not None:
            inverse = key.inverse().astype(int)
            inverse = Nums.Mod(inverse * int(det), 26) * int(det_inv) % 26
            return inverse

        return None

# ------------------------------------------------ #

class Playfair(Cipher):
    def __init__(self, key):
        self.null_char = key[1].upper() if key[1] is not None else 'X'
        self.rows, self.cols = playfair_table(key[0])
        super().__init__(key)

    def encrypt(self, message):
        if not PLAYFAIR.is_valid(message):
            return "Message must only consist of alphabetic characters."
        elif self.null_char in message.upper():
            return "Message cannot contain the null character."

        bigrams = self.bigram(message.upper())
        return self.apply_rules(bigrams, lambda v, first, second: (v[(first + 1) % 5], v[(second + 1) % 5]))

    def decrypt(self, message):
        if not PLAYFAIR.is_valid(message):
            return "Message must only consist of alphabetic characters."

        bigrams = self.bigram(message.upper())
        return self.apply_rules(bigrams, lambda v, first, second: (v[first - 1 if first > 0 else 4], v[second - 1 if second > 0 else 4]))

    def apply_rules(self, bigrams, shift):
        text = ""
        for bigram in bigrams:
            chars = self.apply_slice(bigram, self.rows, shift)
            if chars is None:
                chars = self.apply_slice(bigram, self.cols, shift)
                if chars is None:
                    chars = self.apply_rectangle(bigram)
            text += chars[0] + chars[1]
        return text

    def bigram(self, message):
        if any(char.isspace() for char in message):
            raise ValueError("Message contains whitespace.")
        if not PLAYFAIR.is_valid(message):
            raise ValueError("Message must only consist of alphabetic characters.")

        bigrams = []
        message_iter = iter(message)
        for current in message_iter:
            try:
                next_char = next(message_iter)
                if next_char == current:
                    bigrams.append((current, self.null_char))
                else:
                    bigrams.append((current, next_char))
            except StopIteration:
                bigrams.append((current, self.null_char))
        return bigrams

    def apply_slice(self, b, slices, shift):
        for slice in slices:
            first = slice.find(b[0])
            second = slice.find(b[1])
            if first != -1 and second != -1:
                return shift(list(slice), first, second)
        return None

    def apply_rectangle(self, b):
        row_indices = find_corners(b, self.cols)
        col_indices = find_corners(b, self.rows)
        return self.rows[row_indices[0]][col_indices[1]], self.rows[row_indices[1]][col_indices[0]]

def find_corners(b, slices):
    indices = (0, 0)
    for i, slice in enumerate(slices):
        if b[0] in slice:
            indices = (i, slice.index(b[0]))
        elif b[1] in slice:
            indices = (i, slice.index(b[1]))
    return indices

# ------------------------------------------ #

class Polybius(Cipher):
    def __init__(self, key):
        alphabet_key = keyed_alphabet(key[0], ALPHANUMERIC, False)
        square = polybius_square(alphabet_key, key[1], key[2])
        self.square = square
        super().__init__(key)

    def encrypt(self, message):
        encrypted = ""
        for char in message:
            key = next((k for k, v in self.square.items() if v == char), None)
            if key is not None:
                encrypted += key
            else:
                encrypted += char
        return encrypted

    def decrypt(self, ciphertext):
        message = ""
        buffer = ""
        for char in ciphertext:
            if char in STANDARD:
                buffer += char
            else:
                message += char

            if len(buffer) == 2:
                value = self.square.get(buffer)
                if value is not None:
                    message += value
                else:
                    return "Unknown sequence in the ciphertext."
                buffer = ""
        return message

# ------------------------------------------------- #

SUBSTITUTION_TABLE = [
    [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12],
    [14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11],
    [15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10],
    [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9],
    [17, 18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 16,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7,  8],
    [18, 19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 16, 17,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6,  7],
    [19, 20, 21, 22, 23, 24, 25, 13, 14, 15, 16, 17, 18,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5,  6],
    [20, 21, 22, 23, 24, 25, 13, 14, 15, 16, 17, 18, 19,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4,  5],
    [21, 22, 23, 24, 25, 13, 14, 15, 16, 17, 18, 19, 20,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3,  4],
    [22, 23, 24, 25, 13, 14, 15, 16, 17, 18, 19, 20, 21,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2,  3],
    [23, 24, 25, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1,  2],
    [24, 25, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0,  1],
    [25, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,  0],
]

class Cipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        raise NotImplementedError

    def decrypt(self, ciphertext):
        raise NotImplementedError

def cyclic_keystream(key, message):
    key_len = len(key)
    return [key[i % key_len] for i in range(len(message))]

def key_substitution(message, keystream, substitution_fn):
    encrypted = ""
    for i in range(len(message)):
        mi = ord(message[i]) - ord('A')
        ki = ord(keystream[i]) - ord('A')
        encrypted += chr(ord('A') + substitution_fn(mi, ki))
    return encrypted

class Porta(Cipher):
    def __init__(self, key):
        if len(key) == 0:
            raise ValueError("The key is empty.")
        if not key.isalpha():
            raise ValueError("The key contains a non-alphabetic symbol.")
        super().__init__(key)

    def encrypt(self, message):
        keystream = cyclic_keystream(self.key, message)
        return key_substitution(message, keystream, lambda mi, ki: SUBSTITUTION_TABLE[ki // 2][mi])

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

# ------------------------------------------ #

class Railfence:
    def __init__(self, key):
        if key == 0:
            raise ValueError("The key is 0.")
        self.rails = key

    def encrypt(self, message):
        if self.rails == 1:
            return message

        table = [[(False, '.') for _ in range(len(message))] for _ in range(self.rails)]
        for col, element in enumerate(message):
            rail = self.calc_current_rail(col, self.rails)
            table[rail][col] = (True, element)

        encrypted = ""
        for row in table:
            for is_element, element in row:
                if is_element:
                    encrypted += element
        return encrypted

    def decrypt(self, ciphertext):
        if self.rails == 1:
            return ciphertext

        table = [[(False, '.') for _ in range(len(ciphertext))] for _ in range(self.rails)]
        for col in range(len(ciphertext)):
            rail = self.calc_current_rail(col, self.rails)
            table[rail][col] = (True, '.')

        ct_chars = iter(ciphertext)
        for row in table:
            for i, element in enumerate(row):
                if element[0]:
                    try:
                        row[i] = (True, next(ct_chars))
                    except StopIteration:
                        break

        message = ""
        for col in range(len(ciphertext)):
            rail = self.calc_current_rail(col, self.rails)
            message += table[rail][col][1]
        return message

    @staticmethod
    def calc_current_rail(col, total_rails):
        cycle = 2 * total_rails - 2
        if col % cycle <= cycle // 2:
            return col % cycle
        else:
            return cycle - col % cycle

# ------------------------------------- #

class Scytale:
    def __init__(self, key):
        if key == 0:
            raise ValueError("Invalid key, height cannot be zero.")
        self.height = key

    def encrypt(self, message):
        if self.height >= len(message) or self.height == 1:
            return message

        width = -(-len(message) // self.height)  # Equivalent to ceil(len(message) / self.height)
        table = [[' ' for _ in range(width)] for _ in range(self.height)]

        for pos, element in enumerate(message):
            col = pos % self.height
            row = pos // self.height
            table[col][row] = element

        plaintext = ''.join(''.join(row) for row in table)
        return plaintext.rstrip()

    def decrypt(self, ciphertext):
        if self.height >= len(ciphertext) or self.height == 1:
            return ciphertext

        width = -(-len(ciphertext) // self.height)  # Equivalent to ceil(len(ciphertext) / self.height)
        table = [[' ' for _ in range(width)] for _ in range(self.height)]

        for pos, element in enumerate(ciphertext):
            col = pos // width
            row = pos % width
            table[col][row] = element

        plaintext = ''
        while any(table):
            for column in table:
                if column:
                    plaintext += column.pop(0)

        return plaintext.rstrip()
    
# --------------------------------------------- #

class Vigenere:
    def __init__(self, key):
        if len(key) == 0:
            raise ValueError("The key is empty.")
        if not all(c.isalpha() for c in key):
            raise ValueError("The key contains a non-alphabetic symbol.")
        self.key = key

    def encrypt(self, message):
        keystream = cyclic_keystream(self.key, message)
        encrypted_message = ""
        for mi, ki in zip(message, keystream):
            encrypted_char = chr((ord(mi) + ord(ki)) % 26 + 65)  
            encrypted_message += encrypted_char
        return encrypted_message

    def decrypt(self, ciphertext):
        keystream = cyclic_keystream(self.key, ciphertext)
        decrypted_message = ""
        for ci, ki in zip(ciphertext, keystream):
            decrypted_char = chr((ord(ci) - ord(ki)) % 26 + 65)  
            decrypted_message += decrypted_char
        return decrypted_message

# -------------------------------------------- #

SALTBYTES = 16
HASHEDPASSWORDBYTES = 32
STRPREFIX = b'$argon2id$'
OPSLIMIT_INTERACTIVE = 4
MEMLIMIT_INTERACTIVE = 33554432
OPSLIMIT_MODERATE = 6
MEMLIMIT_MODERATE = 67108864
OPSLIMIT_SENSITIVE = 8
MEMLIMIT_SENSITIVE = 134217728
VARIANT = 0

class OpsLimit:
    def __init__(self, value):
        self.value = value

class MemLimit:
    def __init__(self, value):
        self.value = value

class Salt(bytes):
    def __new__(cls, value):
        return super().__new__(cls, value)

class HashedPassword(bytes):
    def __new__(cls, value):
        return super().__new__(cls, value)

def randombytes_into(buffer):
    randombytes = bytearray(random.getrandbits(8) for _ in range(len(buffer)))
    buffer[0:len(randombytes)] = randombytes

def gen_salt():
    salt = Salt(bytearray(SALTBYTES))
    randombytes_into(salt)
    return salt

def derive_key(key, passwd, salt, opslimit, memlimit):
    res = argon2id_hash_raw(
        ctypes.byref(key),
        ctypes.c_ulonglong(len(key)),
        passwd,
        ctypes.c_ulonglong(len(passwd)),
        salt,
        ctypes.c_ulonglong(opslimit),
        ctypes.c_size_t(memlimit),
        ctypes.c_size_t(VARIANT)
    )
    if res == 0:
        return key
    else:
        raise Exception("Key derivation failed")

def pwhash(passwd, opslimit, memlimit):
    out = HashedPassword(bytearray(HASHEDPASSWORDBYTES))
    res = argon2id_hash_encoded(
        out,
        passwd,
        ctypes.c_ulonglong(len(passwd)),
        ctypes.c_ulonglong(opslimit),
        ctypes.c_size_t(memlimit)
    )
    if res == 0:
        return out
    else:
        raise Exception("Password hashing failed")

def pwhash_verify(hp, passwd):
    res = argon2id_verify(hp, passwd, ctypes.c_ulonglong(len(passwd)))
    return res == 0

argon2id_hash_raw = argon2.argon2id_hash_raw
argon2id_hash_raw.restype = ctypes.c_int
argon2id_hash_raw.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_ulonglong,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_ulonglong,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_ulonglong,
    ctypes.c_size_t,
    ctypes.c_size_t
]

argon2id_hash_encoded = argon2.argon2id_hash_encoded
argon2id_hash_encoded.restype = ctypes.c_int
argon2id_hash_encoded.argtypes = [
    ctypes.POINTER(ctypes.c_char),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_ulonglong,
    ctypes.c_ulonglong,
    ctypes.c_size_t
]

argon2id_verify = argon2.argon2id_verify
argon2id_verify.restype = ctypes.c_int
argon2id_verify.argtypes = [
    ctypes.POINTER(ctypes.c_char),
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_ulonglong
]

# -------------------------------------------------- #

SALTBYTES = 16
HASHEDPASSWORDBYTES = 32

def gen_salt():
    return os.urandom(SALTBYTES)

def derive_key(key, passwd, salt, opslimit, memlimit):
    argon2_hash = hashlib.argon2_hash_password(
        password=passwd,
        salt=salt,
        time_cost=opslimit,
        memory_cost=memlimit,
        parallelism=1,
        hash_len=HASHEDPASSWORDBYTES,
        type=hashlib.TYPE_ARGON2ID
    )
    derived_key = argon2_hash[:len(key)]
    return derived_key if argon2_hash == derived_key else None

def pwhash(passwd, opslimit, memlimit):
    salt = gen_salt()
    derived_key = derive_key([0] * HASHEDPASSWORDBYTES, passwd, salt, opslimit, memlimit)
    if derived_key is not None:
        return bytes(derived_key)
    else:
        raise ValueError("Failed to derive key.")

def pwhash_verify(hp, passwd):
    try:
        return hp == pwhash(passwd, 1, 65536)
    except ValueError:
        return False
    
# -------------------------------------------------- #


class HashedPassword:
    def __init__(self, value):
        self.value = value

class Salt:
    def __init__(self, value):
        self.value = value

class OpsLimit:
    def __init__(self, value):
        self.value = value

class MemLimit:
    def __init__(self, value):
        self.value = value

lib = CDLL("path/to/libcrypto.so")  # Replace with the actual library path

def derive_key(out, password, salt, ops, mem):
    lib.crypto_pwhash_argon2i.argtypes = [
        c_ulonglong, c_ulonglong, c_ulonglong,
        c_ulonglong, c_ulonglong, c_ulonglong,
        c_ulonglong, c_ulonglong, c_ulonglong,
        c_ulonglong, c_ulonglong, c_ulonglong,
        c_ulonglong, c_ulonglong, c_ulonglong
    ]
    lib.crypto_pwhash_argon2i.restype = c_ulonglong

    res = lib.crypto_pwhash_argon2i(
        out, len(out), password, len(password),
        salt, ops, mem, lib.crypto_pwhash_ALG_ARGON2I13
    )

    if res != 0:
        raise Exception("Key derivation failed")

def pwhash(out, password, ops, mem):
    salt = create_string_buffer(lib.crypto_pwhash_argon2i_SALTBYTES)
    lib.randombytes(salt, lib.crypto_pwhash_argon2i_SALTBYTES)

    derive_key(out, password, salt, ops, mem)

def pwhash_verify(hashed_password, password):
    lib.crypto_pwhash_argon2i_str_verify.argtypes = [c_char_p, c_char_p, c_ulonglong]
    lib.crypto_pwhash_argon2i_str_verify.restype = c_int

    res = lib.crypto_pwhash_argon2i_str_verify(
        hashed_password, password, len(password)
    )

    return res == 0

def gen_salt():
    salt = create_string_buffer(lib.crypto_pwhash_argon2i_SALTBYTES)
    lib.randombytes(salt, lib.crypto_pwhash_argon2i_SALTBYTES)
    return salt

def run_derive_key_test(password, salt, expected, out_len, ops, mem):
    out_bin = create_string_buffer(out_len)

    derive_key(out_bin, password, salt, ops, mem)

    if out_bin.raw != expected:
        raise Exception("Output does not match expected result")

# -------------------------------------------- #

def hash_password(password):
    salt = os.urandom(16)

    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    encoded_salt = base64.b64encode(salt).decode('utf-8')
    encoded_password = base64.b64encode(hashed_password).decode('utf-8')

    return f"$bcrypt${bcrypt.DEFAULT_COST}${encoded_salt}${encoded_password}"

def verify_password(password, hashed_password):
    parts = hashed_password.split('$')
    if len(parts) != 4 or parts[1] != 'bcrypt':
        return False

    cost = int(parts[2])
    salt = base64.b64decode(parts[3])
    decoded_password = base64.b64decode(parts[4])

    result = bcrypt.hashpw(password, salt)

    return result == decoded_password

# -------------------------------------------------------- #

def pbkdf2(password, salt, iterations, dk_len):
    BLOCK_SIZE = 64

    result = bytearray(dk_len)
    hmac_result = bytearray(BLOCK_SIZE)
    block = bytearray(BLOCK_SIZE)

    num_blocks = (dk_len // BLOCK_SIZE) + (dk_len % BLOCK_SIZE > 0)

    for i in range(1, num_blocks + 1):
        block[0:4] = (i).to_bytes(4, 'big')

        hmac_hash(password, block, hmac_result)
        xor_bytes(hmac_result, salt, result[(i - 1) * BLOCK_SIZE:i * BLOCK_SIZE])

        for _ in range(1, iterations):
            hmac_hash(password, hmac_result, hmac_result)
            xor_bytes(hmac_result, result[(i - 1) * BLOCK_SIZE:i * BLOCK_SIZE], result[(i - 1) * BLOCK_SIZE:i * BLOCK_SIZE])

    result = bytes(result[:dk_len])
    return result

def hmac_hash(key, data, output):
    hmac_obj = hmac(key, data, hashlib.sha256)
    output[:len(hmac_obj.digest())] = hmac_obj.digest()

def xor_bytes(a, b, output):
    for i in range(len(output)):
        output[i] = a[i] ^ b[i]

# ------------------------------------------------ #

DIGESTBYTES = 32
BLOCKBYTES = 64

class Digest(bytearray):
    def __new__(cls, value):
        return super().__new__(cls, value)

def hash(m):
    h = Digest(DIGESTBYTES)
    _hash_name(h, m, len(m))
    return h

class State:
    def __init__(self):
        self.state = _hash_init()

    def update(self, data):
        _hash_update(self.state, data, len(data))

    def finalize(self):
        digest = Digest(DIGESTBYTES)
        _hash_final(self.state, digest)
        return digest

def _hash_name(output, data, length):
    hash_func = hashlib.sha256()
    hash_func.update(data[:length])
    output[:DIGESTBYTES] = hash_func.digest()

def _hash_init():
    return ctypes.create_string_buffer(BLOCKBYTES)

def _hash_update(state, data, length):
    hash_func = hashlib.sha256()
    hash_func.update(ctypes.string_at(state, BLOCKBYTES))
    hash_func.update(data[:length])
    ctypes.memmove(state, hash_func.digest(), DIGESTBYTES)

def _hash_final(state, digest):
    hash_func = hashlib.sha256()
    hash_func.update(ctypes.string_at(state, BLOCKBYTES))
    digest[:DIGESTBYTES] = hash_func.digest()

def test_hash_multipart():
    for i in range(256):
        m = random.randbytes(i)
        h = hash(m)
        state = State()
        for b in [m[j:j+3] for j in range(0, len(m), 3)]:
            state.update(b)
        h2 = state.finalize()
        assert h == h2
    
# ------------------------------------------------ #

def hmac(hash_func, key, message):
    BLOCK_SIZE = 64

    padded_key = key if len(key) <= BLOCK_SIZE else hash_func(key)
    padded_key += bytes([0x00] * (BLOCK_SIZE - len(padded_key)))

    opad = bytes(byte ^ 0x5C for byte in padded_key)
    ipad = bytes(byte ^ 0x36 for byte in padded_key)

    inner_hash_input = ipad + message
    inner_hash = hash_func(inner_hash_input)

    outer_hash_input = opad + inner_hash
    outer_hash = hash_func(outer_hash_input)

    return outer_hash

# ----------------------------------------------- #

class DiffieHellman:
    def __init__(self):
        self.p = None
        self.g = None
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_prime(self):
        prime_size = 256

        def is_prime(n):
            if n <= 1:
                return False
            if n <= 3:
                return True
            if n % 2 == 0 or n % 3 == 0:
                return False
            i = 5
            while i * i <= n:
                if n % i == 0 or n % (i + 2) == 0:
                    return False
                i += 6
            return True

        while True:
            candidate = random.randint(2**(prime_size-1), 2**prime_size)
            if is_prime(candidate):
                return candidate

    def generate_generator(self, p):
        two = 2
        phi_p = p - 1

        while True:
            candidate = random.randint(2, phi_p)
            if pow(candidate, 2, p) != 1 and pow(candidate, phi_p, p) != 1:
                return candidate

    def new(self):
        self.p = self.generate_prime()
        self.g = self.generate_generator(self.p)
        self.private_key = random.randint(2, self.p - 1)
        self.public_key = None
        self.shared_secret = None

    def generate_public_key(self):
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        return self.shared_secret

    def get_public_key(self):
        return self.public_key

    def get_shared_secret(self):
        return self.shared_secret

# ------------------------------------------- #

def hmac(key, message):
    BLOCK_SIZE = 64

    if len(key) > BLOCK_SIZE:
        key_hash = hashlib.sha256(key).digest()
        key = key_hash
    else:
        key = key

    padded_key = bytearray(BLOCK_SIZE)
    if len(key) < BLOCK_SIZE:
        padded_key[:len(key)] = key
    else:
        padded_key[:] = key

    ipad = xor_bytes(padded_key, bytes([0x36] * BLOCK_SIZE))
    opad = xor_bytes(padded_key, bytes([0x5C] * BLOCK_SIZE))

    inner_hash = hashlib.sha256(ipad + message).digest()
    hmac_hash = hashlib.sha256(opad + inner_hash).digest()

    return hmac_hash

# ------------------------------------------- #

S = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]

def md5(input_bytes):
    def left_rotate(x, amount):
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

    def process_chunk(chunk, state):
        a, b, c, d = state

        buffer = [0] * 16
        for i, byte in enumerate(chunk):
            buffer[i // 4] |= byte << ((i % 4) * 8)

        for i in range(64):
            if i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            f = (f + a + S[i] + buffer[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + left_rotate(f, [7, 12, 17, 22][i % 4])) & 0xFFFFFFFF

        state[0] = (state[0] + a) & 0xFFFFFFFF
        state[1] = (state[1] + b) & 0xFFFFFFFF
        state[2] = (state[2] + c) & 0xFFFFFFFF
        state[3] = (state[3] + d) & 0xFFFFFFFF

    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    message_length = len(input_bytes)
    padded_length = ((message_length + 8) // 64 + 1) * 64
    padded_message = bytearray(padded_length)
    padded_message[:message_length] = input_bytes
    padded_message[message_length] = 0x80
    padded_message[padded_length - 8:padded_length] = int.to_bytes(
        message_length * 8, length=8, byteorder='little'
    )

    for i in range(0, padded_length, 64):
        process_chunk(padded_message[i:i + 64], state)

    return b"".join(int.to_bytes(word, length=4, byteorder='little') for word in state)

# ----------------------------------------------------- #

def hash_password(password):
    salt = b'salt'  
    N = 2**14 
    r = 8  
    p = 1  

    derived_key = hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=32)

    return derived_key.hex()

def verify_password(password, hashed_password):
    derived_key = bytes.fromhex(hashed_password)
    salt = b'salt'  # Get the salt used during hashing

    N = 2**14  # CPU/memory cost factor
    r = 8  # Block size
    p = 1  # Parallelization factor

    derived_key_check = hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=32)

    return derived_key == derived_key_check

# ----------------------------------------- # 

SALTBYTES = 32
HASHEDPASSWORDBYTES = 128
STRPREFIX = b'$scrypt$'

OPSLIMIT_INTERACTIVE = 4
MEMLIMIT_INTERACTIVE = 33554432
OPSLIMIT_SENSITIVE = 6
MEMLIMIT_SENSITIVE = 134217728


class Salt(bytes):
    def __new__(cls, value):
        if len(value) != SALTBYTES:
            raise ValueError("Invalid salt length")
        return super().__new__(cls, value)


class HashedPassword(bytes):
    def __new__(cls, value):
        if len(value) != HASHEDPASSWORDBYTES:
            raise ValueError("Invalid hashed password length")
        return super().__new__(cls, value)


def gen_salt():
    return Salt(bytes([random.randint(0, 255) for _ in range(SALTBYTES)]))


def derive_key(key, passwd, salt, opslimit, memlimit):
    m = hashlib.scrypt(
        passwd,
        salt=salt,
        n=opslimit,
        r=8,
        p=1,
        dklen=len(key),
        maxmem=memlimit,
    )
    return m


def derive_key_interactive(key, passwd, salt):
    return derive_key(
        key,
        passwd,
        salt,
        OPSLIMIT_INTERACTIVE,
        MEMLIMIT_INTERACTIVE,
    )


def derive_key_sensitive(key, passwd, salt):
    return derive_key(
        key,
        passwd,
        salt,
        OPSLIMIT_SENSITIVE,
        MEMLIMIT_SENSITIVE,
    )


def pwhash(passwd, opslimit, memlimit):
    hashed = hashlib.scrypt(
        passwd,
        salt=gen_salt(),
        n=opslimit,
        r=8,
        p=1,
        dklen=HASHEDPASSWORDBYTES,
        maxmem=memlimit,
    )
    return HashedPassword(hashed)


def pwhash_interactive(passwd):
    return pwhash(passwd, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)


def pwhash_sensitive(passwd):
    return pwhash(passwd, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE)


def pwhash_verify(hp, passwd):
    hashed = hp[7:]  # Strip the '$scrypt$' prefix
    try:
        derive_key(bytes(len(hashed)), passwd, Salt(hashed[:SALTBYTES]), OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE)
        return True
    except:
        return False

# ----------------------------------------- #

BLOCK_SIZE = 64


def sha1(input):
    state = [
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    ]

    message = pad_message(input)

    for block in chunks(message, BLOCK_SIZE):
        words = create_word_array(block)

        a = state[0]
        b = state[1]
        c = state[2]
        d = state[3]
        e = state[4]

        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (a << 5) & 0xFFFFFFFF | (a >> 27)
            temp = (temp + f + e + k + words[i]) & 0xFFFFFFFF

            e = d
            d = (c << 30) & 0xFFFFFFFF | (c >> 2)
            c = b
            b = a
            a = temp

        state[0] = (state[0] + a) & 0xFFFFFFFF
        state[1] = (state[1] + b) & 0xFFFFFFFF
        state[2] = (state[2] + c) & 0xFFFFFFFF
        state[3] = (state[3] + d) & 0xFFFFFFFF
        state[4] = (state[4] + e) & 0xFFFFFFFF

    result = bytearray()
    for word in state:
        result.extend(struct.pack('>I', word))

    return result


def pad_message(input):
    message_len = len(input)
    padded_message = bytearray(input)

    padded_message.append(0x80)
    padding_bytes = (56 - (message_len + 1) % BLOCK_SIZE) % BLOCK_SIZE
    padded_message.extend(bytes(padding_bytes))

    bit_length = (message_len << 3).to_bytes(8, 'big')
    padded_message.extend(bit_length)

    return padded_message


def create_word_array(block):
    words = bytearray(block)

    for i in range(16, 80):
        word = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16])
        words.extend(word.to_bytes(4, 'big'))

    return struct.unpack('>80I', words)

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

# ----------------------------------- #

BLOCK_SIZE = 128

def sha512(input):
    state = [
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ]

    message = pad_message(input)

    for block in chunks(message, BLOCK_SIZE):
        words = [0] * 80

        for i, chunk in enumerate(chunks(block, 8)):
            words[i] = int.from_bytes(chunk, 'big')

        for i in range(16, 80):
            s0 = (words[i - 15] >> 1 | words[i - 15] << 63) ^ (words[i - 15] >> 8 | words[i - 15] << 56) ^ (words[i - 15] >> 7)
            s1 = (words[i - 2] >> 19 | words[i - 2] << 45) ^ (words[i - 2] >> 61 | words[i - 2] << 3) ^ (words[i - 2] >> 6)
            words[i] = (
                words[i - 16] + s0 + words[i - 7] + s1
            ) & 0xFFFFFFFFFFFFFFFF

        a, b, c, d, e, f, g, h = state

        for i in range(80):
            s1 = (e >> 14 | e << 50) ^ (e >> 18 | e << 46) ^ (e >> 41 | e << 23)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (
                h + s1 + ch + K[i] + words[i]
            ) & 0xFFFFFFFFFFFFFFFF
            s0 = (a >> 28 | a << 36) ^ (a >> 34 | a << 30) ^ (a >> 39 | a << 25)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFFFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

        state[0] = (state[0] + a) & 0xFFFFFFFFFFFFFFFF
        state[1] = (state[1] + b) & 0xFFFFFFFFFFFFFFFF
        state[2] = (state[2] + c) & 0xFFFFFFFFFFFFFFFF
        state[3] = (state[3] + d) & 0xFFFFFFFFFFFFFFFF
        state[4] = (state[4] + e) & 0xFFFFFFFFFFFFFFFF
        state[5] = (state[5] + f) & 0xFFFFFFFFFFFFFFFF
        state[6] = (state[6] + g) & 0xFFFFFFFFFFFFFFFF
        state[7] = (state[7] + h) & 0xFFFFFFFFFFFFFFFF

    result = bytearray(64)
    for i, word in enumerate(state):
        result[i * 8] = (word >> 56) & 0xFF
        result[i * 8 + 1] = (word >> 48) & 0xFF
        result[i * 8 + 2] = (word >> 40) & 0xFF
        result[i * 8 + 3] = (word >> 32) & 0xFF
        result[i * 8 + 4] = (word >> 24) & 0xFF
        result[i * 8 + 5] = (word >> 16) & 0xFF
        result[i * 8 + 6] = (word >> 8) & 0xFF
        result[i * 8 + 7] = word & 0xFF

    return result

def pad_message(input):
    message_len = len(input)
    padded_message = bytearray(input)

    padded_message.append(0x80)

    padding_bytes = (112 - (message_len + 1) % BLOCK_SIZE) % BLOCK_SIZE
    padded_message.extend(bytes(padding_bytes))

    bit_length = (message_len * 8).to_bytes(16, 'big')
    padded_message.extend(bit_length)

    return padded_message

def chunks(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]

K = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
]

# ------------------------------------------------ #

DIGESTBYTES = 8
KEYBYTES = 16

class Digest(ctypes.Structure):
    _fields_ = [('value', ctypes.c_ubyte * DIGESTBYTES)]

class Key(ctypes.Structure):
    _fields_ = [('value', ctypes.c_ubyte * KEYBYTES)]

def gen_key():
    k = Key()
    for i in range(KEYBYTES):
        k.value[i] = random.randint(0, 255)
    return k

def shorthash(m, k):
    h = Digest()
    FFI.crypto_shorthash_siphash24(ctypes.byref(h), m, len(m), ctypes.byref(k))
    return h