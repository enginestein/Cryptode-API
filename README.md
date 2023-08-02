# Cryptode API and python framework

Introducing Cryptode: A Comprehensive Cryptography Framework

Cryptode is a state-of-the-art cryptography framework originally developed in pure Rust exclusively for the Rust programming language. However, it has now expanded its horizons and is available as an API for other programming languages, including Python and more.

With Cryptode, developers gain access to a wide range of powerful cryptographic functionalities. This framework leverages the robustness and efficiency of Rust to deliver secure and reliable encryption, decryption, and other cryptographic operations. By adhering to industry-standard cryptographic algorithms and protocols, Cryptode ensures the utmost security and integrity of data.

What sets Cryptode apart is its ability to seamlessly integrate into various programming environments. Whether you're a Rust enthusiast or prefer working with Python or other supported languages, Cryptode's versatile API allows you to harness its cryptographic capabilities in your preferred development ecosystem.

By incorporating Cryptode into your projects, you can confidently handle sensitive data, secure communications, and implement cutting-edge cryptographic techniques. Its availability across multiple programming languages broadens its reach and enables developers from different communities to leverage its robust cryptographic features.

Stay at the forefront of data security with Cryptode. Explore its vast array of cryptographic functions and unlock the power of secure communication and information protection in your applications. 

# Installation 

Run the following command to use cryptode in python:

```bash
pip install Cryptode
```

To use it after cloning repository:

```sh
cd Cryptode
py api.py
```

# Usage

All the code that handles the [Cryptode framework](https://github.com/enginestein/Cryptode) which is written in Rust is in the [cryptode.py](https://github.com/enginestein/Cryptode-API/blob/main/src/cryptode.py) file which wraps the Rust code to make it usable in Python. After installing Cryptode from pip, you can use Cryptode:

```py
from Cryptode import another_rot13

print(another_rot13("Hello World")) 
```

The above code encodes the text `Hello World` with Rot 13 encryption algorithm

Cryptode API is same as the Cryptode library for Rust but there are slight changes in the function names which are listed below:

-ABC
-ADFGVX
-ALPHABET_LOWER
-ALPHABET_UPPER
-ALPHANUMERIC
-Affine
-Alphabet
-Alphanumeric
-Autokey
-B
-BB
-BLOCKBYTES
-BLOCK_SIZE
-Baconian
-Block
-C
-CDLL
-CODE_LEN
-CODE_MAP
-Caesar
-Callable
-Cipher
-ColumnarTransposition
-Computing
-DIGESTBYTES
-Dict
-DiffieHellman
-Digest
-FERNET_FILE
-FFI
-FractionatedMorse
-H0
-HASHEDPASSWORDBYTES
-HMAC
-HashedPassword
-Hasher
-Hill
-ITALIC_CODES
-IV
-K
-KEYBYTES
-KK_MAX
-Key
-L
-List
-MEMLIMIT_INTERACTIVE
-MEMLIMIT_MODERATE
-MEMLIMIT_SENSITIVE
-Matrix
-MemLimit
-NN_MAX
-NUMERIC
-Nums
-OPSLIMIT_INTERACTIVE
-OPSLIMIT_MODERATE
-OPSLIMIT_SENSITIVE
-OpsLimit
-Optional
-PLAYFAIR
-Playfair
-Polybius
-Porta
-RC
-Railfence
-S
-SALTBYTES
-SHA256
-SIGMA
-STANDARD
-STRPREFIX
-SUBSTITUTION_TABLE
-Salt
-Scytale
-Standard
-State
-StringIO
-TeaContext
-TestAlphabet
-Tuple
-U64BYTES
-U8BITS
-UNKNOWN_CHARACTER
-UNKNOWN_MORSE_CHARACTER
-VARIANT
-Vigenere
-W
-Word
-__annotations__
-__builtins__
-__cached__
-__doc__
-__file__
-__loader__
-__name__
-__package__
-__spec__
-_check_all_parts
-_check_part
-_decode_part
-_decode_token
-_hash_final
-_hash_init
-_hash_name
-_hash_update
-_morse_dictionary
-_morse_to_alphanumeric_dictionary
-abstractmethod
-add
-another_rot13
-argon2
-argon2id_hash_encoded
-argon2id_hash_raw
-argon2id_verify
-argparse
-ask_bool
-b2h
-base64
-bcrypt
-blake2
-blake2b
-blank_block
-bsig0
-bsig1
-byref
-bytes_to_word
-c_char_p
-c_int
-c_ulonglong
-ceil
-ch
-chacha20
-chi
-chunks
-clr
-columnar_key
-create_string_buffer
-create_tar_gz
-create_word_array
-ctypes
-cyclic_keystream
-decode
-decode_ascii
-decrypt
-decrypt_all_files
-decrypt_file
-decrypt_file_to_file_buffered
-decrypt_from_string
-derive_key
-derive_key_interactive
-derive_key_sensitive
-divide_u64
-encode
-encode_ascii
-encrypt
-encrypt_all_files
-encrypt_bytes_to_string
-encrypt_file
-encrypt_file_to_file_buffered
-f
-fernet
-find_corners
-from_block
-g
-gen_key
-gen_salt
-get_code
-get_key
-h2b
-hash
-hash_password
-hashlib
-hmac
-hmac_hash
-io
-iota
-is_numeric
-iterate
-keccak
-keccak_f
-kerninghan
-key_substitution
-keyed_alphabet
-main
-maj
-md5
-multiprocessing
-np
-os
-pad101
-pad_message
-pbkdf2
-pi
-playfair_table
-polybius_square
-pwhash
-pwhash_interactive
-pwhash_sensitive
-pwhash_verify
-quarter_round
-rail_fence_decrypt
-rail_fence_encrypt
-random
-randombytes_into
-rc
-read_fernet_key_from_file
-read_line
-rho
-rnd
-rot13
-salsa20
-script_dir
-sha1
-sha3_224
-sha3_256
-sha3_384
-sha3_512
-sha512
-shift_substitution
-shorthash
-shutil
-sponge
-ssig0
-ssig1
-state_copy
-state_dump
-state_fill
-state_new
-struct
-sys
-tar_all_dirs
-tarfile
-tea_decrypt
-tea_encrypt
-test_hash_multipart
-theoretical_rot13
-theta
-to_block
-transposition
-unittest
-untar_all_dirs
-untar_dir
-verify_password
-warn_if_file_exists
-write_fernet_key_to_file
-x
-xor
-xor_bytes
-y
-z
-zigzag

Documentation is available [here](https://enginestein.github.io/Cryptode/) but the `pwhash` is not available in Cryptode API but is available in Cryptode.

You can visit Cryptode on [PyPI](https://pypi.org/project/Cryptode/)
