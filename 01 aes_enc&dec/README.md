# AES Encryption and Decryption in C

This directory contains an educational implementation of AES encryption and decryption in the C language.  
It demonstrates key scheduling, block encryption, and decryption for AES-128, AES-192, and AES-256.

## Overview
- The project is designed for learning and analysis, not for production use.
- The implementation follows the basic structure of AES: SubBytes, ShiftRows, MixColumns, and AddRoundKey.
- The code can encrypt and decrypt binary files in ECB or CBC mode.
- The key is not hardcoded and can be provided through command-line arguments, environment variables, or a key file.

## Files
- `aes.h` : AES constants, S-box tables, and function declarations.
- `aes_enc.c` : encryption functions and command-line interface for file encryption.
- `aes_dec.c` : decryption functions and command-line interface for file decryption.
- `main_test.c` : a small test driver using standard AES test vectors to verify correctness.

## Build
Example (using gcc):
```

gcc -o aes_enc aes_enc.c
gcc -o aes_dec aes_dec.c
gcc -o aes_test main_test.c aes_enc.c aes_dec.c

```

## Usage
Example commands:
```

./aes_enc ecb input.bin output.bin --key-hex 000102030405060708090A0B0C0D0E0F
./aes_dec ecb output.bin result.bin --key-hex 000102030405060708090A0B0C0D0E0F
./aes_test

```

## Key Input Options
- `--key-hex <hex string>` : specify key as hexadecimal string  
- `--key-file <filename>` : read key bytes from a file  
- `--key-env <env name>` : read key from environment variable (default: AES_KEY)

## Note
This code is written for educational and academic purposes.  
It should not be used in any security-critical or production environment.
