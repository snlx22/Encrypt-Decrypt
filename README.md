# File Encryption with OpenSSL

This repository contains a C program that demonstrates file encryption and decryption using the OpenSSL library with the AES-256-CBC algorithm. This program was developed for educational purposes to help understand how to implement file encryption in C using standard cryptography libraries.

## Features

- **Key and IV Generation**: The program generates a random AES-256 key and initialization vector (IV) for each encryption session.
- **File Encryption**: Capable of encrypting files in binary format using AES-256-CBC.
- **File Decryption**: Capable of decrypting files previously encrypted, restoring the original content.

## Prerequisites

To compile and run this program, you will need to have the OpenSSL library installed on your system. On Debian/Ubuntu-based systems, you can install OpenSSL with the following command:

```bash
sudo apt-get install libssl-dev
```

## Compilation

The program can be compiled using GCC or any other C compiler that supports linking with the OpenSSL library. Here is an example compilation command:

```bash
gcc -o file_crypto file_crypto.c -lssl -lcrypto
```

Replace file_crypto.c with the name of your source code file if different.

## Usage
After compilation, you can run the program using:

```bash
./file_crypto
```

Make sure to have a file named input.txt in the current directory as the program will try to encrypt it. After running, encrypted.bin and decrypted.txt will be created.

## Warning
This program is for educational purposes only and may not be suitable for production environments. It does not include comprehensive error handling or advanced security practices.

## Contributions
Contributions to improve the program are welcome. Feel free to fork the repository and submit your pull requests.

## License
MIT License
