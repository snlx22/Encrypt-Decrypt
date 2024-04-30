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
