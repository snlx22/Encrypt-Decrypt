#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define AES_256_KEY_SIZE 32  // 256 bits
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024

int EncryptFile(FILE *ifp, FILE *ofp, unsigned char *aes_key, unsigned char *aes_iv) {
    unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + AES_BLOCK_SIZE];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    while ((inlen = fread(inbuf, 1, BUFSIZE, ifp)) > 0) {
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            // encryption error
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, ofp);
    }

    if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &outlen)) {
        // finalization error
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, ofp);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_file(FILE *ifp, FILE *ofp, unsigned char *aes_key, unsigned char *aes_iv) {
    unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + AES_BLOCK_SIZE];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    while ((inlen = fread(inbuf, 1, BUFSIZE, ifp)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            // decryption error
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, ofp);
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf + outlen, &outlen)) {
        // finalization error
        fprintf(stderr, "erro ao finalizar decifração\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, ofp);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int main() {
    FILE *f_input, *f_encrypted, *f_decrypted;
    unsigned char aes_key[AES_256_KEY_SIZE];
    unsigned char aes_iv[AES_BLOCK_SIZE];

    // generate a random key and initialization vector
    if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(aes_iv, sizeof(aes_iv))) {
        fprintf(stderr, "Erro gerando chave/IV aleatórios.\n");
        return 1;
    }
  
    // open input file for reading
    f_input = fopen("input.txt", "rb");
    f_encrypted = fopen("encrypted.bin", "wb");
    if (f_input && f_encrypted) {
        if (!EncryptFile(f_input, f_encrypted, aes_key, aes_iv)) {
            fprintf(stderr, "Erro ao criptografar o arquivo.\n");
        }
        fclose(f_input);
        fclose(f_encrypted);
    } else {
        fprintf(stderr, "Erro ao abrir arquivos.\n");
        return 1;
    }

    // decrypt the file
    f_encrypted = fopen("encrypted.bin", "rb");
    f_decrypted = fopen("decrypted.txt", "wb");
    if (f_encrypted && f_decrypted) {
        if (!decrypt_file(f_encrypted, f_decrypted, aes_key, aes_iv)) {
            fprintf(stderr, "ERROR to decrypt the file.\n");
        }
        fclose(f_encrypted);
        fclose(f_decrypted);
    } else {
        fprintf(stderr, "ERROR to open the file.\n");
        return 1;
    }
    return 0;
}
