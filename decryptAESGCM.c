#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define KEY "pipocadoce?"


int hex_to_bytes(const char* hex_str, unsigned char* byte_array, size_t max_bytes);


int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <ciphertext_hex> <iv_hex> <GCM_tag_hex>\n", argv[0]);
        exit(1);
    }

    char *ciphertext_hex = argv[1];
    char *iv_hex = argv[2];
    char *GCM_tag_hex = argv[3];


    // buffers
    unsigned char decryptedtext[128];
    unsigned char ciphertext[128];
    unsigned char iv[12];
    unsigned char GCM_tag[16];

    int ciphertext_len = hex_to_bytes(ciphertext_hex, ciphertext, sizeof(ciphertext));
    int iv_len = hex_to_bytes(iv_hex, iv, sizeof(iv));
    int GCM_tag_len = hex_to_bytes(GCM_tag_hex, GCM_tag, sizeof(GCM_tag));

    printf("--- PROGRAMA DE DECIFRAGEM ---\n");
    printf("Tentando decifrar com os dados fornecidos no codigo...\n\n");


    unsigned char key[32];
    SHA256((const unsigned char*)KEY, strlen(KEY), key); // hash da chave

    EVP_CIPHER_CTX *ctx;
    int ret, len, decryptedtext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len);
    decryptedtext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_tag_len, GCM_tag);
    
    ret = EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        decryptedtext_len += len;
        decryptedtext[decryptedtext_len] = '\0';
        printf(">>> Sucesso! A mensagem e autentica.\n");
        printf("Texto Decifrado: %s\n", decryptedtext);
    } else {
        printf(">>> Falha na decifragem! A mensagem pode ter sido adulterada ou a chave/passphrase esta incorreta.\n");
    }

    return 0;
}

int hex_to_bytes(const char* hex_str, unsigned char* byte_array, size_t max_bytes)
{
    const char *pos = hex_str;

    // Verifica se a string começa com "0x" (ou "0X")
    if (strncmp(pos, "0x", 2) == 0 || strncmp(pos, "0X", 2) == 0)
    {
        // avança o ponteiro 2 posições, para não ler o 0x.
        pos += 2;
    }

    size_t hex_len = strlen(pos);
    if (hex_len % 2 != 0)
    {
        fprintf(stderr, "String tamanho errado!\n");
        return -1;
    }

    size_t byte_len = hex_len / 2;
    if (byte_len > max_bytes)
    {
        fprintf(stderr, "Hex é muito grande para buffer\n");
        return -1;
    }
    

    for (size_t i = 0; i < byte_len; i++)
    {
        sscanf(pos + 2 * i, "%2hhx", &byte_array[i]);
    }
    return byte_len;
}
