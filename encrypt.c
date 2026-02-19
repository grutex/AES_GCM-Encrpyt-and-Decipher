#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>


#define PLAIN_TEXT "CESAR School"
#define KEY "pipocadoce?"


void print_hex(const char* label, const unsigned char* data, int len);

int main(int argc, char *argv[])
{
    unsigned char key[32];//AES-256 bits = 32B
    unsigned char iv[12]; //96 bits - recomendado para o Advanced Encryption Standard-Galois/Counter Mode Protocol


    SHA256((const unsigned char*)KEY, strlen(KEY), key);// hash SHA-256 (256 bits = 32Bytes) conversão tamanho fixo.
    RAND_bytes(iv, sizeof(iv)); // gera um IV/Nonce aleatório CRIPTOGRAFICAMENTE SEGURO.

    
    printf("--- CIFRA ---\n");
    printf("Plain Text: %s\n\n", PLAIN_TEXT);

    unsigned char ciphertext[128]; //128 é arbitrário, auxiliar para armazenar o resultado da cifragem
    unsigned char GCM_tag[16]; //armazenar a tag autenticadora do protocolo Galois/Counter Mode 
    int len, ciphertext_len; // controle do numero de bytes gravados nas operações


    // CIFRAGEM ALOCACAO
    EVP_CIPHER_CTX *ctx; // ponteiro para os itens da cifra, apontar para a memória alocada dos itens
    ctx = EVP_CIPHER_CTX_new(); //função para alocar memória para o ponteiro de itens.

    // CIFRAGEM CONFIGURACAO
    //                 ctx   - algoritmo      - x   - key - iv
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL); // inicialização.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL); // controle de paramentros especiais ; set -> tag de autenticação de 16 Bytes.
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv); // passamos NULL no algoritmo para não muda-lo.
    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)PLAIN_TEXT, strlen(PLAIN_TEXT)); //a cifragem, finalmente, ocorre aqui, lê o plain_text -> criptografa -> coloca no buffer e atribui a var len.
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); //finaliza a operacao, necessario em algumas cifras para o padding.
    ciphertext_len += len; //padding que é adicionado ao fim da string.
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, GCM_tag); // dessa vez estamos obtendo a tag 16B para armazena-la na VAR. 
    EVP_CIPHER_CTX_free(ctx);// libera a memoria alocada para todos os itens

    // --- CIFRAGEM FIM ---
    printf("Cifragem concluida! Copie os valores abaixo para o programa de decifragem:\n");
    printf("--------------------------------------------------------------------------\n");
    
    print_hex("unsigned char ciphertext[] = { 0x", ciphertext, ciphertext_len);
    print_hex("unsigned char iv[] = { 0x", iv, sizeof(iv));
    print_hex("unsigned char GCM_tag[] = { 0x", GCM_tag, sizeof(GCM_tag));
    
    printf("--------------------------------------------------------------------------\n");

    return 0;
}

//auxiliar para imprimir bytes em hexadecimal no terminal.
void print_hex(const char* label, const unsigned char* data, int len)
{
    printf("%s", label);
    for (int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}
