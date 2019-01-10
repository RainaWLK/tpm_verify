#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

typedef struct
{
    int size;
    uint8_t *data;
} Data;

EVP_PKEY *load_pubkey(const char *file)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;

    FILE *fp = NULL;
    fp = fopen(file, "r");
    uint8_t *buffer = malloc(1024);
    int size = fread(buffer, 1, 1024, fp);
    fclose(fp);

    key = BIO_new_mem_buf(buffer, size);

    pkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);

    BIO_free(key);
    free(buffer);

    return pkey;
}

int
    read_data(const char *file, Data *data)
{
    int res = 0;
    FILE *fp = NULL;

    fp = fopen(file, "rb");
    uint8_t *buffer = malloc(1024);
    int size = fread(buffer, 1, 1024, fp);
    fclose(fp);

    data->size = size;
    data->data = buffer;

    return res;
}

int
    main(
        int argc,
        char *argv[])
{
    int res = EXIT_SUCCESS;

    EVP_PKEY *pubkey = NULL;

    pubkey = load_pubkey("key.pem");

    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = EVP_sha256();

    mdctx = EVP_MD_CTX_create();
    res = EVP_VerifyInit_ex(mdctx, md, NULL);
    if (res == 0)
    {
        printf("Failed to EVP_VerifyInit_ex().\n");
    }

    Data quote = {0};
    read_data("quote.data", &quote);
    EVP_VerifyUpdate(mdctx, quote.data, quote.size);
    if (res == 0)
    {
        printf("Failed to EVP_VerifyUpdate().\n");
    }

    Data signature = {0};
    read_data("quote.sig", &signature);
    int verify = EVP_VerifyFinal(mdctx, signature.data, signature.size, pubkey);

    if (verify == 1)
    {
        printf("Verified OK\n");
    }
    else
    {
        printf("Verified failed...\n");
    }

    free(quote.data);
    free(signature.data);

    return res;
}

