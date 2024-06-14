
#include "tcloud_utils.h"

#include <assert.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>
#include <uuid/uuid.h>
#include <time.h>
#include "tcloud/tcloud_buffer.h"

int tcloud_utils_http_date_string(char *date, size_t len) {
    time_t now;
    struct tm *tm;

    if (date == NULL) {
        return -1;
    }

    now = time(NULL);
    tm = gmtime(&now);

    if (strftime(date, len, "%a, %d %b %Y %H:%M:%S GMT", tm) == 0) {
        return -1;
    }
    return 0;
}

int tcloud_utils_generate_uuid(char *out, size_t len) {
    uuid_t uuid;

    if (!out || len < UUID_STR_LEN) {
        return -1;
    }
    uuid_generate(uuid);
    uuid_unparse(uuid, out);
    return 0;
}

char *tcloud_utils_hmac_sha1(const char *key, const unsigned char *data, size_t len) {
    int offset = 0;
    const int available = SHA_DIGEST_LENGTH * 2 + 1;

    unsigned char *ptr = HMAC(EVP_sha1(), key, strlen(key), (unsigned char *)data, len, NULL, NULL);
    if (!ptr) return NULL;

    char *result = (char *)calloc(1, available);
    if (!result) {
        return NULL;
    }

    for (unsigned int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        int ret = snprintf(result + offset, available - offset, "%02X", ptr[i] & 0xFF);
        offset += ret;
    }

    return result;
}

int tcloud_utils_aes_ecb_data(unsigned char *key, void *data, size_t length, struct tcloud_buffer *r) {
    int out_length = 0;
    if (!data || !r) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    const EVP_CIPHER *cipher = EVP_aes_128_ecb();
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char *)key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, (unsigned char *)r->data, &out_length, (const unsigned char *)data, length) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    r->offset = out_length;

    if (EVP_EncryptFinal_ex(ctx, (unsigned char *)r->data + r->offset, &out_length) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    r->offset += out_length;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int tcloud_utils_rsa_encrypt(const char *public_key, const char *data, size_t length, char *out, size_t *out_len) {
    BIO *bio = BIO_new_mem_buf((void *)public_key, -1);
    EVP_PKEY *evp_pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen = 0;

    if (!bio) {
        fprintf(stderr, "Error creating BIO\n");
        return -1;
    }

    // RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    // rsa_encrypt(rsa, data);
    printf("..............\n");
    evp_pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!evp_pkey) {
        fprintf(stderr, "Error loading public key\n");
        return -1;
    }
#if 0
    unsigned char sha_hash[SHA_DIGEST_LENGTH];
    if (!SHA1(data, length, sha_hash)) {
        handle_errors("SHA1");
        // RSA_free(rsa);
        return -1;
    }
    
    // printf("hash:%s\n", sha_hash);
#endif

    ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
        EVP_PKEY_free(evp_pkey);
        return -1;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing encryption context\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "Error setting padding\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        return -1;
    }
#if 1
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char *)data, length) <= 0) {
        fprintf(stderr, "Error determining buffer length\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        return -1;
    }

    if (outlen > *out_len) {
        fprintf(stderr, "Error determining buffer length ..............\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        return -1;
    }
    *out_len = outlen;
#endif

    memset((void *)out, 0, *out_len);
    // *out_len = sizeof(sha_hash);
    if (EVP_PKEY_encrypt(ctx, (unsigned char *)out, out_len, (const unsigned char *)data, length) <= 0) {
        fprintf(stderr, "Error encrypting data\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_pkey);
        return -1;
    }

    print_hex(out, *out_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_pkey);
    return 0;
}

char *tcloud_utils_base64_encode(const char *data, size_t length) {
    char *ptr = NULL;
    BIO *b, *b64;
    BUF_MEM *buffer = NULL;
    b64 = BIO_new(BIO_f_base64());
    b = BIO_new(BIO_s_mem());
    b = BIO_push(b64, b);
    // do not append \n
    BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b, data, length);
    BIO_flush(b);

    BIO_get_mem_ptr(b, &buffer);
    BIO_set_close(b, BIO_NOCLOSE);

    BIO_free_all(b);

    // printf("buffer len:%ld, strlen:%ld\n", buffer->length, strlen(buffer->data));
    // printf("base64 :%s\n", buffer->data);
    ptr = calloc(1, buffer->length + 1);
    memcpy(ptr, buffer->data, buffer->length);

    BUF_MEM_free(buffer);

    return ptr;
}