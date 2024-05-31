
#include "tcloud_utils.h"

#include <assert.h>
#include <openssl/hmac.h>
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

static int pkcs7_padding(struct tcloud_buffer *data, int block_size) {
    int pad_len = block_size - (data->offset % block_size);
    if (pad_len + data->offset > data->size) {
        if (0 != tcloud_buffer_realloc(data, data->offset + pad_len)) {
            return -1;
        }
    }

    memset((void *)(data->data + data->offset), pad_len, pad_len);

    data->offset += pad_len;

    return 0;
}

int tcloud_utils_aes_ecb_buffer(unsigned char *key, struct tcloud_buffer *d, struct tcloud_buffer *r) {
    int out_length = 0;
    if (!d || !r) return -1;

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

    if (EVP_EncryptUpdate(ctx, (unsigned char *)r->data, &out_length, (const unsigned char *)d->data, d->offset) != 1) {
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
