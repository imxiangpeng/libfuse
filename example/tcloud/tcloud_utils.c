
#include "tcloud_utils.h"

#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <uuid/uuid.h>
#include <time.h>

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
    
    unsigned char *ptr= HMAC(EVP_sha1(), key, strlen(key), (unsigned char *)data, len, NULL, NULL);
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