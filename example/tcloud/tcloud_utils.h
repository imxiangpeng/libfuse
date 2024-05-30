
#ifndef TCLOUD_UTILS_H
#define TCLOUD_UTILS_H
#include <stddef.h>

int tcloud_utils_http_date_string(char *date, size_t len);
int tcloud_utils_generate_uuid(char *uuid, size_t len);
// please release the memory
char *tcloud_utils_hmac_sha1(const char *key, const unsigned char *data, size_t len);
#endif