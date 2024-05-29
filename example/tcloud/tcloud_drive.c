#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <ctype.h>
#endif

#include <json-c/json.h>
#include <json-c/json_object.h>
#include <stdint.h>
#include "tcloud/hr_log.h"

#include <stdlib.h>
#include <time.h>

#include <errno.h>
#include <string.h>

#include <stddef.h>
#include <stdio.h>
#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <curl/curl.h>
#include <curl/urlapi.h>
#include <uuid/uuid.h>
#include "tcloud_buffer.h"

#include "j2sobject_cloud.h"
#include "xxtea.h"
#include "uthash.h"

#include <pthread.h>

#define WEB_BASE_URL "https://cloud.189.cn"
#define APPID "8025431004"
#define CLI_TYPE "10020"
#define RETURN_URL "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"

#define PC "TELEPC"
#define MAC "TELEMAC"
#define ACCOUNT_TYPE "02"
#define APP_ID "8025431004"
#define CLIENT_TYPE "10020"
#define VERSION "6.2"
#define CHANNEL_ID "web_cloud.189.cn"

#define AUTH_URL "https://open.e.189.cn"
#define API_URL "https://api.cloud.189.cn"
#define UPLOAD_URL "https://upload.cloud.189.cn"

struct tcloud_drive_fd {
    int64_t id;  // cloud id
    CURL *curl;  // opened handle
    char *url;
    // default libfuse using multi thread async mode
    // but we do not support (libcurl)
    // also you can use -s to disable libfuse multi thread feature
    pthread_mutex_t mutex;
};

static size_t _data_receive(void *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    struct tcloud_buffer *buf = (struct tcloud_buffer *)userdata;
    size_t total = size * nmemb;
    if (!ptr || !userdata)
        return -1;

    tcloud_buffer_append(buf, ptr, total);
    return total;
}

int http_post(const char *url, struct curl_slist *headers, const char *payload, size_t payload_length, struct tcloud_buffer *result) {
    CURL *curl;
    CURLcode res;
    curl_mime *form = NULL;
    curl_mimepart *field = NULL;

    curl = curl_easy_init();
    if (curl) {
        // curl_easy_setopt(curl, CURLOPT_URL, /*AUTH_URL*/ "http://10.30.11.78/api/logbox/oauth2/loginSubmit.do");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _data_receive);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, result);

        // follow redirect
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

        // char postFields[2048];
        // snprintf(postFields, sizeof(postFields),
        //          "appKey=%s&accountType=%s&userName=%s&password=%s&validateCode=%s&captchaToken=%s&returnUrl=%s"
        //          "&dynamicCheck=FALSE&clientType=%s&cb_SaveName=1&isOauth2=false&state=&paramId=%s",
        //          APP_ID, ACCOUNT_TYPE, rsaUsername, rsaPassword, vcode, captchaToken, RETURN_URL, CLIENT_TYPE, paramId);

        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload_length);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("%lu bytes retrieved\n", (unsigned long)result->offset);
            printf("Response: %s\n", result->data);
        }

        curl_mime_free(form);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    return 0;
}

int http_post_j2sobject_result(const char *url, struct curl_slist *headers, const char *payload, size_t payload_length, struct j2sobject *result) {
    struct tcloud_buffer buffer;

    tcloud_buffer_alloc(&buffer, 2048);

    int ret = http_post(url, headers, payload, payload_length, &buffer);
    printf("ret:%d\n", ret);
    if (ret == 0) {
        printf("response json data:%s\n", buffer.data);
        ret = j2sobject_deserialize(result, buffer.data);
        printf("ret:%d\n", ret);
    }
    tcloud_buffer_free(&buffer);

    return ret;
}
int driver_http_get(const char *url, struct curl_slist *headers, struct tcloud_buffer *result) {
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _data_receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, result);

    // follow redirect
    // curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return -1;
    }
    printf("%lu bytes retrieved\n", (unsigned long)result->offset);
    printf("Response: %s\n", result->data);

    curl_easy_cleanup(curl);

    return 0;
}

static int http_get(CURLU *url, /*struct curl_slist *data, struct curl_slist *header, */ struct tcloud_buffer *mem) {
    long response_code = 0;
    CURL *curl = NULL;

    if (!url) return -1;

    curl = curl_easy_init();
    if (!curl) return -1;

    char *uri = NULL;
    curl_url_get(url, CURLUPART_URL, &uri, 0);
    printf("request: %s\n", uri);
    curl_easy_setopt(curl, CURLOPT_CURLU, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _data_receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, mem);

    // follow redirect
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    CURLcode code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);
    printf("code:%d, response code:%ld\n", CURLE_OK, response_code);

    if (CURLE_OK != code) {
        printf("request failed ... %d:%s\n", code, curl_easy_strerror(code));
        return -1;
    }

    if (response_code != 200) return -1;

    return 0;
}

static long long time_ms() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        perror("clock_gettime");
        return -1;
    }
    return (ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL);
}
char *extract_url_path(const char *url) {
    const char *start = strstr(url, "://");
    if (!start) {
        return NULL;
    }
    start += 3;  // 跳过 "://"
    const char *path_start = strchr(start, '/');
    if (!path_start) {
        path_start = "/";
    }

    const char *query_start = strchr(path_start, '?');
    size_t path_len = query_start ? (size_t)(query_start - path_start) : strlen(path_start);

    char *path = (char *)malloc(path_len + 1);
    if (!path) {
        return NULL;
    }
    strncpy(path, path_start, path_len);
    path[path_len] = '\0';
    return path;
}

int http_gmt_date(char *buffer, size_t length) {
    time_t rawtime;
    struct tm *timeinfo;

    if (buffer == NULL) {
        return -1;
    }

    time(&rawtime);
    timeinfo = gmtime(&rawtime);  // 获取UTC时间

    if (strftime(buffer, length, "%a, %d %b %Y %H:%M:%S GMT", timeinfo) == 0) {
        return -1;
    }

    return 0;
}

void to_uppercase(char *str) {
    while (*str) {
        *str = toupper((unsigned char)*str);
        str++;
    }
}
char *signatureOfHmac(const char *sessionSecret, const char *sessionKey, const char *operate, const char *fullUrl, const char *dateOfGmt, const char *param) {
    char *urlPath = extract_url_path(fullUrl);
    if (!urlPath) {
        return NULL;
    }

    printf("url %s -> %s\n", fullUrl, urlPath);
    int data_len = strlen(sessionKey) + strlen(operate) + strlen(urlPath) + strlen(dateOfGmt) + 50;
    if (param && strlen(param) > 0) {
        data_len += strlen(param) + 9;  // +9 for "&params="
    }

    char *data = (char *)malloc(data_len);
    if (!data) {
        free(urlPath);
        return NULL;
    }

    if (param && strlen(param) > 0) {
        snprintf(data, data_len, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s&params=%s", sessionKey, operate, urlPath, dateOfGmt, param);
    } else {
        snprintf(data, data_len, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", sessionKey, operate, urlPath, dateOfGmt);
    }

    printf("data:%s\n", data);
    free(urlPath);

    unsigned char *result;
    unsigned int len = SHA_DIGEST_LENGTH;

    result = HMAC(EVP_sha1(), sessionSecret, strlen(sessionSecret), (unsigned char *)data, strlen(data), NULL, NULL);
    free(data);

    char *hex_result = (char *)malloc(len * 2 + 1);
    if (!hex_result) {
        return NULL;
    }

    for (unsigned int i = 0; i < len; i++) {
        sprintf(hex_result + i * 2, "%02X", result[i]);
    }
    hex_result[len * 2] = '\0';

    to_uppercase(hex_result);
    return hex_result;
}
int tcloud_drive_init(void) {
    curl_global_init(CURL_GLOBAL_ALL);
    return 0;
}

int tcloud_drive_destroy(void) {
    curl_global_cleanup();
    return 0;
}
static int tcloud_drive_getattr(const char *path, struct stat *stbuf,
                                struct fuse_file_info *fi) {
    printf("%s(%d): path:%s fi:%p\n", __FUNCTION__, __LINE__, path, fi);

    return -ENOENT;
}

static int tcloud_drive_access(const char *path, int mask) {
    printf("%s(%d): ........path:%s\n", __FUNCTION__, __LINE__, path);
    return 0;
}

#if 0
int tcloud_drive_readdir(int64_t id, struct j2scloud_folder_resp * dir) {
  char *path = NULL;


  // asprintf(&path, "/workspace/workspace/libfuse/libfuse/build/filelists-%d.json", id);
  asprintf(&path, "/home/alex/workspace/workspace/libfuse/libfuse/build/filelists-%d.json", id);
  
  printf("folder :%d --> %s\n", id, path);
  
  
    int ret = j2sobject_deserialize_target_file(        J2SOBJECT(dir),        path,        "fileListAO");
  
  free(path);


  return ret;
}
#else

// Referer: https://cloud.189.cn
// Sessionkey: 2f66d7f1-af6a-4a7b-a3b9-e81640c0b44d
// Signature: 3D40EFF921EB4110B73386D195DDE7B3905646E3
// X-Request-Id: 7442917f-ffb1-472f-87ec-97e05ae1c7f9
// id: folder id
int tcloud_drive_readdir(uint64_t id, struct j2scloud_folder_resp *dir) {
    uuid_t uuid;
    char request_id[UUID_STR_LEN + 20] = {0};
    char *url = NULL;
    // const char* url = "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action";
    struct curl_slist *headers = NULL;
    const char *secret = "FA75442F51DA58C650DAC77D9BB3DC5B";
    const char *session_key = "cbc87566-6cf2-47b9-b2f3-f3d48525a16b";

    char tmp[512] = {0};

    headers = curl_slist_append(headers, "Accept: application/json;charset=UTF-8");
    headers = curl_slist_append(headers, "Referer: https://cloud.189.cn");
    snprintf(tmp, sizeof(tmp), "Sessionkey: %s", session_key);
    headers = curl_slist_append(headers, tmp);

    // 生成UUID
    uuid_generate(uuid);

    int ret = snprintf(request_id, sizeof(request_id), "%s", "X-Request-ID: ");
    // 将UUID转换为字符串形式
    uuid_unparse(uuid, request_id + ret);

    printf("Generated UUID: %s\n", request_id + ret);

    headers = curl_slist_append(headers, request_id);

    // generate query payload

    long folder_id = id;
    printf("folder :%ld vs id:%ld\n", folder_id, id);
    const int page_size = 100;
    int page_num = 1;

    //    CURLU *url = curl_url();
    // curl_url_set(url, CURLUPART_URL, "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action");
    // snprintf(tmp, sizeof(tmp))
    // "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action?folderId=%d"
    //
    asprintf(&url,
             "https://api.cloud.189.cn/listFiles.action"
             "?folderId=%ld"
             "&fileType=0"
             "&mediaType=0"
             "&mediaAttr=0"
             "&iconOption=0"
             "&orderBy=filename"
             "&descending=true"
             "&pageNum=%d"
             "&pageSize=%d"
             "&clientType=%s&version=%s&channelId=%s&rand=%d_%d",
             folder_id, page_num, page_size,
             PC, VERSION, CHANNEL_ID, rand(), rand());

    char date[64] = {0};
    http_gmt_date(date, sizeof(date));
    printf("date:%s\n", date);

    snprintf(tmp, sizeof(tmp), "Date: %s", date);
    headers = curl_slist_append(headers, tmp);

    char *signature = signatureOfHmac(secret, session_key, "GET", url, date, NULL);

    printf("signature:%s\n", signature);

    int offset = strlen("Signature: ");

    signature = realloc(signature, strlen(signature) + offset);

    memcpy(signature + offset, signature, strlen(signature));
    memcpy(signature, "Signature: ", offset);
    headers = curl_slist_append(headers, signature);

    struct tcloud_buffer buffer;

    tcloud_buffer_alloc(&buffer, 2048);

    printf("%s(%d): request:%s\n", __FUNCTION__, __LINE__, url);
    ret = driver_http_get(url, headers, &buffer);

    printf("file list: %s\n", buffer.data);
    ret = j2sobject_deserialize_target(dir, buffer.data, "fileListAO");
    printf("ret:%d\n", ret);

    tcloud_buffer_free(&buffer);
    curl_slist_free_all(headers);
    free(url);
    return 0;
}
#endif

static int tcloud_drive_releasedir(const char *path,
                                   struct fuse_file_info *fi) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

static int tcloud_drive_mkdir(const char *path, mode_t mode) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

static int tcloud_drive_rmdir(const char *path) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

static int tcloud_drive_rename(const char *from, const char *to,
                               unsigned int flags) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

static int tcloud_drive_truncate(const char *path, off_t size,
                                 struct fuse_file_info *fi) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}
static int tcloud_drive_utimens(const char *path, const struct timespec tv[2],
                                struct fuse_file_info *fi) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

// return real download url
void *tcloud_drive_open(int64_t id) {
    struct tcloud_drive_fd *fd = NULL;
    int ret = -1;
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    // https://api.cloud.189.cn/getFileDownloadUrl.action
    uuid_t uuid;
    char request_id[UUID_STR_LEN + 20] = {0};
    char *url = NULL;
    // const char* url = "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action";
    struct curl_slist *headers = NULL;
    const char *secret = "FA75442F51DA58C650DAC77D9BB3DC5B";
    const char *session_key = "cbc87566-6cf2-47b9-b2f3-f3d48525a16b";

    char tmp[512] = {0};

    headers = curl_slist_append(headers, "Accept: application/json;charset=UTF-8");
    headers = curl_slist_append(headers, "Referer: https://cloud.189.cn");
    snprintf(tmp, sizeof(tmp), "Sessionkey: %s", session_key);
    headers = curl_slist_append(headers, tmp);

    // 生成UUID
    uuid_generate(uuid);

    ret = snprintf(request_id, sizeof(request_id), "%s", "X-Request-ID: ");
    // 将UUID转换为字符串形式
    uuid_unparse(uuid, request_id + ret);

    printf("Generated UUID: %s\n", request_id + ret);

    headers = curl_slist_append(headers, request_id);

    // generate query payload

    printf("id:%ld\n", id);
    const int page_size = 100;
    int page_num = 1;

    //    CURLU *url = curl_url();
    // curl_url_set(url, CURLUPART_URL, "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action");
    // snprintf(tmp, sizeof(tmp))
    // "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action?folderId=%d"
    //
    asprintf(&url,
             "https://api.cloud.189.cn/getFileDownloadUrl.action"
             // "http://10.30.11.78/listFiles.action"
             "?fileId=%ld"
             "&clientType=%s&version=%s&channelId=%s&rand=%d_%d",
             id,
             PC, VERSION, CHANNEL_ID, rand(), rand());

    char date[64] = {0};
    http_gmt_date(date, sizeof(date));
    printf("date:%s\n", date);

    snprintf(tmp, sizeof(tmp), "Date: %s", date);
    headers = curl_slist_append(headers, tmp);

    char *signature = signatureOfHmac(secret, session_key, "GET", url, date, NULL);

    printf("signature:%s\n", signature);

    int offset = strlen("Signature: ");

    signature = realloc(signature, strlen(signature) + offset);

    memcpy(signature + offset, signature, strlen(signature));
    memcpy(signature, "Signature: ", offset);
    headers = curl_slist_append(headers, signature);

    struct tcloud_buffer buffer;

    tcloud_buffer_alloc(&buffer, 2048);

    printf("%s(%d): request:%s\n", __FUNCTION__, __LINE__, url);
    ret = driver_http_get(url, headers, &buffer);

    printf("file list: %s\n", buffer.data);
    printf("ret:%d\n", ret);

    curl_slist_free_all(headers);
    free(url);
    struct json_object *root = json_tokener_parse(buffer.data);
    tcloud_buffer_free(&buffer);
    if (root) {
        struct json_object *download_url = NULL;
        if (json_object_object_get_ex(root, "fileDownloadUrl", &download_url)) {
            ret = 0;
            fd = (struct tcloud_drive_fd *)calloc(1, sizeof(struct tcloud_drive_fd));
            fd->url = strdup(json_object_get_string(download_url));
            pthread_mutex_init(&fd->mutex, NULL);
            // fd->curl = curl_easy_init();
            // curl_easy_setopt(fd->curl, CURLOPT_URL, json_object_get_string(download_url));
        }
        printf("%s(%d): ..fd:%p..download url:%s....\n", __FUNCTION__, __LINE__, fd, json_object_get_string(download_url));
        json_object_put(root);
        root = NULL;
    }

    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return fd;
}
int tcloud_drive_release(struct tcloud_drive_fd *fd) {
    if (!fd) return -1;
    printf("%s(%d): .....release :%p...\n", __FUNCTION__, __LINE__, fd);
    pthread_mutex_destroy(&fd->mutex);
    // curl_easy_cleanup(fd->curl);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

size_t tcloud_drive_read(struct tcloud_drive_fd *fd, char *rbuf, size_t size, off_t offset) {
    size_t result = 0;
    CURL *curl = fd->curl;
    if (!fd) return -1;
    HR_LOGD("%s(%d): ......fd:%p. offset:%ld, size:%ld.\n", __FUNCTION__, __LINE__, fd, offset, size);
    // https://api.cloud.189.cn/getFileDownloadUrl.action
    struct tcloud_buffer b;
    tcloud_buffer_prealloc(&b, rbuf, size);

    char range[64] = {0};
    snprintf(range, sizeof(range), "%zu-%zu", offset, offset + size - 1);

    // pthread_mutex_lock(&fd->mutex);
            curl = curl_easy_init();
            curl_easy_setopt(curl, CURLOPT_URL, fd->url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _data_receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);
    curl_easy_setopt(curl, CURLOPT_RANGE, range);
    // follow redirect
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    HR_LOGD("%s(%d): .....try do perform curl:%p...\n", __FUNCTION__, __LINE__, curl);
    int res = curl_easy_perform(curl);

    // pthread_mutex_unlock(&fd->mutex);
    if (res != CURLE_OK) {
    curl_easy_cleanup(curl);
        HR_LOGD("%s(%d): .....do perform failed .......... curl:%p...\n", __FUNCTION__, __LINE__, curl);
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return -EIO;
    }
    curl_easy_cleanup(curl);

    memcpy(rbuf, b.data, b.offset);
    HR_LOGD("%s(%d): ........read:%ld\n", __FUNCTION__, __LINE__, b.offset);

    result = b.offset;
    tcloud_buffer_free(&b);

    return result;
}
static int tcloud_drive_write(const char *path, const char *wbuf, size_t size,
                              off_t offset, struct fuse_file_info *fi) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    printf("wbuffer:%s\n", wbuf);
    return size;
}

// https://api.cloud.189.cn/newOpen/user/getUserInfo.action
static int tcloud_drive_statfs(const char *path, struct statvfs *buf) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}
static int tcloud_drive_create(const char *path, mode_t mode,
                               struct fuse_file_info *fi) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}
