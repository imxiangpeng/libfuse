#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <ctype.h>
#include <curl/multi.h>
#include <unistd.h>
#include "tcloud/tcloud_request.h"
#include "tcloud_utils.h"
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
#include "tcloud_drive.h"
#include "tcloud_request.h"
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
// #define API_URL "https://api.cloud.189.cn"
#define API_URL "http://api.cloud.189.cn"
#define UPLOAD_URL "https://upload.cloud.189.cn"

#define TCLOUD_DRIVE_READ_BUFFER_SIZE (2 * 1024 * 1024)

const char *secret = "A8CD8047724920AC491C30F01EEDF6F3";
const char *session_key = "a947ec7d-0ebf-4835-bc8d-0fb75853d3c5";

size_t cycle_total;
static int _pause = 0;
struct tcloud_drive {
    struct tcloud_request *request;  // api request
    pthread_mutex_t mutex;
};
struct tcloud_drive_fd {
    int64_t id;  // cloud id
    CURLM *multi;
    CURL *curl;  // opened handle
    char *url;

    cycle_buffer_t *cycle;

    size_t offset;

    int status;  // 1 -> running, 0 -> stopped
    int paused;

    int eof;
    pthread_t tid;  // download tid
    // pthread_cond_broadcast(pthread_cond_t *cond)
    pthread_cond_t write_cond;
    pthread_cond_t read_cond;
    pthread_mutex_t lock;
    // default libfuse using multi thread async mode
    // but we do not support (libcurl)
    // also you can use -s to disable libfuse multi thread feature
    pthread_mutex_t mutex;
};

static struct tcloud_drive _drive;

static long long time_ms() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        perror("clock_gettime");
        return -1;
    }
    return (ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL);
}
static char *request_url_path(const char *url) {
    const char *start = strstr(url, "://");
    if (!start) {
        return NULL;
    }
    start += 3;  // skip "://"
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
    timeinfo = gmtime(&rawtime);

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
    char *urlPath = request_url_path(fullUrl);
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
static size_t _data_receive(void *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    struct tcloud_buffer *buf = (struct tcloud_buffer *)userdata;
    size_t total = size * nmemb;
    if (!ptr || !userdata)
        return total;  // drop all data

    tcloud_buffer_append(buf, ptr, total);
    return total;
}

static size_t _cycle_data_receive(void *ptr, size_t size, size_t nmemb,
                                  void *userdata) {
    struct tcloud_drive_fd *fd = (struct tcloud_drive_fd *)userdata;
    cycle_buffer_t *buf = NULL;
    size_t total = size * nmemb;
    HR_LOGD("%s(%d): write:%u\n", __FUNCTION__, __LINE__, total);
    if (!ptr || !userdata)
        return total;  // drop all data
    buf = fd->cycle;

    pthread_mutex_lock(&fd->lock);
    // not available
    while (cycle_buffer_available_size(buf) < total) {
        HR_LOGD("%s(%d): not enough wait ... :%u\n", __FUNCTION__, __LINE__, total);
        pthread_cond_wait(&fd->write_cond, &fd->lock);
        if (fd->status == 0) {
            pthread_mutex_unlock(&fd->lock);
            return 0;
        }
    }
    //pthread_mutex_unlock(&fd->lock);
    unsigned int rc = cycle_buffer_put(buf, ptr, total, 0);

    //pthread_mutex_lock(&fd->lock);
    pthread_cond_signal(&fd->read_cond);
    pthread_mutex_unlock(&fd->lock);
    cycle_total += total;

    // HR_LOGD("%s(%d): write:%u, total:%ld\n", __FUNCTION__, __LINE__, rc, cycle_total);
    return rc;
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

static int _http_get(const char *url, struct curl_slist *headers, struct tcloud_buffer *result) {
    CURL *curl;
    CURLcode res;
    long response_code = 0;

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
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return -1;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    printf("code:%d, response code:%ld\n", CURLE_OK, response_code);
    printf("%lu bytes retrieved\n", (unsigned long)result->offset);
    printf("Response: %s\n", result->data);

    curl_easy_cleanup(curl);

    return 0;
}

#if 0
static int _tcloud_drive_http_get(const char *url, const char *payload, struct tcloud_buffer *buf) {
    char *request_url = NULL;
    struct curl_slist *headers = NULL;
    char tmp[512] = {0};

    // const char *secret = "FA3387A62BE630E89D18ABBCD4AF662E";
    // const char* session_key = "0bdc1b48-b764-478d-8984-c1faccd99a78";
    //  const char *secret = "FA75442F51DA58C650DAC77D9BB3DC5B";
    // const char *session_key = "cbc87566-6cf2-47b9-b2f3-f3d48525a16b";
    uuid_t uuid;
    char request_id[UUID_STR_LEN + 20] = {0};

    // X-Request-ID:
    uuid_generate(uuid);
    int pos = snprintf(request_id, sizeof(request_id), "%s", "X-Request-ID: ");
    uuid_unparse(uuid, request_id + pos);
    printf("Generated UUID: %s\n", request_id + pos);
    headers = curl_slist_append(headers, request_id);

    char date[64] = {0};
    // Date:
    http_gmt_date(date, sizeof(date));
    snprintf(tmp, sizeof(tmp), "Date: %s", date);
    headers = curl_slist_append(headers, tmp);

    // Accept:
    headers = curl_slist_append(headers, "Accept: application/json;charset=UTF-8");
    // Referer:
    headers = curl_slist_append(headers, "Referer: https://cloud.189.cn");

    // Sessionkey:
    snprintf(tmp, sizeof(tmp), "Sessionkey: %s", session_key);
    headers = curl_slist_append(headers, tmp);

    if (!payload) {
        asprintf(&request_url, "%s?clientType=%s&version=%s&channelId=%s&rand=%d_%d", url, PC, VERSION, CHANNEL_ID, rand(), rand());
    } else {
        asprintf(&request_url, "%s?%s&clientType=%s&version=%s&channelId=%s&rand=%d_%d", url, payload, PC, VERSION, CHANNEL_ID, rand(), rand());
    }

    char *signature = signatureOfHmac(secret, session_key, "GET", url, date, NULL);
    printf("signature:%s\n", signature);

    int offset = strlen("Signature: ");
    int val_len = strlen(signature);

    void *ptr = realloc(signature, val_len + offset + 1);
    if (!ptr) {
        free(signature);
        free(request_url);
        return -1;
    }
    signature = ptr;
    *(signature + val_len + offset) = '\0';
    memcpy(signature + offset, signature, strlen(signature));
    memcpy(signature, "Signature: ", offset);
    headers = curl_slist_append(headers, signature);

    int ret = _http_get(url, headers, buf);

    HR_LOGD("%s(%d): code:%d result:%s\n", __FUNCTION__, __LINE__, ret, buf->data);

    curl_slist_free_all(headers);

    free(signature);
    free(request_url);
    return ret;
}
#endif
static int _tcloud_drive_fill_final(struct tcloud_request *req, const char *uri, struct tcloud_buffer *params) {
    char tmp[512] = {0};
    if (!req) return -1;

    char uuid[UUID_STR_LEN] = {0};
    tcloud_utils_generate_uuid(uuid, sizeof(uuid));

    char date[64] = {0};
    tcloud_utils_http_date_string(date, sizeof(date));

    req->set_header(req, "Date", date);
    req->set_header(req, "SessionKey", session_key);
    req->set_header(req, "X-Request-ID", uuid);

    char *signature_data = NULL;
    if (params) {
        asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s&params=%s", session_key, req->method == TR_METHOD_GET ? "GET" : "POST", uri, date, params->data);
    } else {
        asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session_key, req->method == TR_METHOD_GET ? "GET" : "POST", uri, date);
    }

    HR_LOGD("%s(%d): signature data:%s\n", __FUNCTION__, __LINE__, signature_data);
    char *signature = tcloud_utils_hmac_sha1(secret, (const unsigned char *)signature_data, strlen(signature_data));
    HR_LOGD("%s(%d): signature:%s\n", __FUNCTION__, __LINE__, signature);
    req->set_header(req, "Signature", signature);
    free(signature_data);
    free(signature);

    req->set_header(req, "Referer", "https://cloud.189.cn");

    req->set_query(req, "clientType", "TELEPC");
    req->set_query(req, "version", "6.2");
    req->set_query(req, "channelI", "web_cloud.189.cn");
    snprintf(tmp, sizeof(tmp), "%d_%d", rand(), rand());
    req->set_query(req, "rand", tmp);

    return 0;
}

int tcloud_drive_init(void) {
    curl_global_init(CURL_GLOBAL_ALL);

    _drive.request = tcloud_request_new();
    return 0;
}

int tcloud_drive_destroy(void) {
    tcloud_request_free(_drive.request);
    _drive.request = NULL;
    curl_global_cleanup();
    return 0;
}

int tcloud_drive_storage_statfs(struct statvfs *st) {
    struct json_object *root = NULL, *capacity = NULL, *available = NULL, *res_code = NULL;
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request;

    const char *action = "/getUserInfo.action";

    tcloud_buffer_alloc(&b, 512);

    int ret = _tcloud_drive_fill_final(_drive.request, "/getUserInfo.action", NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        return ret;
    }

    req->get(req, action, &b, NULL);

    printf("data:%s\n", b.data);
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "res_code", &res_code);
    if (!res_code || json_object_get_int(res_code) != 0) {
        json_object_put(root);
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "capacity", &capacity);
    json_object_object_get_ex(root, "available", &available);
    printf("%s(%d): .capability:%ld, available:%ld...\n", __FUNCTION__, __LINE__, json_object_get_int64(capacity), json_object_get_int64(available));
    st->f_namemax = 255;
    st->f_bsize = 4096;
    st->f_blocks = json_object_get_int64(capacity) / st->f_bsize;
    st->f_bfree = json_object_get_int64(available) / st->f_bsize;
    st->f_bavail = json_object_get_int64(available) / st->f_bsize;
    printf("%s(%d): .capability:%ld, available:%ld-%ld....\n", __FUNCTION__, __LINE__, st->f_blocks * 4096, st->f_bfree, st->f_bavail);
    printf("%s(%d): .capability:%ld, available:%ld-%ld....\n", __FUNCTION__, __LINE__, st->f_blocks * 4096, st->f_bfree, st->f_bavail);
    json_object_put(root);
    root = NULL;
}

// id: file or folder id
// type: 0 --> folder
//       1 --> file
// we only used to get root folder information
// other folder/file information we have got in listFile
int tcloud_drive_getattr(int64_t id, int type, struct timespec *atime, struct timespec *ctime) {
    printf("%s(%d): id:%ld, type:%d\n", __FUNCTION__, __LINE__, id, type);

    struct json_object *root = NULL, *res_code = NULL;
    struct tcloud_buffer b;

    struct tcloud_request *req = _drive.request;

    const char *action = type == 0 ? "/getFolderInfo.action" : "/getFileInfo.action";

    tcloud_buffer_alloc(&b, 512);

    // req->set_query(req, "folderId", "-11");
    char *url = NULL;
    asprintf(&url, API_URL "%s?folderId=%ld", action, id);
    if (!url) return -1;

    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    int ret = _tcloud_drive_fill_final(req, action, NULL);

    HR_LOGD("%s(%d): failed ..........ret:%d...\n", __FUNCTION__, __LINE__, ret);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        return ret;
    }

    req->get(req, url, &b, NULL);

    free(url);

    HR_LOGD("%s(%d): ret:%d -> %s\n", __FUNCTION__, __LINE__, ret, b.data);
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "res_code", &res_code);
    if (!res_code || json_object_get_int(res_code) != 0) {
        json_object_put(root);
        printf(" can not parse json .....\n");
        return -1;
    }

    ctime->tv_sec = json_object_get_int64(json_object_object_get(root, "createTime"));
    atime->tv_sec = json_object_get_int64(json_object_object_get(root, "lastOpTime"));

    json_object_put(root);

    return 0;
}

static int tcloud_drive_access(const char *path, int mask) {
    printf("%s(%d): ........path:%s\n", __FUNCTION__, __LINE__, path);
    return 0;
}

// Referer: https://cloud.189.cn
// Sessionkey: 2f66d7f1-af6a-4a7b-a3b9-e81640c0b44d
// Signature: 3D40EFF921EB4110B73386D195DDE7B3905646E3
// X-Request-Id: 7442917f-ffb1-472f-87ec-97e05ae1c7f9
// id: folder id
int tcloud_drive_readdir(int64_t id, struct j2scloud_folder_resp *dir) {
    struct tcloud_buffer b;
    char *url = NULL;
    int page_num = 1;
    int page_size = 100;

    char tmp[256] = {0};
    struct tcloud_request *req = _drive.request;
    const char *action = "/listFiles.action";

    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);

    asprintf(&url,
             API_URL
             "%s"
             "?folderId=%ld"
             "&fileType=0"
             "&mediaType=0"
             "&mediaAttr=0"
             "&iconOption=0"
             "&orderBy=filename"
             "&descending=true"
             "&pageNum=%d"
             "&pageSize=%d",
             action,
             id, page_num, page_size);

    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);
    if (!url) return -1;

    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);
    tcloud_buffer_alloc(&b, 2048);
    req->method = TR_METHOD_GET;
    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);
    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);
    int ret = _tcloud_drive_fill_final(req, action, NULL);
    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        return ret;
    }

    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);

    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    ret = req->request(req, url, &b, NULL);
    free(url);
    printf("%s(%d): ...ret:%d.......\n", __FUNCTION__, __LINE__, ret);
    HR_LOGD("%s(%d): ....data:%s......\n", __FUNCTION__, __LINE__, b.data);

    if (ret != 0) {
        tcloud_buffer_free(&b);
        return ret;
    }

    printf("%s(%d): ret:%d -> %s\n", __FUNCTION__, __LINE__, ret, b.data);
    ret = j2sobject_deserialize_target(dir, b.data, "fileListAO");
    HR_LOGD("%s(%d): ret:%d -> %s\n", __FUNCTION__, __LINE__, ret, b.data);
    tcloud_buffer_free(&b);

    return ret;
}

static int tcloud_drive_releasedir(const char *path,
                                   struct fuse_file_info *fi) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

int64_t tcloud_drive_mkdir(int64_t parent, const char *name) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);

    struct json_object *root = NULL, *res_code = NULL;
    struct tcloud_buffer b;
    char *url = NULL;
    int64_t id = -1;
    struct tcloud_request *req = _drive.request;
    const char *action = "/createFolder.action";

    if (!name) return -1;

    asprintf(&url, API_URL
             "/createFolder.action"
             "?parentFolderId=%ld"
             "&folderName=%s",
             parent, name);

    if (!url) return -1;

    tcloud_buffer_alloc(&b, 512);
    req->method = TR_METHOD_GET;
    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        return ret;
    }

    ret = req->request(req, url, &b, NULL);
    free(url);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        return ret;
    }

    HR_LOGD("%s(%d): ret:%d -> %s\n", __FUNCTION__, __LINE__, ret, b.data);
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "res_code", &res_code);
    if (!res_code || json_object_get_int(res_code) != 0) {
        json_object_put(root);
        printf(" can not parse json .....\n");
        return -1;
    }

    id = json_object_get_int64(json_object_object_get(root, "id"));

    json_object_put(root);

    return id;
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
struct tcloud_drive_fd *tcloud_drive_open(int64_t id) {
    struct tcloud_drive_fd *fd = NULL;
    struct tcloud_buffer b;
    int ret = -1;
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    // https://api.cloud.189.cn/getFileDownloadUrl.action
    char *url = NULL;

    struct tcloud_request *req = _drive.request;
    const char *action = "/getFileDownloadUrl.action";
    char tmp[512] = {0};
    //    CURLU *url = curl_url();
    // curl_url_set(url, CURLUPART_URL, "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action");
    // snprintf(tmp, sizeof(tmp))
    // "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action?folderId=%d"
    //
    asprintf(&url,
             API_URL
             "/getFileDownloadUrl.action"
             "?fileId=%ld",
             id);

    if (!url) return NULL;

    tcloud_buffer_alloc(&b, 512);
    req->method = TR_METHOD_GET;
    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        return NULL;
    }

    ret = req->request(req, url, &b, NULL);
    free(url);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        return NULL;
    }

    printf("file list: %s\n", b.data);
    printf("ret:%d\n", ret);

    struct json_object *root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (root) {
        struct json_object *download_url = NULL;
        if (json_object_object_get_ex(root, "fileDownloadUrl", &download_url)) {
            ret = 0;
            fd = (struct tcloud_drive_fd *)calloc(1, sizeof(struct tcloud_drive_fd));
            fd->url = strdup(json_object_get_string(download_url));
            pthread_mutex_init(&fd->mutex, NULL);
            pthread_mutex_init(&fd->lock, NULL);
            pthread_cond_init(&fd->write_cond, NULL);
            pthread_cond_init(&fd->read_cond, NULL);
            cycle_buffer_init(&fd->cycle, TCLOUD_DRIVE_READ_BUFFER_SIZE);
            fd->multi = curl_multi_init();
            fd->curl = curl_easy_init();

            curl_multi_add_handle(fd->multi, fd->curl);
            curl_easy_setopt(fd->curl, CURLOPT_URL, fd->url);
            curl_easy_setopt(fd->curl, CURLOPT_WRITEFUNCTION, _cycle_data_receive);
            curl_easy_setopt(fd->curl, CURLOPT_WRITEDATA, fd /*->cycle*/);
            // follow redirect
            curl_easy_setopt(fd->curl, CURLOPT_FOLLOWLOCATION, 1);
            curl_easy_setopt(fd->curl, CURLOPT_BUFFERSIZE, TCLOUD_DRIVE_READ_BUFFER_SIZE / 2);
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

    fd->status = 0;

    pthread_cond_broadcast(&fd->write_cond);
    if (fd->tid != 0) {
        pthread_cancel(fd->tid);
        pthread_join(fd->tid, NULL);
        fd->tid = 0;
    }

    pthread_mutex_destroy(&fd->mutex);
    // tcloud_request_free(fd->request);
    curl_multi_remove_handle(fd->multi, fd->curl);
    curl_easy_cleanup(fd->curl);
    curl_multi_cleanup(fd->curl);

    cycle_buffer_destroy(&fd->cycle);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

// large file we use seperate thread download
// care that we do not support random read, only support stream read from head
void *_tcloud_drive_read_routin(void *arg) {
    struct tcloud_drive_fd *fd = (struct tcloud_drive_fd *)arg;
    // we should reset, and request new data
    int still_running = 0;
    cycle_buffer_reset(fd->cycle);
    // fd->offset = offset;
    char range[64] = {0};
    // snprintf(range, sizeof(range), "%zu-", offset);
    // curl_easy_setopt(fd->curl, CURLOPT_RANGE, range);
    fd->status = 1;
    HR_LOGD("%s(%d): !!!!!!!!\n", __FUNCTION__, __LINE__);
    do {
        int numfds;
        CURLMcode mc = curl_multi_wait(fd->multi, NULL, 0, 1000, &numfds);

        // HR_LOGD("%s(%d): wait end... still_running:%d, numfds:%d\n", __FUNCTION__, __LINE__, still_running, numfds);
        if (mc) {
            fprintf(stderr, "curl_multi_poll() failed, code %d.\n", (int)mc);
            break;
        }

        mc = curl_multi_perform(fd->multi, &still_running);
        // HR_LOGD("%s(%d): mc:%d, still_running:%d\n", __FUNCTION__, __LINE__, mc, still_running);
        if (mc != CURLM_OK) {
            HR_LOGD("%s(%d): mc:%d, still_running:%d.... failed!!!!!!!!!\n", __FUNCTION__, __LINE__, mc, still_running);
            break;
        }

        int msgq = 0;
        struct CURLMsg *m = curl_multi_info_read(fd->multi, &msgq);
        if (m && m->msg == CURLMSG_DONE) {
            HR_LOGD("%s(%d):  read complete ................. total:%ld\n", __FUNCTION__, __LINE__, cycle_total);
            fd->status = 0;
            fd->eof = 1;
            break;
        }
        // if (!mc && still_running)
        //    HR_LOGD("%s(%d): wait ... still_running:%d\n", __FUNCTION__, __LINE__, still_running);

        // HR_LOGD("%s(%d):  total:%ld\n", __FUNCTION__, __LINE__, cycle_total);
        if (still_running == 0) {
            // printf("mxppppppppppppppppppppppppppppppppppppppppppppp\n");
            // sleep(1);
            // still_running = 1;
        }
        // avai = cycle_buffer_data_size(fd->cycle);
        // if (avai > size) {
        //    printf("data enough, break; mxppppppppppppppppppppppppppppppppppppppppppppp\n");
        // break;
        //}

        // curl_easy_pause(fd->curl, CURLPAUSE_CONT);
        /* if there are still transfers, loop! */
    } while (still_running && fd->status != 0);

    return NULL;
}
size_t tcloud_drive_read(struct tcloud_drive_fd *fd, char *rbuf, size_t size, off_t offset) {
    size_t result = 0;
    if (!fd) return -1;
    HR_LOGD("%s(%d): ......fd:%p. offset:%ld, size:%ld.\n", __FUNCTION__, __LINE__, fd, offset, size);
    // https://api.cloud.189.cn/getFileDownloadUrl.action
    // struct tcloud_buffer b;
    // tcloud_buffer_prealloc(&b, rbuf, size);

    // snprintf(range, sizeof(range), "%zu-%zu", offset, offset + size - 1);

    // pthread_mutex_lock(&fd->mutex);

    if (fd->tid == 0) {
        int ret = pthread_create(&fd->tid, NULL, _tcloud_drive_read_routin, (void *)fd);
        if (ret != 0) {
            HR_LOGD("%s(%d): ....thread task create failed .....fd:%p. offset:%ld, size:%ld.\n", __FUNCTION__, __LINE__, fd, offset, size);
            return -1;
        }
    }

    pthread_mutex_lock(&fd->lock);
    unsigned int avai = cycle_buffer_data_size(fd->cycle);

    HR_LOGD("%s(%d): ......fd:%p. offset:%ld, size:%ld. current buf offset:%ld, avai:%u\n", __FUNCTION__, __LINE__, fd, offset, size, fd->offset, avai);

    if (avai == 0) {
        if (fd->eof) {
            HR_LOGD("%s(%d): ...end...fd:%p. offset:%ld, size:%ld. current buf offset:%ld, avai:%u\n", __FUNCTION__, __LINE__, fd, offset, size, fd->offset, avai);
            pthread_mutex_unlock(&fd->lock);
            return 0;
        }
        pthread_cond_wait(&fd->read_cond, &fd->lock);
    }

    result = cycle_buffer_get(fd->cycle, (unsigned char *)rbuf, size);
    fd->offset += result;

    pthread_cond_signal(&fd->write_cond);
    pthread_mutex_unlock(&fd->lock);
    HR_LOGD("%s(%d): ........read:%ld, now offset:%u\n", __FUNCTION__, __LINE__, result, fd->offset);

    return result;
}

#if 0
size_t tcloud_drive_read(struct tcloud_drive_fd *fd, char *rbuf, size_t size, off_t offset) {
    size_t result = 0;
    if (!fd) return -1;
    HR_LOGD("%s(%d): ......fd:%p. offset:%ld, size:%ld.\n", __FUNCTION__, __LINE__, fd, offset, size);
    // https://api.cloud.189.cn/getFileDownloadUrl.action
    // struct tcloud_buffer b;
    // tcloud_buffer_prealloc(&b, rbuf, size);

    // snprintf(range, sizeof(range), "%zu-%zu", offset, offset + size - 1);

    // pthread_mutex_lock(&fd->mutex);

    unsigned int avai = cycle_buffer_data_size(fd->cycle);

    HR_LOGD("%s(%d): ......fd:%p. offset:%ld, size:%ld. current buf offset:%ld, avai:%u\n", __FUNCTION__, __LINE__, fd, offset, size, fd->offset, avai);
    // offset is not in cached
    // if (offset < fd->offset || offset > fd->offset + avai) {
    if (offset != fd->offset || avai == 0) {
        // we should reset, and request new data
        int still_running = 0;
        cycle_buffer_reset(fd->cycle);
        fd->offset = offset;
        char range[64] = {0};
        snprintf(range, sizeof(range), "%zu-", offset);
        // curl_easy_setopt(fd->curl, CURLOPT_RANGE, range);
        do {
            int numfds;
            CURLMcode mc = curl_multi_wait(fd->multi, NULL, 0, 1000, &numfds);

            // HR_LOGD("%s(%d): wait end... still_running:%d, numfds:%d\n", __FUNCTION__, __LINE__, still_running, numfds);
            if (mc) {
                fprintf(stderr, "curl_multi_poll() failed, code %d.\n", (int)mc);
                break;
            }

            mc = curl_multi_perform(fd->multi, &still_running);
            // HR_LOGD("%s(%d): mc:%d, still_running:%d\n", __FUNCTION__, __LINE__, mc, still_running);
            if (mc != CURLM_OK) {
                HR_LOGD("%s(%d): mc:%d, still_running:%d.... failed!!!!!!!!!\n", __FUNCTION__, __LINE__, mc, still_running);
                break;
            }

            int msgq = 0;
            struct CURLMsg *m = curl_multi_info_read(fd->multi, &msgq);
            if (m && m->msg == CURLMSG_DONE) {
                HR_LOGD("%s(%d):  read complete ................. total:%ld\n", __FUNCTION__, __LINE__, cycle_total);
                break;
            }
            // if (!mc && still_running)
            //    HR_LOGD("%s(%d): wait ... still_running:%d\n", __FUNCTION__, __LINE__, still_running);

            // HR_LOGD("%s(%d):  total:%ld\n", __FUNCTION__, __LINE__, cycle_total);
            if (still_running == 0) {
                printf("mxppppppppppppppppppppppppppppppppppppppppppppp\n");
                // sleep(1);
                // still_running = 1;
            }
            avai = cycle_buffer_data_size(fd->cycle);
            if (avai > size) {
                printf("data enough, break; mxppppppppppppppppppppppppppppppppppppppppppppp\n");
                // break;
            }

            if (_pause) break;

            // curl_easy_pause(fd->curl, CURLPAUSE_CONT);
            /* if there are still transfers, loop! */
        } while (still_running);

        curl_easy_setopt(fd->curl, CURLOPT_RANGE, NULL);
    }

    result = cycle_buffer_get(fd->cycle, (unsigned char *)rbuf, size);
    fd->offset += result;

    //  pthread_mutex_unlock(&fd->mutex);
    HR_LOGD("%s(%d): ........read:%ld, now offset:%u\n", __FUNCTION__, __LINE__, result, fd->offset);

    // tcloud_buffer_free(&b);

    if (_pause) {
        curl_easy_pause(fd->curl, CURLPAUSE_CONT);
        _pause = 0;
    }
    return result;
}
#endif
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
