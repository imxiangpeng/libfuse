#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <ctype.h>
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

const char *secret = "A8CD8047724920AC491C30F01EEDF6F3";
const char *session_key = "a947ec7d-0ebf-4835-bc8d-0fb75853d3c5";

struct tcloud_drive {
    struct tcloud_request *request;  // api request
    pthread_mutex_t mutex;
};
struct tcloud_drive_fd {
    int64_t id;  // cloud id
    CURL *curl;  // opened handle
    char *url;

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
    int ret = -1;
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    // https://api.cloud.189.cn/getFileDownloadUrl.action
    uuid_t uuid;
    char request_id[UUID_STR_LEN + 20] = {0};
    char *url = NULL;
    // const char* url = "https://api.cloud.189.cn/newOpen/oauth2/accessToken.action";
    struct curl_slist *headers = NULL;
    // const char *secret = "FA75442F51DA58C650DAC77D9BB3DC5B";
    // const char *session_key = "cbc87566-6cf2-47b9-b2f3-f3d48525a16b";

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
    ret = _http_get(url, headers, &buffer);

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
