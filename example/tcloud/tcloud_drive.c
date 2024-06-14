#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "hr_list.h"
#endif
#include <ctype.h>
#include <curl/multi.h>
#include <fcntl.h>
#include <sys/param.h>
#include <unistd.h>
#include "tcloud/tcloud_request.h"
#include "tcloud_utils.h"

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

#define TCLOUD_REQUEST_POOL_SIZE (2)

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

#define TCLOUD_DRIVE_RESERVE_ID -0xEF00000000000001
// const char *secret = "49A06A5CA9FC9B9FA4EBCE2837B7741A";
// const char *session_key = "da374873-7b39-4020-860b-4279c2db77d9";

const char *secret = "705DD28638B377C924486C7132D4AB9A";
const char *session_key = "ce152573-2cc1-4438-a3db-efe63a43993c";

struct tcloud_drive {
    struct tcloud_request_pool *request_pool;  // api request pool
    pthread_mutex_t mutex;
};

enum tcloud_drive_fd_type {
    TCLOUD_DRIVE_FD_DOWNLOAD = 0,
    TCLOUD_DRIVE_FD_UPLOAD,
};

struct tcloud_drive_fd {
    enum tcloud_drive_fd_type type;
    int64_t id;  // cloud id

    size_t size;  // total file size
    CURLM *multi;
    CURL *curl;  // opened handle
    char *url;

    // cycle_buffer_t *cycle;
    struct tcloud_buffer cache;

    size_t offset;

    int paused;
    // default libfuse using multi thread async mode
    // but we do not support (libcurl)
    // also you can use -s to disable libfuse multi thread feature
    pthread_mutex_t mutex;

    // upload ...
    int is_eof;  // stream is end ?
};

// store read/write read
struct tcloud_drive_data_chunk {
    off_t offset;
    size_t size;
    struct hr_list_head entry;
    char payload[];
};

struct tcloud_drive_upload_fd {
    struct tcloud_drive_fd base;

    char *name;       // file name
    char *upload_id;  // allocated when initMultiUpload
    // size_t total_size; // it should be set in set attr, upload must known full size
    size_t split_slice_size;  // split slice size

    // recoding current offset, it will be used to adjust chunk order
    size_t sequence_processing_offset;

    char md5sum[MD5_DIGEST_LENGTH * 2 + 1];
    EVP_MD_CTX *mdctx;

    // current slice upload related ...
    EVP_MD_CTX *slice_mdctx;
    size_t slice_offset;
    size_t slice_content_length;  // current slice size
    // current slice md5 digest data
    unsigned char slice_md5_digest[MD5_DIGEST_LENGTH];

    // all slices summary
    // store slice md5sum (hex upper string) joined with \n
    struct tcloud_buffer slices_md5sum_data;
    // slice md5sum when only one part
    // or all slice md5sum data set's md5
    char slices_md5sum[MD5_DIGEST_LENGTH * 2 + 1];

    // condition for incoming queue
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    int pending_length;

    pthread_t tid;  // upload thread ...
    // upload related ...
    struct hr_list_head incoming_queue;  // write will queue data into this queue
    struct hr_list_head upload_queue;    // upload thread dequeue from incoming queue and sort chunk into slice part, then upload it
};

#define TCLOUD_DRIVE_UPLOAD_PENDING_MAX (10)

#define TCLOUD_DRIVE_UPLOAD_FD(self) container_of(self, struct tcloud_drive_upload_fd, base)
#define TCLOUD_DRIVE_FD(self) (&self->base)
//#define TCLOUD_DRIVE_DWLOAD_FD(self) container_of(self, struct tcloud_drive_upload_fd, base)

// data of initMultiUpload
struct response_init_multi_upload {
    int type;
    char *host;
    char *id;
    int exists;
};

// data of getMultiUploadUrls
struct response_multi_upload_urls {
    char *url;
    char *header;
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

static size_t _download_receive(void *ptr, size_t size, size_t nmemb,
                                void *userdata) {
    struct tcloud_drive_fd *fd = (struct tcloud_drive_fd *)userdata;
    struct tcloud_buffer *b = NULL;
    size_t total = size * nmemb;
    // HR_LOGD("%s(%d): write:%u\n", __FUNCTION__, __LINE__, total);
    if (!ptr || !userdata)
        return total;  // drop all data

    b = &fd->cache;

#if 0
    if (fd->fd == 0) {
        char path[256] = {0};
        snprintf(path, sizeof(path),
                 "/home/alex/workspace/workspace/libfuse/libfuse/build/"
                 "./dump_%p_%ld",
                 (void *)fd, time(NULL));
        printf("mxp, create:%s\n", path);
        fd->fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        printf("mxp, create:%s -> %d\n", path, fd->fd);
    }

    if (fd->fd > 0) {
        int ret = write(fd->fd, ptr, total);
        if (ret < 0) {
            perror("write failed:\n");
        }
        printf("mxp, write:%d -> %s\n", ret, strerror(errno));
    }
#endif

    if (b->size - b->offset < total) {
        // HR_LOGD("%s(%d):not enough, auto pause total:%ld\n", __FUNCTION__, __LINE__, total);
        fd->paused = 1;
        return CURL_WRITEFUNC_PAUSE;
    }

    tcloud_buffer_append(b, ptr, total);

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

static int _tcloud_drive_fill_final(struct tcloud_request *req, const char *uri, struct tcloud_buffer *params) {
    char tmp[512] = {0};
    if (!req) return -1;

    char uuid[UUID_STR_LEN] = {0};
    tcloud_utils_generate_uuid(uuid, sizeof(uuid));

    char date[64] = {0};
    tcloud_utils_http_date_string(date, sizeof(date));

    req->set_header(req, "Accept", "application/json;charset=UTF-8");
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
    req->set_query(req, "channelId", "web_cloud.189.cn");
    snprintf(tmp, sizeof(tmp), "%d_%d", rand(), rand());
    req->set_query(req, "rand", tmp);

    return 0;
}

int tcloud_drive_init(void) {
    curl_global_init(CURL_GLOBAL_ALL);

    _drive.request_pool = tcloud_request_pool_create(TCLOUD_REQUEST_POOL_SIZE);
    return 0;
}

int tcloud_drive_destroy(void) {
    tcloud_request_pool_destroy(_drive.request_pool);
    curl_global_cleanup();
    return 0;
}

int tcloud_drive_storage_statfs(struct statvfs *st) {
    struct json_object *root = NULL, *capacity = NULL, *available = NULL, *res_code = NULL;
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);

    const char *action = "/getUserInfo.action";

    tcloud_buffer_alloc(&b, 512);

    int ret = _tcloud_drive_fill_final(req, "/getUserInfo.action", NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    req->get(req, API_URL "/getUserInfo.action", &b, NULL);

    _drive.request_pool->release(_drive.request_pool, req);

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

    return 0;
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

    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);

    const char *action = type == 0 ? "/getFolderInfo.action" : "/getFileInfo.action";

    tcloud_buffer_alloc(&b, 512);

    // req->set_query(req, "folderId", "-11");
    char *url = NULL;
    asprintf(&url, API_URL "%s?folderId=%ld", action, id);
    if (!url) return -1;

    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    req->get(req, url, &b, NULL);
    _drive.request_pool->release(_drive.request_pool, req);

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
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);
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
        _drive.request_pool->release(_drive.request_pool, req);
        tcloud_buffer_free(&b);
        return ret;
    }

    printf("%s(%d): ..........\n", __FUNCTION__, __LINE__);

    ret = req->request(req, url, &b, NULL);
    _drive.request_pool->release(_drive.request_pool, req);
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
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);
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
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    ret = req->request(req, url, &b, NULL);
    _drive.request_pool->release(_drive.request_pool, req);
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

// static int tcloud_drive_truncate(const char *path, off_t size,
//                                  struct fuse_file_info *fi) {
//     printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
//     return 0;
// }
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

    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
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

    if (!url) {
        _drive.request_pool->release(_drive.request_pool, req);
        return NULL;
    }

    tcloud_buffer_alloc(&b, 512);
    req->method = TR_METHOD_GET;
    ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return NULL;
    }

    ret = req->request(req, url, &b, NULL);
    _drive.request_pool->release(_drive.request_pool, req);
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
            fd->multi = curl_multi_init();
            fd->curl = curl_easy_init();

            tcloud_buffer_alloc(&fd->cache, TCLOUD_DRIVE_READ_BUFFER_SIZE);

            curl_multi_add_handle(fd->multi, fd->curl);
            curl_easy_setopt(fd->curl, CURLOPT_URL, fd->url);
            curl_easy_setopt(fd->curl, CURLOPT_WRITEFUNCTION, _download_receive);
            curl_easy_setopt(fd->curl, CURLOPT_WRITEDATA, fd);
            // follow redirect
            curl_easy_setopt(fd->curl, CURLOPT_FOLLOWLOCATION, 1);
            // curl_easy_setopt(fd->curl, CURLOPT_BUFFERSIZE, TCLOUD_DRIVE_READ_BUFFER_SIZE / 2);
        }
        printf("%s(%d): ..fd:%p..download url:%s....\n", __FUNCTION__, __LINE__, fd, json_object_get_string(download_url));
        json_object_put(root);
        root = NULL;
    }

    return fd;
}
int tcloud_drive_release(struct tcloud_drive_fd *fd) {
    printf("%s(%d): .....release :%p...\n", __FUNCTION__, __LINE__, fd);
    if (!fd) return -1;
    printf("%s(%d): .....release :%p...\n", __FUNCTION__, __LINE__, fd);
    pthread_mutex_destroy(&fd->mutex);
    curl_multi_remove_handle(fd->multi, fd->curl);
    curl_easy_cleanup(fd->curl);
    curl_multi_cleanup(fd->multi);

    if (fd->url) {
        free(fd->url);
    }

    tcloud_buffer_free(&fd->cache);

    // final free self
    free(fd);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

size_t tcloud_drive_read(struct tcloud_drive_fd *fd, char *rbuf, size_t size, off_t offset) {
    int still_running = 0;

    if (!fd) return -1;
    HR_LOGD("%s(%d): ......fd:%p. offset:%ld, size:%ld.\n", __FUNCTION__, __LINE__, fd, offset, size);

    // offset is not in cached
    if (offset != fd->offset) {
        HR_LOGD("%s(%d): warning !!! random read !!! maybe pool performance .....fd:%p. offset:%ld, size:%ld. current buf offset:%ld, cache size:%u\n", __FUNCTION__, __LINE__, fd, offset, size, fd->offset, fd->cache.offset);
    }

    pthread_mutex_lock(&fd->mutex);
    if (offset == fd->offset && fd->cache.offset != 0) {
        size = MIN(size, fd->cache.offset);
        memcpy(rbuf, fd->cache.data, size);
        memmove(fd->cache.data, fd->cache.data + size, fd->cache.offset - size);
        fd->cache.offset -= size;
        fd->offset += size;
        pthread_mutex_unlock(&fd->mutex);
        return size;
    }

    if (offset != fd->offset) {
        char range[64] = {0};
        snprintf(range, sizeof(range), "%zu-", offset);
        // must remove/add again for new request
        curl_multi_remove_handle(fd->multi, fd->curl);
        curl_easy_setopt(fd->curl, CURLOPT_URL, fd->url);
        curl_easy_setopt(fd->curl, CURLOPT_RANGE, range);
        curl_multi_add_handle(fd->multi, fd->curl);

        // reset offset because it's maybe not equal
        fd->offset = offset;
        // drop all cached data
        // using fast method, direct adjust offset to 0
        fd->cache.offset = 0;  // tcloud_buffer_reset(&fd->data);
    }

    if (fd->paused) {
        // resume when download is paused
        curl_easy_pause(fd->curl, CURLPAUSE_CONT);
        fd->paused = 0;
    }

    do {
        int numfds = 0;
        int msgq = 0;
        CURLMcode mc = curl_multi_wait(fd->multi, NULL, 0, 1000, &numfds);
        if (mc) {
            HR_LOGE("curl_multi_wait failed, code %d.\n", (int)mc);
            break;
        }

        mc = curl_multi_perform(fd->multi, &still_running);
        if (mc != CURLM_OK) {
            HR_LOGD("%s(%d): call curl_multi_perform fail ... mc:%d, still_running:%d.... failed!!!!!!!!!\n", __FUNCTION__, __LINE__, mc, still_running);
            break;
        }

        struct CURLMsg *m = curl_multi_info_read(fd->multi, &msgq);
        if (m && m->msg == CURLMSG_DONE) {
            HR_LOGD("%s(%d):  read complete ... total:%ld ?\n", __FUNCTION__, __LINE__, fd->offset + fd->cache.offset);
            break;
        }

        // download paused, buffer maybe full, we should read directly ...
        if (fd->paused) {
            break;
        }

        // data available/enough, return now
        if (fd->cache.offset >= size) {
            break;
        }

    } while (still_running);

    size = MIN(size, fd->cache.offset);
    memcpy(rbuf, fd->cache.data, size);
    fd->cache.offset -= size;
    if (fd->cache.offset > 0) {
        memmove(fd->cache.data, fd->cache.data + size, fd->cache.offset);
    }

    fd->offset += size;
    pthread_mutex_unlock(&fd->mutex);
    HR_LOGD("%s(%d): ....out .....fd:%p. offset:%ld, size:%ld.\n", __FUNCTION__, __LINE__, fd, offset, size);
    return size;
}
// https://api.cloud.189.cn/newOpen/user/getUserInfo.action
static int tcloud_drive_statfs(const char *path, struct statvfs *buf) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

struct tcloud_drive_fd *tcloud_drive_create(const char *name, int64_t parent) {
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);

    struct tcloud_drive_upload_fd *fd = NULL;

    if (!name) return NULL;

    fd = (struct tcloud_drive_upload_fd *)calloc(1, sizeof(struct tcloud_drive_upload_fd));
    if (!fd) return NULL;

    fd->name = strdup(name);
    // reserved id, id will be reset after commitMultiUploadFile
    TCLOUD_DRIVE_FD(fd)->id = TCLOUD_DRIVE_RESERVE_ID;

    tcloud_buffer_alloc(&fd->slices_md5sum_data, 512);

    HR_INIT_LIST_HEAD(&fd->incoming_queue);
    HR_INIT_LIST_HEAD(&fd->upload_queue);

    pthread_mutex_init(&fd->mutex, NULL);
    pthread_cond_init(&fd->cond, NULL);

    fd->tid = 0;

    return TCLOUD_DRIVE_FD(fd);
}

static void *_tcloud_drive_upload_routin(void *arg) {
    return NULL;
}
int tcloud_drive_write(struct tcloud_drive_fd *self, const char *data, size_t size, off_t offset) {
    HR_LOGD("%s(%d): ........\n", __FUNCTION__, __LINE__);
    struct hr_list_head *p = NULL;
    struct tcloud_drive_upload_fd *fd = NULL;

    struct tcloud_drive_data_chunk *ch = NULL;

    if (!self || !data) return -1;
    fd = TCLOUD_DRIVE_UPLOAD_FD(self);

    if (self->type != TCLOUD_DRIVE_FD_UPLOAD) {
        HR_LOGD("%s(%d): error not upload fd ........\n", __FUNCTION__, __LINE__);
        return -EIO;
    }
    if (fd->tid == 0) {
        int ret = pthread_create(&fd->tid, NULL, _tcloud_drive_upload_routin, fd);
        if (ret != 0) {
            return -EIO;
        }
    }

    // append data bellow chunk directly
    ch = (struct tcloud_drive_data_chunk *)calloc(1, sizeof(struct tcloud_drive_data_chunk) + size);
    if (!ch) {
        return -ENOMEM;
    }

    ch->offset = offset;
    ch->size = size;
    // ch->payload = (char *)ch + sizeof(struct tcloud_drive_data_chunk);
    memcpy(ch->payload, data, size);

    pthread_mutex_lock(&fd->mutex);
    if (fd->pending_length > TCLOUD_DRIVE_UPLOAD_PENDING_MAX) {
        HR_LOGD("%s(%d): reach max pending queue ........\n", __FUNCTION__, __LINE__);
        pthread_cond_wait(&fd->cond, &fd->mutex);
    }

    fd->pending_length++;

    hr_list_for_each_prev(p, &fd->incoming_queue) {
        struct tcloud_drive_data_chunk *c1 = container_of(p, struct tcloud_drive_data_chunk, entry);
        // HR_LOGD("%s(%d): cur :%p, HEAD:%p...current:%ld\n", __FUNCTION__, __LINE__, p, &_queue.head, c1->offset);

        // the last should always bigger
        if (c1->offset < ch->offset) {
            // HR_LOGD("%s(%d): found cur :%p, HEAD:%p...current:%ld\n", __FUNCTION__, __LINE__, p, &_queue.head, c1->offset);
            break;
        }
    }

    hr_list_add(&ch->entry, p);

    pthread_cond_signal(&fd->cond);
    pthread_mutex_unlock(&fd->mutex);
    return size;
}

// maybe called when create, we must known size before upload ...
// see: initMultiUpload
int tcloud_drive_truncate(struct tcloud_drive_fd *self, size_t size) {
    // struct tcloud_drive_upload_fd * fd = NULL;
    if (!self) return -1;
    // fd = TCLOUD_DRIVE_UPLOAD_FD(self);

    self->size = size;

    return 0;
}