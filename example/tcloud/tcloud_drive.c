#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <bits/time.h>
#include <openssl/evp.h>

#include "hr_list.h"
#endif
#include <ctype.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <curl/urlapi.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "j2sobject_cloud.h"
#include "tcloud/hr_log.h"
#include "tcloud/tcloud_request.h"
#include "tcloud_buffer.h"
#include "tcloud_drive.h"
#include "tcloud_request.h"
#include "tcloud_utils.h"
#include "uthash.h"
#include "xxtea.h"

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

const char *_user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#define TCLOUD_DRIVE_READ_BUFFER_SIZE (2 * 1024 * 1024)

#define TCLOUD_REQUEST_POOL_SIZE (5)

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

// const char *secret = "49A06A5CA9FC9B9FA4EBCE2837B7741A";
// const char *session_key = "da374873-7b39-4020-860b-4279c2db77d9";

const char *secret = "2605FEBA341CB21F23F57782A042F1B1";
const char *session_key = "82cc88a6-5e43-494d-a50b-66abc579eaa2";

struct tcloud_drive {
    struct tcloud_request_pool *request_pool;  // api request pool
    pthread_mutex_t mutex;
};

enum tcloud_drive_fd_type {
    TCLOUD_DRIVE_FD_DOWNLOAD = 0,
    TCLOUD_DRIVE_FD_UPLOAD,
};
struct tcloud_drive_download_fd {
    struct tcloud_drive_fd base;
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

    EVP_MD_CTX *mdctx;
    char md5sum[MD5_DIGEST_LENGTH * 2 + 1];  // file md5

    // current slice upload related ...
    int slice_id;  // part num/id
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

    struct tcloud_request *upload_request;
    // condition for incoming queue
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    int pending_length;

    int error_code;  // !0 -> error

    pthread_t tid;  // upload thread ...
    // upload related ...
    struct hr_list_head incoming_queue;  // write will queue data into this queue
    struct hr_list_head upload_queue;    // upload thread dequeue from incoming queue and sort chunk into slice part, then upload it
};

#define TCLOUD_DRIVE_UPLOAD_PENDING_MAX (50)

#define TCLOUD_DRIVE_DOWNLOAD_FD(self) container_of(self, struct tcloud_drive_download_fd, base)
#define TCLOUD_DRIVE_UPLOAD_FD(self) container_of(self, struct tcloud_drive_upload_fd, base)
#define TCLOUD_DRIVE_FD(self) (&self->base)

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

static struct tcloud_drive_fd *_tcloud_drive_fd_allocate(enum tcloud_drive_fd_type type);
static void _tcloud_drive_fd_deallocate(struct tcloud_drive_fd *fd);
static int _tcloud_drive_batch_task(const char *type, int64_t target_dir, const char *taskinfo, char *id /*out*/, int len);
static int _tcloud_drive_wait_task(const char *type, const char *id, int *status);

#if 0

static size_t _data_receive(void *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    struct tcloud_buffer *buf = (struct tcloud_buffer *)userdata;
    size_t total = size * nmemb;
    if (!ptr || !userdata)
        return total;  // drop all data

    tcloud_buffer_append(buf, ptr, total);
    return total;
}

#endif

static char *_hex_to_string(const char *data, size_t len) {
    int size = 0;
    size_t offset = 0;
    char *ptr = NULL;
    if (!data) return NULL;

    size = len * 2 + 1;

    ptr = (char *)calloc(1, size);
    if (!ptr) return NULL;

    for (int i = 0; i < len; i++) {
        int rc = snprintf(ptr + offset, size - offset, "%02x", data[i] & 0xFF);
        offset += rc;
    }

    return ptr;
}

static size_t _tcloud_drive_download_receive(void *ptr, size_t size, size_t nmemb, void *userdata) {
    struct tcloud_drive_download_fd *fd = (struct tcloud_drive_download_fd *)userdata;
    struct tcloud_buffer *b = NULL;
    size_t total = size * nmemb;

    if (!ptr || !userdata)
        return total;  // drop all data

    b = &fd->cache;

    if (b->size - b->offset < total) {
        // HR_LOGD("%s(%d):not enough, auto pause total:%ld\n", __FUNCTION__, __LINE__, total);
        fd->paused = 1;
        return CURL_WRITEFUNC_PAUSE;
    }

    tcloud_buffer_append(b, ptr, total);

    return total;
}

static int _tcloud_drive_fill_final(struct tcloud_request *req, const char *uri, struct tcloud_buffer *params) {
    char tmp[512] = {0};
    char *params_query = NULL;
    if (!req) return -1;

    char uuid[UUID_STR_LEN] = {0};
    tcloud_utils_generate_uuid(uuid, sizeof(uuid));

    char date[64] = {0};
    tcloud_utils_http_date_string(date, sizeof(date));
    HR_LOGD("%s(%d): req:%p\n", __FUNCTION__, __LINE__, req);

    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    HR_LOGD("%s(%d): req:%p\n", __FUNCTION__, __LINE__, req);
    req->set_header(req, "Date", date);
    req->set_header(req, "SessionKey", session_key);
    req->set_header(req, "X-Request-ID", uuid);

    char *signature_data = NULL;
    if (params) {
        struct tcloud_buffer r;
        tcloud_buffer_alloc(&r, 512);
        // printf("raw params:%s\n", params->data);
        int rc = tcloud_utils_aes_ecb_data((unsigned char *)secret, params->data, params->offset, &r);
        // printf("aes enc result:%d, result:%ld\n", rc, r.offset);

        params_query = _hex_to_string(r.data, r.offset);
        // printf("encryption text:%s\n", params_query);
        tcloud_buffer_free(&r);
        asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s&params=%s", session_key, req->method == TR_METHOD_GET ? "GET" : "POST", uri, date, params_query);
    } else {
        asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session_key, req->method == TR_METHOD_GET ? "GET" : "POST", uri, date);
    }

    // HR_LOGD("%s(%d): signature data:%s\n", __FUNCTION__, __LINE__, signature_data);
    char *signature = tcloud_utils_hmac_sha1(secret, (const unsigned char *)signature_data, strlen(signature_data));
    // HR_LOGD("%s(%d): signature:%s\n", __FUNCTION__, __LINE__, signature);
    req->set_header(req, "Signature", signature);
    free(signature_data);
    free(signature);

    req->set_header(req, "Referer", "https://cloud.189.cn");

    req->set_query(req, "clientType", "TELEPC");
    req->set_query(req, "version", "6.2");
    req->set_query(req, "channelId", "web_cloud.189.cn");
    snprintf(tmp, sizeof(tmp), "%d_%d", rand(), rand());
    req->set_query(req, "rand", tmp);
    if (params_query) {
        req->set_query(req, "params", params_query);
        free(params_query);
    }

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

    req->method = TR_METHOD_GET;
    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    req->request(req, API_URL "/getUserInfo.action", &b);

    _drive.request_pool->release(_drive.request_pool, req);

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
    st->f_namemax = 255;
    st->f_bsize = 512;
    st->f_blocks = json_object_get_int64(capacity) / st->f_bsize;
    st->f_bfree = json_object_get_int64(available) / st->f_bsize;
    st->f_bavail = json_object_get_int64(available) / st->f_bsize;
    printf("%s(%d): .capability:%ld, available:%ld-%ld....\n", __FUNCTION__, __LINE__, st->f_blocks * st->f_bsize, st->f_bfree, st->f_bavail);
    printf("%s(%d): .capability:%ld, available:%ld-%ld....\n", __FUNCTION__, __LINE__, st->f_blocks * st->f_bsize, st->f_bfree, st->f_bavail);
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

    char *url = NULL;
    struct json_object *root = NULL, *res_code = NULL;
    struct tcloud_buffer b;

    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);

    const char *action = type == 0 ? "/getFolderInfo.action" : "/getFileInfo.action";

    tcloud_buffer_alloc(&b, 512);

    asprintf(&url, API_URL "%s?folderId=%ld", action, id);
    if (!url) return -1;

    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    req->get(req, url, &b);
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

    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);
    const char *action = "/listFiles.action";

    printf("%s(%d): ..........%ld\n", __FUNCTION__, __LINE__, id);

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

    if (!url) {
        _drive.request_pool->release(_drive.request_pool, req);
        return -1;
    }
    tcloud_buffer_alloc(&b, 2048);
    req->method = TR_METHOD_GET;
    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        _drive.request_pool->release(_drive.request_pool, req);
        tcloud_buffer_free(&b);
        return ret;
    }

    ret = req->request(req, url, &b);
    _drive.request_pool->release(_drive.request_pool, req);
    free(url);

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
             "?parentFolderId=%ld",
             parent);

    // query will auto encode url
    req->set_query(req, "folderName", name);

    if (!url) return -1;

    tcloud_buffer_alloc(&b, 512);
    req->method = TR_METHOD_GET;
    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    ret = req->request(req, url, &b);
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

int tcloud_drive_rmdir(int64_t id, const char *name) {
    int rc = 0;
    char tmp[128] = {0};
    struct json_object *root = NULL, *task = NULL;

    root = json_object_new_array();
    task = json_object_new_object();
    json_object_array_add(root, task);

    snprintf(tmp, sizeof(tmp), "%ld", id);
    json_object_object_add(task, "fileId", json_object_new_string(tmp));
    // no need
    char *escape_name = curl_easy_escape(NULL, name, 0);
    json_object_object_add(task, "fileName", json_object_new_string(escape_name));
    curl_free(escape_name);
    json_object_object_add(task, "isFolder", json_object_new_int(1));

    rc = _tcloud_drive_batch_task("DELETE", 0, json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN), tmp, sizeof(tmp));

    json_object_put(root);

    int i = 0;
    while (i < 5) {
        int status = 0;

        usleep(1000 * 100);
        _tcloud_drive_wait_task("DELETE", tmp, &status);
        if (status == 2) {  // conflict
    HR_LOGD("%s(%d): delete maybe failed ....\n", __FUNCTION__, __LINE__);
            return -status;
        }
        if (status == 4) {  // complete
            return 0;
        }

        i++;
    }
    
    HR_LOGD("%s(%d): delete maybe failed ....\n", __FUNCTION__, __LINE__);
    return rc;
}

int tcloud_drive_rename(int64_t id, const char *name, unsigned int flags) {
    printf("%s(%d): .....rename %ld -> %s with flags:0x%X ...\n", __FUNCTION__, __LINE__, id, name, flags);
    char tmp[128] = {0};
    char *url = NULL;
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);
    const char *action = "/renameFile.action";
    struct json_object *root = NULL, *res_code = NULL;

    if (!name) return -1;

    snprintf(tmp, sizeof(tmp), "%ld", id);
    if (flags == 1) {
        action = "/renameFolder.action";
        req->set_query(req, "folderId", tmp);
        // no need manual encode name, auto encoded when we request
        req->set_query(req, "destFolderName", name);
    } else {
        req->set_query(req, "fileId", tmp);
        // no need manual encode name, auto encoded when we request
        req->set_query(req, "destFileName", name);
    }

    asprintf(&url, API_URL "%s", action);

    if (!url) return -1;

    tcloud_buffer_alloc(&b, 512);
    req->method = TR_METHOD_GET;
    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    ret = req->request(req, url, &b);
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
    json_object_put(root);
    return 0;
}

int tcloud_drive_move(int64_t id, const char *name, int64_t parent, unsigned int flags) {
    printf("%s(%d): .....move %ld -> %s with flags:0x%X ...\n", __FUNCTION__, __LINE__, id, name, flags);
    int rc = 0;
    char tmp[128] = {0};
    struct json_object *root = NULL, *task = NULL;

    if (!name) return -1;

    snprintf(tmp, sizeof(tmp), "%ld", id);

    root = json_object_new_array();
    task = json_object_new_object();
    json_object_array_add(root, task);

    snprintf(tmp, sizeof(tmp), "%ld", id);
    json_object_object_add(task, "fileId", json_object_new_string(tmp));
    // no need
    char *escape_name = curl_easy_escape(NULL, name, 0);
    json_object_object_add(task, "fileName", json_object_new_string(escape_name));
    curl_free(escape_name);
    json_object_object_add(task, "isFolder", json_object_new_int(flags == 1 ? 1 : 0));

    rc = _tcloud_drive_batch_task("MOVE", parent, json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN), tmp, sizeof(tmp));

    json_object_put(root);

    int i = 0;
    while (i < 5) {
        int status = 0;

        usleep(1000 * 100);
        _tcloud_drive_wait_task("MOVE", tmp, &status);
        if (status == 2) {  // conflict
    HR_LOGD("%s(%d): delete maybe failed ....\n", __FUNCTION__, __LINE__);
            return -status;
        }
        if (status == 4) {  // complete
            return 0;
        }

        i++;
    }

    HR_LOGD("%s(%d): delete maybe failed ....\n", __FUNCTION__, __LINE__);
    return rc;
}

// return real download url
struct tcloud_drive_fd *tcloud_drive_open(int64_t id) {
    struct tcloud_drive_download_fd *fd = NULL;
    struct tcloud_buffer b;
    int ret = -1;
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    // https://api.cloud.189.cn/getFileDownloadUrl.action
    char *url = NULL;

    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    const char *action = "/getFileDownloadUrl.action";
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

    ret = req->request(req, url, &b);
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
            struct tcloud_drive_fd *self = _tcloud_drive_fd_allocate(TCLOUD_DRIVE_FD_DOWNLOAD);
            
            self->id = id;

            fd = TCLOUD_DRIVE_DOWNLOAD_FD(self);
            fd->url = strdup(json_object_get_string(download_url));
            pthread_mutex_init(&fd->mutex, NULL);
            fd->multi = curl_multi_init();
            fd->curl = curl_easy_init();

            tcloud_buffer_alloc(&fd->cache, TCLOUD_DRIVE_READ_BUFFER_SIZE);

            curl_multi_add_handle(fd->multi, fd->curl);
            curl_easy_setopt(fd->curl, CURLOPT_URL, fd->url);
            curl_easy_setopt(fd->curl, CURLOPT_WRITEFUNCTION, _tcloud_drive_download_receive);
            curl_easy_setopt(fd->curl, CURLOPT_WRITEDATA, fd);
            // follow redirect
            curl_easy_setopt(fd->curl, CURLOPT_FOLLOWLOCATION, 1);
        }
        printf("%s(%d): ..fd:%p..download url:%s....\n", __FUNCTION__, __LINE__, fd, json_object_get_string(download_url));
        json_object_put(root);
        root = NULL;
    }

    return TCLOUD_DRIVE_FD(fd);
}

int tcloud_drive_release(struct tcloud_drive_fd *fd, int64_t *id) {
    printf("%s(%d): .....release :%p...\n", __FUNCTION__, __LINE__, fd);
    if (!fd) return -1;
    HR_LOGD("%s(%d): .....release :%p...\n", __FUNCTION__, __LINE__, fd);

    if (fd->type == TCLOUD_DRIVE_FD_DOWNLOAD) {
        struct tcloud_drive_download_fd *_fd = TCLOUD_DRIVE_DOWNLOAD_FD(fd);
        pthread_mutex_destroy(&_fd->mutex);
        curl_multi_remove_handle(_fd->multi, _fd->curl);
        curl_easy_cleanup(_fd->curl);
        curl_multi_cleanup(_fd->multi);

        if (_fd->url) {
            free(_fd->url);
        }

        tcloud_buffer_free(&_fd->cache);
        free(_fd);
        return 0;
    }

    if (fd->type == TCLOUD_DRIVE_FD_UPLOAD) {
        struct tcloud_drive_upload_fd *_fd = TCLOUD_DRIVE_UPLOAD_FD(fd);
        printf("%s(%d): .mark as eof .......\n", __FUNCTION__, __LINE__);

        fd->is_eof = 1;
        pthread_cond_broadcast(&_fd->cond);
        if (_fd->tid != 0) {
            pthread_join(_fd->tid, NULL);
            _fd->tid = 0;
        }
        
        if (id) {
            *id = fd->id;
        }

        tcloud_buffer_free(&_fd->slices_md5sum_data);

        if (_fd->name) {
            free(_fd->name);
            _fd->name = NULL;
        }
        if (_fd->upload_id) {
            free(_fd->upload_id);
            _fd->upload_id = NULL;
        }
        pthread_mutex_destroy(&_fd->mutex);
        pthread_cond_destroy(&_fd->cond);

        if (_fd->upload_request) {
            tcloud_request_free(_fd->upload_request);
            _fd->upload_request = NULL;
        }

        _tcloud_drive_fd_deallocate(fd);
        return 0;
    }

    // final free self
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return 0;
}

size_t tcloud_drive_read(struct tcloud_drive_fd *fd, char *rbuf, size_t size, off_t offset) {
    int still_running = 0;
    struct tcloud_drive_download_fd *_fd = NULL;

    if (!fd) return -1;
    HR_LOGD("%s(%d): ......fd:%p. offset:%ld, size:%ld.\n", __FUNCTION__, __LINE__, fd, offset, size);

    _fd = TCLOUD_DRIVE_DOWNLOAD_FD(fd);
    // offset is not in cached
    if (offset != _fd->offset) {
        HR_LOGD("%s(%d): warning !!! random read !!! maybe pool performance .....fd:%p. offset:%ld, size:%ld. current buf offset:%ld, cache size:%u\n", __FUNCTION__, __LINE__, fd, offset, size, _fd->offset, _fd->cache.offset);
    }

    pthread_mutex_lock(&_fd->mutex);
    if (offset == _fd->offset && _fd->cache.offset != 0) {
        size = MIN(size, _fd->cache.offset);
        memcpy(rbuf, _fd->cache.data, size);
        memmove(_fd->cache.data, _fd->cache.data + size, _fd->cache.offset - size);
        _fd->cache.offset -= size;
        _fd->offset += size;
        pthread_mutex_unlock(&_fd->mutex);
        return size;
    }

    if (offset != _fd->offset) {
        char range[64] = {0};
        // do not end, so we may prefetch some data when sequence read ...
        snprintf(range, sizeof(range), "%zu-", offset);
        // snprintf(range, sizeof(range), "%zu-%zu", offset, offset + size);
        // must remove/add again for new request
        curl_multi_remove_handle(_fd->multi, _fd->curl);
        curl_easy_setopt(_fd->curl, CURLOPT_URL, _fd->url);
        curl_easy_setopt(_fd->curl, CURLOPT_RANGE, range);
        curl_multi_add_handle(_fd->multi, _fd->curl);

        // reset offset because it's maybe not equal
        _fd->offset = offset;
        // drop all cached data
        // using fast method, direct adjust offset to 0
        _fd->cache.offset = 0;  // tcloud_buffer_reset(&fd->data);
    }

    if (_fd->paused) {
        // resume when download is paused
        curl_easy_pause(_fd->curl, CURLPAUSE_CONT);
        _fd->paused = 0;
    }

    do {
        int numfds = 0;
        int msgq = 0;
        CURLMcode mc = curl_multi_wait(_fd->multi, NULL, 0, 1000, &numfds);
        if (mc) {
            HR_LOGE("curl_multi_wait failed, code %d.\n", (int)mc);
            break;
        }

        mc = curl_multi_perform(_fd->multi, &still_running);
        if (mc != CURLM_OK) {
            HR_LOGD("%s(%d): call curl_multi_perform fail ... mc:%d, still_running:%d.... failed!!!!!!!!!\n", __FUNCTION__, __LINE__, mc, still_running);
            break;
        }

        struct CURLMsg *m = curl_multi_info_read(_fd->multi, &msgq);
        if (m && m->msg == CURLMSG_DONE) {
            HR_LOGD("%s(%d):  read complete ... total:%ld ?\n", __FUNCTION__, __LINE__, _fd->offset + _fd->cache.offset);
            break;
        }

        // download paused, buffer maybe full, we should read directly ...
        if (_fd->paused) {
            break;
        }

        // data available/enough, return now
        if (_fd->cache.offset >= size) {
            break;
        }

    } while (still_running);

    size = MIN(size, _fd->cache.offset);
    memcpy(rbuf, _fd->cache.data, size);
    _fd->cache.offset -= size;
    if (_fd->cache.offset > 0) {
        memmove(_fd->cache.data, _fd->cache.data + size, _fd->cache.offset);
    }

    _fd->offset += size;
    pthread_mutex_unlock(&_fd->mutex);
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
    struct tcloud_drive_fd *self = NULL;

    struct tcloud_drive_upload_fd *fd = NULL;

    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    if (!name) return NULL;

    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    self = _tcloud_drive_fd_allocate(TCLOUD_DRIVE_FD_UPLOAD);
    if (!self) return NULL;

    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    fd = TCLOUD_DRIVE_UPLOAD_FD(self);

    fd->name = strdup(name);
    // reserved id, id will be reset after commitMultiUploadFile
    self->id = TCLOUD_DRIVE_RESERVE_ID;
    self->parent = parent;

    tcloud_buffer_alloc(&fd->slices_md5sum_data, 512);

    HR_INIT_LIST_HEAD(&fd->incoming_queue);
    HR_INIT_LIST_HEAD(&fd->upload_queue);
    pthread_condattr_t condattr;
    pthread_condattr_init(&condattr);
    pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC);
    pthread_mutex_init(&fd->mutex, NULL);
    pthread_cond_init(&fd->cond, NULL);

    fd->tid = 0;

    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return TCLOUD_DRIVE_FD(fd);
}

static int init_multi_upload(struct tcloud_drive_upload_fd *fd, struct response_init_multi_upload *data) {
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);  // tcloud_request_new();

    const char *url = "http://upload.cloud.189.cn/person/initMultiUpload";

    const char *action = "/person/initMultiUpload";

    char tmp[256] = {0};

    HR_LOGD("%s(%d): .....fd:%p -> %s... req:%p\n", __FUNCTION__, __LINE__, fd, fd->name, req);
    tcloud_buffer_alloc(&b, 512);
    snprintf(tmp, sizeof(tmp), "parentFolderId=%ld", TCLOUD_DRIVE_FD(fd)->parent);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "fileName=");
    // care that you should encode filename when it contains zh
    char *escape_name = curl_easy_escape(NULL, fd->name, strlen(fd->name));
    tcloud_buffer_append_string(&b, escape_name);
    curl_free(escape_name);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "fileSize=");
    snprintf(tmp, sizeof(tmp), "%ld", TCLOUD_DRIVE_FD(fd)->size);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "sliceSize=");
    snprintf(tmp, sizeof(tmp), "%ld", fd->split_slice_size);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "lazyCheck=1");

    HR_LOGD("%s(%d): init params:%s\n", __FUNCTION__, __LINE__, b.data);

    req->method = TR_METHOD_GET;
    HR_LOGD("%s(%d): .....fd:%p -> %s... req:%p\n", __FUNCTION__, __LINE__, fd, fd->name, req);
    _tcloud_drive_fill_final(req, action, &b);
    HR_LOGD("%s(%d): .....fd:%p -> %s... req:%p\n", __FUNCTION__, __LINE__, fd, fd->name, req);

    tcloud_buffer_reset(&b);
    HR_LOGD("%s(%d): .....fd:%p -> %s... req:%p\n", __FUNCTION__, __LINE__, fd, fd->name, req);
    req->request(req, url, &b);

    HR_LOGD("%s(%d): .....fd:%p -> %s... req:%p\n", __FUNCTION__, __LINE__, fd, fd->name, req);
    printf("result:(%ld)%s\n", b.offset, b.data);

    _drive.request_pool->release(_drive.request_pool, req);

    if (!data) {
        return -1;
    }
    struct json_object *root = NULL, *code = NULL, *json_data = NULL;
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "code", &code);
    if (!code || strcmp("SUCCESS", json_object_get_string(code)) != 0) {
        json_object_put(root);
        printf(" can not parse json or request failed.....\n");
        return -1;
    }
    json_object_object_get_ex(root, "data", &json_data);
    if (!json_data) {
        json_object_put(root);
        return -1;
    }

    struct json_object *json_upload_type = NULL, *json_upload_host = NULL, *json_upload_file_id = NULL, *json_file_data_exists = NULL;
    json_object_object_get_ex(json_data, "uploadType", &json_upload_type);
    json_object_object_get_ex(json_data, "uploadHost", &json_upload_host);
    json_object_object_get_ex(json_data, "uploadFileId", &json_upload_file_id);
    json_object_object_get_ex(json_data, "fileDataExists", &json_file_data_exists);

    data->type = json_object_get_int(json_upload_type);
    data->host = strdup(json_object_get_string(json_upload_host));
    data->id = strdup(json_object_get_string(json_upload_file_id));
    data->exists = json_object_get_int(json_file_data_exists);

    // HR_LOGD("%s(%d): .uploadType:%d, uploadHost:%s, uploadFileId:%s, fileDataExists:%d...\n", __FUNCTION__, __LINE__,
    //        json_object_get_int(json_upload_type),
    //        json_object_get_string(json_upload_host),
    //        json_object_get_string(json_upload_file_id),
    //        json_object_get_int(json_file_data_exists));
    json_object_put(root);
    return 0;
}

static int get_multi_upload_urls(const char *id, int part, const char *md5_base64, struct response_multi_upload_urls *res) {
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);

    const char *url = "http://upload.cloud.189.cn/person/getMultiUploadUrls";

    const char *action = "/person/getMultiUploadUrls";

    char tmp[256] = {0};

    tcloud_buffer_alloc(&b, 512);
    snprintf(tmp, sizeof(tmp), "uploadFileId=%s", id);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    snprintf(tmp, sizeof(tmp), "partInfo=%d-%s", part, md5_base64);
    tcloud_buffer_append_string(&b, tmp);

    req->method = TR_METHOD_GET;
    _tcloud_drive_fill_final(req, action, &b);

    tcloud_buffer_reset(&b);
    req->request(req, url, &b);

    // printf("result:(%ld)%s\n", b.offset, b.data);

    _drive.request_pool->release(_drive.request_pool, req);

    struct json_object *root = NULL, *code = NULL;
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "code", &code);
    if (!code || strcmp("SUCCESS", json_object_get_string(code)) != 0) {
        json_object_put(root);
        printf(" can not parse json or request failed.....\n");
        return -1;
    }

    struct json_object *json_upload_urls = NULL;
    json_object_object_get_ex(root, "uploadUrls", &json_upload_urls);

    const char *part_number_prefix = "partNumber_";
    json_object_object_foreach(json_upload_urls, key, val) {
        printf("keys:%s\n", key);
        if (!strncmp(key, part_number_prefix, strlen(part_number_prefix))) {
            res->url = strdup(json_object_get_string(json_object_object_get(val, "requestURL")));
            res->header = strdup(json_object_get_string(json_object_object_get(val, "requestHeader")));
            break;
        }
    }
    json_object_put(root);

    return 0;
}

static size_t _upload_read_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    int rs = 0;
    struct tcloud_drive_data_chunk *ch = NULL;
    struct tcloud_drive_upload_fd *fd = (struct tcloud_drive_upload_fd *)userdata;
    if (!fd) return -1;
    // always return one chunk

    // HR_LOGD("%s(%d): read data :%ld\n", __FUNCTION__, __LINE__, size * nmemb);
    if (hr_list_empty(&fd->upload_queue)) {
        return 0;
    }

    ch = hr_list_first_entry(&fd->upload_queue, struct tcloud_drive_data_chunk, entry);
    rs = ch->size;

    // HR_LOGD("%s(%d): read data :%ld, current chunk:%ld\n", __FUNCTION__, __LINE__,  size * nmemb, ch->size);
    if (rs <= size * nmemb) {
        memcpy(ptr, ch->payload, rs);
        hr_list_del(&ch->entry);
        free(ch);
        return rs;
    }
    rs = size * nmemb;
    memcpy(ptr, ch->payload, rs);
    ch->offset += rs;
    ch->size -= rs;
    memcpy(ch->payload, ch->payload + rs, ch->size);
    // HR_LOGD("%s(%d): split read data :%ld, current chunk:%ld, real read:%ld\n", __FUNCTION__, __LINE__,  size * nmemb, ch->size, rs);
    // leave it later delete
    return rs;
}

static int do_stream_upload(struct tcloud_drive_upload_fd *fd) {
    int rc = -1;
    struct response_multi_upload_urls res;

    struct tcloud_buffer b;
    struct tcloud_request *req = NULL;
    char tmp[128] = {0};

    if (!fd) return -1;
    memset((void *)&res, 0, sizeof(res));

    char *md5_base64 = tcloud_utils_base64_encode((const char *)fd->slice_md5_digest, sizeof(fd->slice_md5_digest));

    HR_LOGD("%s(%d): upload id:%s, part:%d, md5sum:%s\n", __FUNCTION__, __LINE__, fd->upload_id, fd->slice_id, md5_base64);

    rc = get_multi_upload_urls(fd->upload_id, fd->slice_id + 1, md5_base64, &res);

    free(md5_base64);

    if (rc != 0) {
        HR_LOGD("%s(%d): can not get upload url!\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if (!fd->upload_request) {
        fd->upload_request = tcloud_request_new();
    }

    req = fd->upload_request;

    tcloud_buffer_alloc(&b, 512);

    HR_LOGD("%s(%d): response url:%s, header:%s\n", __FUNCTION__, __LINE__, res.url, res.header);

    char *saveptr, *saveptr2;
    char *token = strtok_r(res.header, "&", &saveptr);
    while (token) {
        char *name = strtok_r(token, "=", &saveptr2);
        char *value = saveptr2;  // strtok_r(saveptr2, "=", &saveptr2);
        printf("name:%s, val:%s\n", name, value);

        req->set_header(req, name, value);

        token = strtok_r(saveptr, "&", &saveptr);
    }

#if 0  // force none https for debug!
    if (!strncmp(res.url, "https://", 8)) {
        size_t len = strlen(res.url);
        memcpy(res.url + 4, res.url + 5, len - 5);
        res.url[len - 1] = '\0';
    }
#endif

    req->set_header(req, "Expect", NULL);

    req->set_header(req, "Accept", "application/json;charset=UTF-8");

    req->set_header(req, "User-Agent", _user_agent);

    req->set_query(req, "clientType", "TELEPC");
    req->set_query(req, "version", "6.2");
    req->set_query(req, "channelId", "web_cloud.189.cn");
    snprintf(tmp, sizeof(tmp), "%d_%d", rand(), rand());
    req->set_query(req, "rand", tmp);

    req->put(req, res.url, &b, fd->slice_content_length, _upload_read_callback, fd);

    HR_LOGD("%s(%d): response url:%s, header:%s\n", __FUNCTION__, __LINE__, res.url, res.header);
    printf("upload result:%s\n", b.data);

    if (res.url) {
        free(res.url);
    }
    if (res.header) {
        free(res.header);
    }

    tcloud_buffer_free(&b);

    return 0;
}

static int do_commit_upload(struct tcloud_drive_upload_fd *fd) {
    struct tcloud_buffer b;
    struct tcloud_request *req = NULL;

    const char *url = "http://upload.cloud.189.cn/person/commitMultiUploadFile";
    const char *action = "/person/commitMultiUploadFile";
    char tmp[256] = {0};

    if (!fd) return -1;

    req = tcloud_request_new();

    tcloud_buffer_alloc(&b, 512);
    snprintf(tmp, sizeof(tmp), "uploadFileId=%s", fd->upload_id);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    snprintf(tmp, sizeof(tmp), "fileMd5=%s", fd->md5sum);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    snprintf(tmp, sizeof(tmp), "sliceMd5=%s", fd->slices_md5sum);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "opertype=3");  // force overwrite origin file
    tcloud_buffer_append_string(&b, "&");
    // always lazy check
    snprintf(tmp, sizeof(tmp), "lazyCheck=%d", 1 /*queue->slice_size == 1 ? 0 : 1*/);
    tcloud_buffer_append_string(&b, tmp);

    HR_LOGD("%s(%d): .....deallocate:%p -> %s...param:%s\n", __FUNCTION__, __LINE__, fd, fd->name, b.data);
    req->method = TR_METHOD_GET;
    _tcloud_drive_fill_final(req, action, &b);

    HR_LOGD("%s(%d): .....deallocate:%p -> %s...\n", __FUNCTION__, __LINE__, fd, fd->name);
    tcloud_buffer_reset(&b);
    req->request(req, url, &b);
    tcloud_request_free(req);

    printf("result:(%ld)%s\n", b.offset, b.data);
    // parse result:
    // {"code":"SUCCESS","file":{"userFileId":"924751139406138475","fileName":"upload_data(20240614113937).bin","fileSize":330692658,"fileMd5":"58D7264C94A1F48513A83D6F55C74ABD","createDate":"Jun 14, 2024 11:39:37 AM","rev":20240614113937,"userId":300000969222651}}
    struct json_object *root = NULL, *code = NULL, *json_file = NULL;
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }

    json_object_object_get_ex(root, "code", &code);
    if (!code || strcmp("SUCCESS", json_object_get_string(code)) != 0) {
        json_object_put(root);
        printf(" can not parse json or request failed.....\n");
        return -1;
    }

    json_object_object_get_ex(root, "file", &json_file);

    TCLOUD_DRIVE_FD(fd)->id = atol(json_object_get_string(json_object_object_get(json_file, "userFileId")));
    json_object_put(root);

    HR_LOGD("%s(%d): upload success :%ld\n", __FUNCTION__, __LINE__, TCLOUD_DRIVE_FD(fd)->id);

    return 0;
}

#define CHUNK_10M (1024 * 1024 * 10)
static size_t _calc_slice_size(size_t total) {
    static struct {
        size_t size;
        size_t min;
        size_t max;
    } _slice_size_table[] = {
        {CHUNK_10M, 0, 1000L * CHUNK_10M},
        {CHUNK_10M * 2, 1000L * CHUNK_10M, 1000L * CHUNK_10M * 2},
        {CHUNK_10M * 5, 1000L * CHUNK_10M * 2, 2000L * CHUNK_10M * 5},
        // n >= 6
        // 2000*(n-1)*10MB  ->  2000_n_10MB  -> 2000 片 n*10MB
        // {CHUNK_10M * n, 1000L * CHUNK_10M * ( n - 1), 2000L * CHUNK_10M * n},
    };

    for (int i = 0; i < sizeof(_slice_size_table) / sizeof(_slice_size_table[0]); i++) {
        if (total >= _slice_size_table[i].min && total < _slice_size_table[i].max) {
            return _slice_size_table[i].size;
        }
    }

    total += CHUNK_10M * 2000L;

    return total / 2000L;  //(total / (CHUNK_10M * 2000L)) * CHUNK_10M;
}

static void *_tcloud_drive_upload_routin(void *arg) {
    int rc = 0;
    struct tcloud_drive_upload_fd *fd = (struct tcloud_drive_upload_fd *)arg;
    struct tcloud_drive_data_chunk *ch = NULL;
    struct response_init_multi_upload init_resp;

    char md5[MD5_DIGEST_LENGTH * 2 + 1] = {0};

    if (!fd) return NULL;

    fd->mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(fd->mdctx, EVP_md5(), NULL);

    fd->slice_mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(fd->slice_mdctx, EVP_md5(), NULL);

    if (fd->split_slice_size == 0) {
        fd->split_slice_size = _calc_slice_size(TCLOUD_DRIVE_FD(fd)->size);
    }

    HR_LOGE("%s(%d): split slice size:%ld...\n", __FUNCTION__, __LINE__, fd->split_slice_size);

    HR_LOGD("%s(%d): .....deallocate:%p -> %s...\n", __FUNCTION__, __LINE__, fd, fd->name);
    // init multi upload ...
    rc = init_multi_upload(fd, &init_resp);
    HR_LOGD("%s(%d): .....deallocate:%p -> %s...\n", __FUNCTION__, __LINE__, fd, fd->name);
    if (rc != 0) {
        HR_LOGE("%s(%d): initMultiUpload failed ...\n", __FUNCTION__, __LINE__);
        fd->error_code = -1;  // init error
        pthread_cond_signal(&fd->cond);
        return NULL;
    }

    // move memory to fd->upload_id directly, (no need allocate again)
    // fd->upload_id will be freed later!
    if (init_resp.id) {
        fd->upload_id = init_resp.id;
        init_resp.id = NULL;
    }

    if (init_resp.host) {
        free(init_resp.host);
        init_resp.host = NULL;
    }

    if (!fd->upload_id) {
        HR_LOGE("%s(%d): initMultiUpload failed can not get upload id...\n", __FUNCTION__, __LINE__);

        return NULL;
    }

    while (1) {
        pthread_mutex_lock(&fd->mutex);

        if (hr_list_empty(&fd->incoming_queue)) {
            HR_LOGD("%s(%d): incoming queue is empty ...\n", __FUNCTION__, __LINE__);
            if (TCLOUD_DRIVE_FD(fd)->is_eof) {
                pthread_mutex_unlock(&fd->mutex);
                break;
            }
            pthread_cond_wait(&fd->cond, &fd->mutex);
            // we should verify weather it's end
            pthread_mutex_unlock(&fd->mutex);
            continue;
        }

        // peek the first chunk
        ch = hr_list_first_entry(&fd->incoming_queue, struct tcloud_drive_data_chunk, entry);

        HR_LOGD("%s(%d): incoming chunk offset:%ld vs %ld, size: %ld...\n", __FUNCTION__, __LINE__, ch->offset, fd->sequence_processing_offset, ch->size);
        // zero chunk -> end of file
        if (ch->size == 0) {
            pthread_mutex_unlock(&fd->mutex);
            break;
        }

        // current chunk is not order! wait next chunk come in
        if (fd->sequence_processing_offset != ch->offset) {
            HR_LOGD("%s(%d): incoming chunk offset:%ld, size: %ld  offset not matched...\n", __FUNCTION__, __LINE__, ch->offset, ch->size);
            pthread_cond_wait(&fd->cond, &fd->mutex);
            pthread_mutex_unlock(&fd->mutex);
            continue;
        }

        // verify current slice is full?
        if (fd->slice_offset + ch->size < fd->split_slice_size) {
            // adjust current slice to upload queue
            EVP_DigestUpdate(fd->mdctx, ch->payload, ch->size);
            EVP_DigestUpdate(fd->slice_mdctx, ch->payload, ch->size);
            fd->slice_offset += ch->size;
            fd->sequence_processing_offset += ch->size;
            fd->slice_content_length += ch->size;

            // move to upload queue
            hr_list_move_tail(&ch->entry, &fd->upload_queue);
            fd->pending_length--;
            pthread_cond_signal(&fd->cond);
            pthread_mutex_unlock(&fd->mutex);
            continue;
        }

        // now it's large than split slice size, we should split chunk
        size_t s = fd->split_slice_size - fd->slice_offset;

        EVP_DigestUpdate(fd->mdctx, ch->payload, s);
        EVP_DigestUpdate(fd->slice_mdctx, ch->payload, s);
        fd->slice_offset += s;
        fd->sequence_processing_offset += s;
        fd->slice_content_length += s;

        // consume full chunk
        if (ch->size - s == 0) {
            hr_list_move_tail(&ch->entry, &fd->upload_queue);
            fd->pending_length--;
        } else {
            // split current chunk to two, and leave current chunk in incoming queue
            // append data bellow chunk directly
            struct tcloud_drive_data_chunk *n = (struct tcloud_drive_data_chunk *)calloc(1, sizeof(struct tcloud_drive_data_chunk) + ch->size);
            if (!n) {
                // return -ENOMEM;
            }

            HR_INIT_LIST_HEAD(&n->entry);

            n->offset = ch->offset;
            n->size = s;
            // copy chunk write data to new chunk
            memcpy(n->payload, ch->payload, s);
            // add new chunk to upload queue
            hr_list_add_tail(&n->entry, &fd->upload_queue);

            // leave left data in current chunk
            ch->offset += s;
            ch->size -= s;

            memcpy(ch->payload, ch->payload + s, ch->size);
        }

        pthread_mutex_unlock(&fd->mutex);
        // calc current slice md5 information
        unsigned int digest_length = sizeof(fd->slice_md5_digest);
        EVP_DigestFinal_ex(fd->slice_mdctx, fd->slice_md5_digest, &digest_length);

        char *ptr = md5;
        int available = sizeof(md5);
        for (unsigned int i = 0; i < digest_length; i++) {
            if (available < 2) break;
            int ret = snprintf(ptr, available, "%02X", fd->slice_md5_digest[i]);
            available -= ret;
            ptr += ret;
        }

        if (fd->slice_id != 0) {
            tcloud_buffer_append_string(&fd->slices_md5sum_data, "\n");
        }
        tcloud_buffer_append_string(&fd->slices_md5sum_data, md5);

        // do upload ...
        do_stream_upload(fd);

        printf("%s(%d): @@@@@@@@@@@@@@@@@@@@@ finished part %d ....................\n", __FUNCTION__, __LINE__, fd->slice_id);
        fd->slice_id++;
        fd->slice_offset = 0;
        fd->slice_content_length = 0;

        // init md5 ctx again for next slice
        EVP_DigestInit_ex(fd->slice_mdctx, EVP_md5(), NULL);
        memset((void *)fd->slice_md5_digest, 0, sizeof(fd->slice_md5_digest));

        // make sure all chunk have been freed!
        // normal it will be freed when have been readed!
        while (!hr_list_empty(&fd->upload_queue)) {
            ch = hr_list_first_entry(&fd->upload_queue, struct tcloud_drive_data_chunk, entry);
            hr_list_del(&ch->entry);
            free(ch);
            ch = NULL;
        }

        HR_INIT_LIST_HEAD(&fd->upload_queue);
    }

    // final last slice (not full in above)

    // update the last not full slice
    if (!hr_list_empty(&fd->upload_queue)) {
        // calc current slice md5 information
        unsigned int digest_length = sizeof(fd->slice_md5_digest);
        EVP_DigestFinal_ex(fd->slice_mdctx, fd->slice_md5_digest, &digest_length);
        printf("%s(%d): @@@@@@@@@@@@@@@@@@@@@ upload the last part ..................\n", __FUNCTION__, __LINE__);

        char *ptr = md5;
        int available = sizeof(md5);
        for (unsigned int i = 0; i < digest_length; i++) {
            if (available < 2) break;
            int ret = snprintf(ptr, available, "%02X", fd->slice_md5_digest[i]);
            available -= ret;
            ptr += ret;
        }

        if (fd->slice_id != 0) {
            tcloud_buffer_append_string(&fd->slices_md5sum_data, "\n");
        }
        tcloud_buffer_append_string(&fd->slices_md5sum_data, md5);
        // uploading the last ...
        do_stream_upload(fd);
        fd->slice_id++;
    }

    // final total file md5sum
    unsigned char *md5_digest = NULL;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
    char *ptr = fd->md5sum;
    int available = sizeof(fd->md5sum);

    md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(fd->mdctx, md5_digest, &md5_digest_len);

    for (unsigned int i = 0; i < md5_digest_len; i++) {
        if (available < 2) break;
        int ret = snprintf(ptr, available, "%02X", md5_digest[i]);
        available -= ret;
        ptr += ret;
    }

    HR_LOGD("%s(%d): file total md5sum:%s, fd->slice_id:%d\n", __FUNCTION__, __LINE__, fd->md5sum, fd->slice_id);

    // multi parts ?
    // if (TCLOUD_DRIVE_FD(fd)->size / fd->split_slice_size > 1) {
    if (fd->slice_id == 1) {
        snprintf(fd->slices_md5sum, sizeof(fd->slices_md5sum), "%s", fd->slices_md5sum_data.data);
    } else {
        // must call init again
        EVP_DigestInit_ex(fd->mdctx, EVP_md5(), NULL);

        HR_LOGD("%s(%d): slice sum data:%s\n", __FUNCTION__, __LINE__, fd->slices_md5sum_data.data);
        printf("%s(%d): slice sum data:%s\n", __FUNCTION__, __LINE__, fd->slices_md5sum_data.data);
        EVP_DigestUpdate(fd->mdctx, fd->slices_md5sum_data.data, fd->slices_md5sum_data.offset);
        md5_digest_len = EVP_MD_size(EVP_md5());
        ptr = fd->slices_md5sum;
        available = sizeof(fd->slices_md5sum);

        memset((void *)md5_digest, 0, md5_digest_len);
        EVP_DigestFinal_ex(fd->mdctx, md5_digest, &md5_digest_len);

        for (unsigned int i = 0; i < md5_digest_len; i++) {
            if (available < 2) break;
            int ret = snprintf(ptr, available, "%02X", md5_digest[i]);
            available -= ret;
            ptr += ret;
        }
        HR_LOGD("%s(%d): slice sum :%s\n", __FUNCTION__, __LINE__, fd->slices_md5sum);
    }

    OPENSSL_free(md5_digest);
    HR_LOGD("%s(%d): .....deallocate:%p -> %s...\n", __FUNCTION__, __LINE__, fd, fd->name);
    // prepare commit
    do_commit_upload(fd);

    HR_LOGD("%s(%d): .....deallocate:%p -> %s...\n", __FUNCTION__, __LINE__, fd, fd->name);
    // free any ...

    EVP_MD_CTX_free(fd->mdctx);
    EVP_MD_CTX_free(fd->slice_mdctx);
    free(fd->upload_id);
    fd->upload_id = NULL;

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
        return size;  //-EIO; // drop without error
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

    if (fd->error_code != 0) {
        return -1;
    }
    pthread_mutex_lock(&fd->mutex);
    if (fd->pending_length > TCLOUD_DRIVE_UPLOAD_PENDING_MAX) {
        HR_LOGD("%s(%d): reach max pending queue ........\n", __FUNCTION__, __LINE__);
#if 0
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 35;
        int rc = pthread_cond_timedwait(&fd->cond, &fd->mutex, &ts);
        if (rc != 0) {
            pthread_mutex_unlock(&fd->mutex);
            HR_LOGD("%s(%d): reach max pending queue timeout, return........\n", __FUNCTION__, __LINE__);
            return -EAGAIN;
        }
#endif
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
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    // struct tcloud_drive_upload_fd * fd = NULL;
    if (!self) return -1;
    // fd = TCLOUD_DRIVE_UPLOAD_FD(self);

    self->size = size;

    return 0;
}

int tcloud_drive_unlink(int64_t id, const char *name) {
    HR_LOGD("%s(%d): ........name:%s\n", __FUNCTION__, __LINE__, name);
    int rc = 0;

    char tmp[128] = {0};

    struct json_object *root = NULL, *task = NULL;

    root = json_object_new_array();
    task = json_object_new_object();
    json_object_array_add(root, task);

    snprintf(tmp, sizeof(tmp), "%ld", id);
    json_object_object_add(task, "fileId", json_object_new_string(tmp));
    // no need
    char *escape_name = curl_easy_escape(NULL, name, 0);
    json_object_object_add(task, "fileName", json_object_new_string(escape_name));
    curl_free(escape_name);
    json_object_object_add(task, "isFolder", json_object_new_int(0));

    rc = _tcloud_drive_batch_task("DELETE", 0, json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN), tmp, sizeof(tmp));

    json_object_put(root);

    int i = 0;
    while (i < 5) {
        int status = 0;

        usleep(1000 * 100);
        _tcloud_drive_wait_task("DELETE", tmp, &status);
        if (status == 2) {  // conflict
    HR_LOGD("%s(%d): delete maybe failed ....\n", __FUNCTION__, __LINE__);
            return -status;
        }
        if (status == 4) {  // complete
            return 0;
        }

        i++;
    }

    HR_LOGD("%s(%d): delete maybe failed ....\n", __FUNCTION__, __LINE__);
    HR_LOGD("%s(%d): ..maybe delete error......name:%s\n", __FUNCTION__, __LINE__, name);
    return rc;
}

static struct tcloud_drive_fd *_tcloud_drive_fd_allocate(enum tcloud_drive_fd_type type) {
    switch (type) {
        case TCLOUD_DRIVE_FD_DOWNLOAD: {
            struct tcloud_drive_download_fd *fd = (struct tcloud_drive_download_fd *)calloc(1, sizeof(struct tcloud_drive_download_fd));
            if (!fd) return NULL;
            TCLOUD_DRIVE_FD(fd)->type = type;
            return TCLOUD_DRIVE_FD(fd);
            break;
        }
        case TCLOUD_DRIVE_FD_UPLOAD: {
            struct tcloud_drive_upload_fd *fd = (struct tcloud_drive_upload_fd *)calloc(1, sizeof(struct tcloud_drive_upload_fd));
            if (!fd) return NULL;
            TCLOUD_DRIVE_FD(fd)->type = type;

            return TCLOUD_DRIVE_FD(fd);
            break;
        }
        default:
            return NULL;
    }
    return NULL;
}

static void _tcloud_drive_fd_deallocate(struct tcloud_drive_fd *fd) {
    if (!fd) return;

    switch (fd->type) {
        case TCLOUD_DRIVE_FD_DOWNLOAD: {
            break;
        }

        case TCLOUD_DRIVE_FD_UPLOAD: {
            struct tcloud_drive_upload_fd *_fd = TCLOUD_DRIVE_UPLOAD_FD(fd);
            HR_LOGD("%s(%d): .....deallocate:%p -> %s...\n", __FUNCTION__, __LINE__, _fd, _fd->name);
            free(_fd);

            break;
        }

        default:
            break;
    }
}

// type:
// task: json string
static int _tcloud_drive_batch_task(const char *type, int64_t target_dir, const char *taskinfo, char *id /*out*/, int len) {
    struct json_object *root = NULL, *res_code = NULL, *task_id = NULL;
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);

    const char *action = "/batch/createBatchTask.action";

    if (!type || !taskinfo || !id) return -1;
    tcloud_buffer_alloc(&b, 512);

    req->method = TR_METHOD_POST;
    req->set_form(req, "type", type);

    // 0 -> 同步盘, we never use it
    if (target_dir != 0) {
        char tmp[128] = {0};
        snprintf(tmp, sizeof(tmp), "%ld", target_dir);
        req->set_form(req, "targetFolderId", tmp);
    } else {
        req->set_form(req, "targetFolderId", "");
    }
    req->set_form(req, "taskInfos", taskinfo);

    json_object_put(root);

    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    req->post(req, API_URL "/batch/createBatchTask.action", &b);

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

    json_object_object_get_ex(root, "taskId", &task_id);
    HR_LOGD("%s(%d): task id:%s...\n", __FUNCTION__, __LINE__, json_object_get_string(task_id));
    snprintf(id, len, "%s", json_object_get_string(task_id));
    json_object_put(root);
    root = NULL;

    return 0;
}
static int _tcloud_drive_wait_task(const char *type, const char *id, int *status) {
    struct json_object *root = NULL, *res_code = NULL, *task_status = NULL;
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);

    const char *action = "/batch/checkBatchTask.action";

    if (!type || !id || !status) return -1;

    tcloud_buffer_alloc(&b, 512);

    req->method = TR_METHOD_POST;
    req->set_form(req, "type", type);
    req->set_form(req, "taskId", id);

    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    req->post(req, API_URL "/batch/checkBatchTask.action", &b);

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

    json_object_object_get_ex(root, "taskStatus", &task_status);
    *status = atoi(json_object_get_string(task_status));
    HR_LOGD("%s(%d): task status:%s...\n", __FUNCTION__, __LINE__, json_object_get_string(task_status));
    json_object_put(root);
    root = NULL;

    return 0;
}
static int _tcloud_drive_batch_task_timeout(const char *type, int64_t target_dir, const char *taskinfo, int timeout_ms) {
    struct json_object *root = NULL, *res_code = NULL, *task_id = NULL, *task_status = NULL;
    struct tcloud_buffer b;
    struct tcloud_request *req = _drive.request_pool->acquire(_drive.request_pool);
    char id[128] = {0};
    int i = 0;

    const char *action = "/batch/createBatchTask.action";

    if (!type || !taskinfo) return -1;
    tcloud_buffer_alloc(&b, 512);

    req->method = TR_METHOD_POST;
    req->set_form(req, "type", type);

    // 0 -> 同步盘, we never use it
    if (target_dir != 0) {
        char tmp[128] = {0};
        snprintf(tmp, sizeof(tmp), "%ld", target_dir);
        req->set_form(req, "targetFolderId", tmp);
    }
    req->set_form(req, "taskInfos", taskinfo);

    json_object_put(root);

    int ret = _tcloud_drive_fill_final(req, action, NULL);
    if (ret != 0) {
        tcloud_buffer_free(&b);
        _drive.request_pool->release(_drive.request_pool, req);
        return ret;
    }

    req->post(req, API_URL "/batch/createBatchTask.action", &b);

    printf("data:%s\n", b.data);
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        _drive.request_pool->release(_drive.request_pool, req);
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "res_code", &res_code);
    if (!res_code || json_object_get_int(res_code) != 0) {
        _drive.request_pool->release(_drive.request_pool, req);
        json_object_put(root);
        printf(" can not parse json .....\n");
        return -1;
    }

    json_object_object_get_ex(root, "taskId", &task_id);
    HR_LOGD("%s(%d): task id:%s...\n", __FUNCTION__, __LINE__, json_object_get_string(task_id));
    snprintf(id, sizeof(id), "%s", json_object_get_string(task_id));

    // release json immediately
    json_object_put(root);
    root = NULL;

    usleep(10 * 1000);
    i = 0;
    do {
        // check task
        req->method = TR_METHOD_POST;
        req->set_form(req, "type", type);
        req->set_form(req, "taskId", id);

        tcloud_buffer_reset(&b);
        ret = _tcloud_drive_fill_final(req, action, NULL);
        if (ret != 0) {
            tcloud_buffer_free(&b);
            _drive.request_pool->release(_drive.request_pool, req);
            return ret;
        }

        req->post(req, API_URL "/batch/checkBatchTask.action", &b);

        printf("data:%s\n", b.data);
        root = json_tokener_parse(b.data);
        tcloud_buffer_free(&b);
        if (!root) {
            _drive.request_pool->release(_drive.request_pool, req);
            printf(" can not parse json .....\n");
            return -1;
        }
        json_object_object_get_ex(root, "res_code", &res_code);
        if (!res_code || json_object_get_int(res_code) != 0) {
            _drive.request_pool->release(_drive.request_pool, req);
            json_object_put(root);
            printf(" can not parse json .....\n");
            return -1;
        }

        json_object_object_get_ex(root, "taskStatus", &task_status);
        int status = atoi(json_object_get_string(task_status));
        HR_LOGD("%s(%d): task status:%s...\n", __FUNCTION__, __LINE__, json_object_get_string(task_status));
        json_object_put(root);
        root = NULL;
        if (status == 4) {
            _drive.request_pool->release(_drive.request_pool, req);
            return 0;
        }
        if (status == 2 || status == 5 || status == 6) {
            _drive.request_pool->release(_drive.request_pool, req);
            return -status;
        }

        usleep(1000 * 100);
    } while (i++ < timeout_ms / 100);

    _drive.request_pool->release(_drive.request_pool, req);
    return 0;
}