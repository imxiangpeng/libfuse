#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include "tcloud/tcloud_utils.h"
#include "tcloud_buffer.h"
#include "tcloud_request.h"

#ifndef UUID_STR_LEN
#define UUID_STR_LEN (37)
#endif
// Accept:application/json;charset=UTF-8
// Browser-Id: c2f7ebcc42acb3131efe073d69a5e300
// Cookie: apm_key=442B469E314C60BD7E94B8D38B2508E9; apm_uid=0F310A9138C4597D24E634AF0CB5DDFB; apm_ct=20240514104347000; apm_ua=B78B4E2D6C0A362C418B145FE44ED73F; share_nQvYv2yAziAn=kxs6; JSESSIONID=5C208DC8A10740C705AE73EAB0272742; COOKIE_LOGIN_USER=B014F9CB2D276A39763062D8A477559D9CA83742046BDCCCB3BDF4099D3F93ED407C1C45D016201EAEF753F71A0761AD38667D2EA5542102
// path: /api/open/file/createFolder.action?noCache=0.2920529085627337
// https://cloud.189.cn/api/open/file/createFolder.action?noCache=0.2920529085627337
// Referer", "https://cloud.189.cn/
const char *_user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

int login(void) {
    struct tcloud_request *req;
    struct tcloud_buffer b;
    const char *login_url = "http://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https%3A%2F%2Fcloud.189.cn%2Fmain.action";
    // const char *listfiles_url = "https://cloud.189.cn/api/open/file/listFiles.action";
    const char *listfiles_url = "http://api.cloud.189.cn/listFiles.action";
    tcloud_buffer_alloc(&b, 2048);
#if 1

    req = tcloud_request_new(T_REQ_GET, login_url);

    req->set_query(req, "id", "-11");
    req->set_form(req, "id", "-11");
    req->set_header(req, "Referer", "https://cloud.189.cn");
    // req->allow_redirect(req, 0);

    req->request(req, NULL /*&b*/, NULL);

    printf("data:%s\n", b.data);

    tcloud_request_free(req);
#endif
    printf("%s(%d): ....................\n", __FUNCTION__, __LINE__);

    // req = tcloud_request_new(T_REQ_GET, listfiles_url);
    req = tcloud_request_new(T_REQ_POST, listfiles_url);
    req->set_query(req, "folderId", "-11");
    req->set_query(req, "pageSize", "100");
    req->set_query(req, "pageNum", "1");
    req->set_query(req, "mediaType", "0");
    req->set_query(req, "iconOption", "5");
    req->set_query(req, "orderBy", "lastOpTime");
    req->set_query(req, "descending", "true");
    req->set_query(req, "clientType", "TELEPC");
    req->set_query(req, "version", "6.2");
    req->set_query(req, "channelI", "web_cloud.189.cn");
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%d_%d", rand(), rand());
    req->set_query(req, "rand", tmp);
    char *params = NULL;
    char date[256] = {0};
    const char *secret = "FA3387A62BE630E89D18ABBCD4AF662E";
    const char *session = "0bdc1b48-b764-478d-8984-c1faccd99a78";
    char uuid[UUID_STR_LEN] = {0};
    char *signature = NULL;

    if (params) {
        req->set_query(req, "params", params);
    }

    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    req->set_header(req, "Cookie", "apm_key=442B469E314C60BD7E94B8D38B2508E9; apm_uid=0F310A9138C4597D24E634AF0CB5DDFB; apm_ct=20240514104347000; apm_ua=B78B4E2D6C0A362C418B145FE44ED73F; JSESSIONID=77EF1BD4222AFF30027DC3CB0130806D; COOKIE_LOGIN_USER=1E8C73CA11130323563DF55CDD6544FD0F7070F473458CA876DAE4EBCCE98E6608E62F57F309D43511A71452B9F82429611D1D3C0B4812AE");
    tcloud_utils_generate_uuid(uuid, sizeof(uuid));
    tcloud_utils_http_date_string(date, sizeof(date));

    char *signature_data = NULL;
    // asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "GET", "/api/open/file/listFiles.action", date);
    // asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "GET", "/listFiles.action", date);
    asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "POST", "/listFiles.action", date);
    signature = tcloud_utils_hmac_sha1(secret, (const unsigned char *)signature_data, strlen(signature_data));
    printf("sig data:%s\n", signature_data);
    free(signature_data);
    printf("signature:%s\n", signature);
    req->set_header(req, "Date", date);
    req->set_header(req, "SessionKey", session);
    req->set_header(req, "X-Request-ID", uuid);
    req->set_header(req, "Signature", signature);
    req->set_header(req, "Referer", "https://cloud.189.cn");

    tcloud_buffer_reset(&b);
    req->request(req, &b, NULL);

    free(signature);
    printf("data:%s\n", b.data);
    tcloud_request_free(req);
    tcloud_buffer_free(&b);
    return 0;
}
#if 0
int create_file() {
    
    struct tcloud_request *req;
    struct tcloud_buffer b;
    req = tcloud_request_new(T_REQ_POST, listfiles_url);
    req->set_query(req, "folderId", "-11");
    req->set_query(req, "pageSize", "100");
    req->set_query(req, "pageNum", "1");
    req->set_query(req, "mediaType", "0");
    req->set_query(req, "iconOption", "5");
    req->set_query(req, "orderBy", "lastOpTime");
    req->set_query(req, "descending", "true");
    req->set_query(req, "clientType", "TELEPC");
    req->set_query(req, "version", "6.2");
    req->set_query(req, "channelI", "web_cloud.189.cn");
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%d_%d", rand(), rand());
    req->set_query(req, "rand", tmp);
    char *params = NULL;    
    char date[256] = {0};
    const char *secret = "FA3387A62BE630E89D18ABBCD4AF662E";
    const char* session = "0bdc1b48-b764-478d-8984-c1faccd99a78";
    char uuid[UUID_STR_LEN]  = {0};
    char *signature = NULL;

    if (params) {
        req->set_query(req, "params", params);
    }
    
    req->set_header(req, "Accept" , "application/json;charset=UTF-8");
    req->set_header(req, "Cookie", "apm_key=442B469E314C60BD7E94B8D38B2508E9; apm_uid=0F310A9138C4597D24E634AF0CB5DDFB; apm_ct=20240514104347000; apm_ua=B78B4E2D6C0A362C418B145FE44ED73F; JSESSIONID=77EF1BD4222AFF30027DC3CB0130806D; COOKIE_LOGIN_USER=1E8C73CA11130323563DF55CDD6544FD0F7070F473458CA876DAE4EBCCE98E6608E62F57F309D43511A71452B9F82429611D1D3C0B4812AE");
    tcloud_utils_generate_uuid(uuid, sizeof(uuid));
    tcloud_utils_http_date_string(date, sizeof(date));
    
    char *signature_data = NULL;
    // asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "GET", "/api/open/file/listFiles.action", date);
    // asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "GET", "/listFiles.action", date);
    asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "POST", "/listFiles.action", date);
    signature = tcloud_utils_hmac_sha1(secret, signature_data, strlen(signature_data));
    printf("sig data:%s\n", signature_data);
    free(signature_data);
    printf("signature:%s\n", signature);
    req->set_header(req, "Date", date);
    req->set_header(req, "SessionKey", session);
    req->set_header(req, "X-Request-ID", uuid);
    req->set_header(req, "Signature", signature);
    req->set_header(req, "Referer", "https://cloud.189.cn");

    tcloud_buffer_reset(&b);
    req->request(req, &b, NULL);
    
    free(signature);
    printf("data:%s\n", b.data);
    tcloud_request_free(req);
    tcloud_buffer_free(&b);
    return 0;
}
#endif

char *hex_to_string(const char *data, size_t len) {
    int size = 0;
    size_t offset = 0;
    char *ptr = NULL;
    if (!data) return NULL;

    size = len * 2 + 1;

    ptr = (unsigned char *)calloc(1, size);
    if (!ptr) return NULL;

    for (int i = 0; i < len; i++) {
        int rc = snprintf(ptr + offset, size - offset, "%02x", data[i] & 0xFF);
        offset += rc;
    }

    return ptr;
}
int web_initmulti() {
    const char *secret = "FA3387A62BE630E89D18ABBCD4AF662E";
    const char *session_key = "6c0a98e4-c9c1-4732-9fda-a4ca658ee510";//"6c0a98e4-c9c1-4732-9fda-a4ca658ee510";  //"0bdc1b48-b764-478d-8984-c1faccd99a78";//"6c0a98e4-c9c1-4732-9fda-a4ca658ee510";
    time_t date = time(NULL) * 1000;//1717119472517;
    const char *rsa_pkid = "36fac50fee614589897163504404b389";//"99c53d1ec92e44308e453691db49e312";
//    const char *pub = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZ/Ix82QPOfbc0VzDGqx8ez2SmKceu4ZznQcTXtyuXXWjOB6ehcP8rE0MKUponNmg4sRJIoUfrQcUgiItInCvA1wxgFSq843ojuvMef8udXWA1HH8D8dM87qilYe0TrLUeXgsZbaMJENMdVtxRtqDPykaAhe/DuCGujPlG/t1/BQIDAQAB\n-----END PUBLIC KEY-----";
    const char *pub = "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNqLC6L43z3Oy8jdxDke8vrpR/90/3UIq62iyJLyOn/APMXpRSwDyWbO8jdd+aaDVhG5ogpsz8iS6ppKEGRJupltd3RVBKATQJehgRiU4fZdH3wJWSqEuDDsvUMQpfdmJfS42CwLpd7fzrKLo/CDUSF8P2FD1V1CPEOcr0oK48iwIDAQAB"
    "\n-----END PUBLIC KEY-----";
    const char *pre_aes_key = "90aefc29c67042408e2";//"0f1e9f36d2c9451eb4846";
    struct tcloud_request *req;
    struct tcloud_buffer b;
    // req = tcloud_request_new(T_REQ_POST, listfiles_url)   ;

    /*  "parentFolderId=225281133668609798",
        "fileName=WIFI%E5%90%9E%E5%90%90%E9%87%8FFAQ.docx",
        "fileSize=52250",
        "sliceSize=10485760",
        "fileMd5=928095757f98dc7cce23ce4527f332a5",
        "sliceMd5=928095757f98dc7cce23ce4527f332a5"       */

    tcloud_buffer_alloc(&b, 2048);
    // tcloud_buffer_append_string(&b, "parentFolderId=225281133668609798");
    tcloud_buffer_append_string(&b, "parentFolderId=325031136449786738");
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "fileName=WIFI%E5%90%9E%E5%90%90%E9%87%8FFAQ.docx");
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "fileSize=52250");
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "sliceSize=10485760");
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "fileMd5=928095757f98dc7cce23ce4527f332a5");
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "sliceMd5=928095757f98dc7cce23ce4527f332a5");
    // "parentFolderId=225281133668609798&fileName=WIFI%E5%90%9E%E5%90%90%E9%87%8FFAQ.docx&fileSize=52250&sliceSize=10485760&fileMd5=928095757f98dc7cce23ce4527f332a5&sliceMd5=928095757f98dc7cce23ce4527f332a5"

    printf("now join with:&:%s\n", b.data);
    char *p = "parentFolderId=225281133668609798&fileName=WIFI%E5%90%9E%E5%90%90%E9%87%8FFAQ.docx&fileSize=52250&sliceSize=10485760&fileMd5=928095757f98dc7cce23ce4527f332a5&sliceMd5=928095757f98dc7cce23ce4527f332a5";
    printf("verify:%d\n", !strcmp(b.data, p));

    // aes string -> bytes
    /*parse: function(t) {
    for (var e = t.length, n = [], r = 0; r < e; r++)
        n[r >>> 2] |= (255 & t.charCodeAt(r)) << 24 - r % 4 * 8;
    return new l.init(n,e)
    }*/

    // for (size_t r = 0; r < len; ++r) {
    //    data[r >> 2] |= ((unsigned char)t[r]) << (24 - r % 4 * 8); // 构建字节序列
    //}

    printf("'3':%d\n", '3');
    int val = (255 & '3') << 24 - 4 % 4 * 8;
    printf("val:%d\n", val);

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
    int len = MIN(strlen(pre_aes_key), 16);
    int aes_bytes[4] = {0};
    for (int i = 0; i < len; i++) {
        aes_bytes[i >> 2] |= ((unsigned char)pre_aes_key[i]) << (24 - i % 4 * 8);
    }

    printf("%u %u %u %u\n", aes_bytes[0], aes_bytes[1], aes_bytes[2], aes_bytes[3]);

    char keys[16] = {0};

    for (int i = 0; i < sizeof(aes_bytes); i++) {
        keys[4 * i + 3] = (char)(aes_bytes[i] & 0xFF);
        keys[4 * i + 2] = (char)((aes_bytes[i] >> 8) & 0xFF);
        keys[4 * i + 1] = (char)((aes_bytes[i] >> 16) & 0xFF);
        keys[4 * i + 0] = (char)((aes_bytes[i] >> 24) & 0xFF);
    }
    // char *c = (char *)&aes_bytes;

    for (int i = 0; i < 16; i++) {
        printf("0x%x\n", keys[i]);
    }
    printf("\n");

    // using aes bytes key to sign previous parameter
    struct tcloud_buffer r;
    tcloud_buffer_alloc(&r, 512);
    // asprintf(&k, "%u%u%u%u", aes_bytes[0], aes_bytes[1], aes_bytes[2], aes_bytes[3]);
    unsigned char key[16] = {
        0x30, 0x66, 0x31, 0x65,  // 812003685
        0x39, 0x66, 0x33, 0x36,  // 962999094
        0x64, 0x32, 0x63, 0x39,  // 1681023801
        0x34, 0x35, 0x31, 0x65   // 875901285
    };
    tcloud_utils_aes_ecb_data(keys, b.data, b.offset, &r);

    // equal with web api?
    // result should be: a4802c5356c941bdfd10924f06807d08483617a7de852c24cd9d3e58434555758c33574ad14e444845c9de7045f928c5889d38ca3d5ea0485723f84f575f16f6f28e9e406c275e9b92f4c1e1989fd1f9f56d10b20a9a8044b66a496a2ef374020da6d3eebc492cd434a8efd0e402d042a51b53c93748893f450da4355165d8dc6fb1e1c3dd0c9b133160d78c59ee3396fd9275bd23c64b9a28172c8a200ddc6fbc91e7c223b331a839b1b4bf48c7e678ce3933d91d5f0988be85e58cc5c52b33c8f039fe3f687adb4bc0cfaf3d0ec97e
    for (int i = 0; i < r.offset; i++) {
        printf("%02x", (unsigned char)r.data[i] /*& 0xFF*/);
    }

    printf("\n");

    char *params = hex_to_string(r.data, r.offset);
    tcloud_buffer_free(&r);
    printf("now ptr:%s\n", params);

    // const char* initmultiupload = "https://upload.cloud.189.cn/person/initMultiUpload";
    const char *initmultiupload = "http://upload.cloud.189.cn/person/initMultiUpload";
    req = tcloud_request_new(T_REQ_GET, initmultiupload);
    req->set_query(req, "params", params);
    // free(params);

    char uuid[UUID_STR_LEN] = {0};
    char *signature = NULL;
    // char date[256] = {0};

    tcloud_utils_generate_uuid(uuid, sizeof(uuid));
    // tcloud_utils_http_date_string(date, sizeof(date));

    char *signature_data = NULL;
    // asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "GET", "/api/open/file/listFiles.action", date);
    // asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session, "GET", "/listFiles.action", date);
    asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%ld&params=%s", session_key, "GET", "/person/initMultiUpload", date, params);
    signature = tcloud_utils_hmac_sha1(pre_aes_key /* secret*/, (const unsigned char *)signature_data, strlen(signature_data));
    printf("sig data:%s\n", signature_data);
    free(signature_data);
    printf("signature:%s\n", signature);
    // req->set_header(req, "Date", date)

    char tmp[128] = {0};
    snprintf(tmp, sizeof(tmp), "%ld", date);
    req->set_header(req, "SessionKey", session_key);
    req->set_header(req, "X-Request-ID", uuid);
    req->set_header(req, "X-Request-Date", tmp);
    req->set_header(req, "Signature", signature);
    req->set_header(req, "PkId", rsa_pkid);

    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    req->set_header(req, "Cookie", "apm_key=442B469E314C60BD7E94B8D38B2508E9; apm_uid=0F310A9138C4597D24E634AF0CB5DDFB; apm_ct=20240514104347000; apm_ua=B78B4E2D6C0A362C418B145FE44ED73F; JSESSIONID=77EF1BD4222AFF30027DC3CB0130806D; COOKIE_LOGIN_USER=1E8C73CA11130323563DF55CDD6544FD0F7070F473458CA876DAE4EBCCE98E6608E62F57F309D43511A71452B9F82429611D1D3C0B4812AE");

    

    size_t rsa_len = sizeof(tmp);

    int rc = tcloud_utils_rsa_encrypt(pub, pre_aes_key, strlen(pre_aes_key), tmp, &rsa_len);
    printf("rc:%d\n", rc);
    
    printf("encryption text:%s\n", tmp);

    char *encryption_text = hex_to_string(tmp, rsa_len);
    printf("encryption text:%s\n", encryption_text);
    req->set_header(req, "EncryptionText", encryption_text);
    
    tcloud_buffer_reset(&b);
    req->request(req, &b, NULL);

    free(signature);
    printf("data:%s\n", b.data);
    tcloud_request_free(req);
    tcloud_buffer_free(&b);

    return 0;
}

int main(int argc, char **argv) {
    web_initmulti();

    return 0;
}
