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
//Referer", "https://cloud.189.cn/
const char* _user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

int main(int argc, char** argv) {

    struct tcloud_request *req;
    struct tcloud_buffer b;
    const char *login_url = "http://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https%3A%2F%2Fcloud.189.cn%2Fmain.action";
    // const char *listfiles_url = "https://cloud.189.cn/api/open/file/listFiles.action";
    const char *listfiles_url = "http://api.cloud.189.cn/listFiles.action";
    tcloud_buffer_alloc(&b, 2048);
#if 0

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