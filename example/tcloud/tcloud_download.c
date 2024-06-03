#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <unistd.h>
#include "hr_log.h"
#include "tcloud/tcloud_utils.h"
#include "tcloud_buffer.h"
#include "tcloud_request.h"

const char *_user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#define CHUNK_SIZE (16 * 1024)

static CURLM *multi = NULL;
static CURL *easy = NULL;

static size_t _data_receive(void *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    HR_LOGD("%s(%d): come in :%ld\n", __FUNCTION__, __LINE__, size * nmemb);
    struct tcloud_buffer *buf = (struct tcloud_buffer *)userdata;
    size_t total = size * nmemb;
    if (!ptr || !userdata)
        return total;  // drop all data

    tcloud_buffer_append(buf, ptr, total);
    return total;
}

int download(void) {
    int still_running = 0;
    int numfds;
    CURLMcode mc = curl_multi_wait(multi, NULL, 0, 1000, &numfds);

    printf("numfds:%d, mc:%d\n", numfds, mc);

    curl_multi_perform(multi, &still_running);
    //while(CURLM_CALL_MULTI_PERFORM ==
    //    curl_multi_perform(multi, &still_running));
    int msgq = 0;
struct CURLMsg *m = curl_multi_info_read(multi, &msgq);   
    printf("msg:%d\n", m ? m->msg: -1);
    return 0;
}

int main(int argc, char **argv) {
    struct tcloud_buffer b;
    const char *url = "http://10.30.11.78:8088/4k.ts";
    multi = curl_multi_init();
    easy = curl_easy_init();

    curl_multi_add_handle(multi, easy);
    tcloud_buffer_alloc(&b, CHUNK_SIZE);
    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, _data_receive);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, (void *)&b);
    curl_easy_setopt(easy, CURLOPT_BUFFERSIZE, CHUNK_SIZE);


    while (1) {
        download();

        usleep(50);
    }

    curl_multi_remove_handle(multi, easy);
    curl_easy_cleanup(easy);

    curl_multi_cleanup(multi);
    return 0;
}
