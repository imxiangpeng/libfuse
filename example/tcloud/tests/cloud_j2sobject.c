#include <stdio.h>

#include "j2sobject_cloud.h"


int main(int argc, char **argv) {
    struct j2scloud_folder_resp *object = (struct j2scloud_folder_resp *)j2sobject_create(&j2scloud_folder_resp_prototype);

    int ret = j2sobject_deserialize_target_file(J2SOBJECT(object), "filelists.json", "fileListAO");

    printf("ret:%d\n", ret);

    printf("count:%d\n", object->count);
    printf("file list size:%d\n", object->fileListSize);
#if 1
    j2scloud_folder_t *t = NULL;

    printf("folder list:%p\n", object->folderList);
    for (t = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next; t != (j2scloud_folder_t *)J2SOBJECT(object->folderList); t = (j2scloud_folder_t *)J2SOBJECT(t)->next) {
        printf("folder id:%ld\n", (long)t->id);
        printf("folder name:%s\n", t->name);
        printf("folder create date:%s\n", t->createDate);
        printf("folder last access date:%s\n", t->lastOpTime);
        printf("folder rev:%s\n", t->rev);
        printf("folder parent id:%ld\n", (long)t->parentId);
    }

    j2scloud_file_t *f = NULL;
    for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next; f != (j2scloud_file_t *)J2SOBJECT(object->fileList); f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
        printf("file id:%ld\n", (long)f->id);
        printf("file name:%s\n", f->name);
        printf("file create date:%s\n", f->createDate);
        printf("file last access date:%s\n", f->lastOpTime);
        printf("file rev:%s\n", f->rev);
        printf("file parent id:%ld\n", (long)f->parentId);
        printf("file size:%ld\n", (long)f->size);
        printf("file md5:%s\n", f->md5);
        printf("file mediatype:%d\n", f->mediaType);
        printf("file orientation:%d\n", f->orientation);

        if (f->icon) {

        printf("file small url:%s\n", f->icon->smallUrl);
        if (f->icon->mediumUrl)
            printf("file medium url:%s\n", f->icon->mediumUrl);
        printf("file large url:%s\n", f->icon->largeUrl);
        }
    }
#endif
    printf("try release .......\n");
    j2sobject_free(J2SOBJECT(object));
    return 0;
}
