#ifndef J2SOBJECT_CLOUD_H
#define J2SOBJECT_CLOUD_H

#include "j2sobject.h"

// telecom_cloud_ -> j2scloud
typedef struct j2scloud_folder {
    J2SOBJECT_DECLARE_OBJECT;
    int64_t id; // int64_t
    char *name;
    char *createDate;
    char *lastOpTime;
    // double rev; // int64_t
    char *rev; // int64_t
    int64_t parentId; // int64_t

} j2scloud_folder_t;

typedef struct j2scloud_icon {
    J2SOBJECT_DECLARE_OBJECT;
    char *smallUrl;
    char *mediumUrl;
    char *largeUrl;
    char *max600;
} j2scloud_icon_t;

typedef struct j2scloud_file {
    J2SOBJECT_DECLARE_OBJECT;
    int64_t id; // int64_t
    char *name;
    char *createDate;
    char *lastOpTime;
    // double rev; // int64_t 
    char *rev; // int64_t 
    int64_t parentId; // int64_t
    int64_t size; // int64_t
    char md5[32 + 4];
    int mediaType;
    int orientation;
    // ignore media attr list
    // mediaAttrList*;

    // icon
    j2scloud_icon_t *icon;

} j2scloud_file_t;


// fileListAO
typedef struct j2scloud_folder_resp {
    J2SOBJECT_DECLARE_OBJECT;
    int count;
    int fileListSize;
    j2scloud_folder_t *folderList;
    j2scloud_file_t *fileList;
    int64_t lastRev;
} j2scloud_folder_resp_t;

extern struct j2sobject_prototype j2scloud_folder_prototype;
extern struct j2sobject_prototype j2scloud_file_prototype;
extern struct j2sobject_prototype j2scloud_folder_resp_prototype;
#endif // J2SOBJECT_CLOUD_H
