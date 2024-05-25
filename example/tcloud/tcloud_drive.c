#include <stdlib.h>
#include <time.h>

#include <errno.h>
#include <string.h>

#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include "j2sobject_cloud.h"

static int tcloud_drive_getattr(const char *path, struct stat *stbuf,
                                struct fuse_file_info *fi) {
  printf("%s(%d): path:%s fi:%p\n", __FUNCTION__, __LINE__, path, fi);


  return -ENOENT;
}

static int tcloud_drive_access(const char *path, int mask) {
  printf("%s(%d): ........path:%s\n", __FUNCTION__, __LINE__, path);
  return 0;
}

int tcloud_drive_opendir(int32_t id, struct j2scloud_folder_resp **dir) {
  printf("%s(%d): .......folder id:%d\n", __FUNCTION__, __LINE__, id);
  *dir = (struct j2scloud_folder_resp *)j2sobject_create(&j2scloud_folder_resp_prototype);
  return 0;
}

int tcloud_drive_readdir(int32_t id, struct j2scloud_folder_resp * dir) {
  char *path = NULL;


  asprintf(&path, "/workspace/workspace/libfuse/libfuse/build/filelists-%d.json", id);
  
  printf("folder :%d --> %s\n", id, path);
  
  
    int ret = j2sobject_deserialize_target_file(        J2SOBJECT(dir),        path,        "fileListAO");
  
  free(path);


  return ret;
}

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

static int tcloud_drive_open(const char *path, struct fuse_file_info *fi) {
  printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
  return 0;
}
static int tcloud_drive_release(const char *path, struct fuse_file_info *fi) {
  printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
  return 0;
}

static int tcloud_drive_read(const char *path, char *rbuf, size_t size,
                             off_t offset, struct fuse_file_info *fi) {
  printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
  return 0;
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
