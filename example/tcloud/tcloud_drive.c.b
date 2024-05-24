#include <stdlib.h>
#include <time.h>
#define FUSE_USE_VERSION 31

#include <errno.h>
#include <string.h>

#include <fuse.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include "j2sobject_cloud.h"

static struct options {
  const char *filename;
  const char *contents;
  int show_help;
} options;

#define OPTION(t, p)                                                           \
  { t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
    OPTION("--name=%s", filename), OPTION("--contents=%s", contents),
    OPTION("-h", show_help), OPTION("--help", show_help), FUSE_OPT_END};

struct j2scloud_folder_resp *root_dir = NULL;

int timespec_from_date_string(struct timespec *ts, const char* date) {
  struct tm tm_time;

  if (!ts || !date) return -1;

    memset(&tm_time, 0, sizeof(struct tm));

    if (strptime(date, "%Y-%m-%d %H:%M:%S", &tm_time) == NULL) {
        fprintf(stderr, "Failed to parse time string\n");
        return 1;
    }

    time_t time_epoch = mktime(&tm_time);
    if (time_epoch == -1) {
        fprintf(stderr, "Failed to convert to time_t\n");
        return 1;
    }

    ts->tv_sec = time_epoch;
    ts->tv_nsec = 0;

    // 打印结果
    printf("Time: %ld seconds, %ld nanoseconds\n", ts->tv_sec, ts->tv_nsec); 
  return 0;
}

static void *tcloud_drive_init(struct fuse_conn_info *conn,
                               struct fuse_config *cfg) {

  (void)conn;
  (void)cfg;

  if (!root_dir) {
    root_dir = (struct j2scloud_folder_resp *)j2sobject_create(
        &j2scloud_folder_resp_prototype);
    int ret = j2sobject_deserialize_target_file(
        J2SOBJECT(root_dir),
        "/home/alex/workspace/workspace/libfuse/libfuse/build/filelists.json",
        "fileListAO");
  }
  return NULL;
}

static int tcloud_drive_getattr(const char *path, struct stat *stbuf,
                                struct fuse_file_info *fi) {
  printf("%s(%d): path:%s fi:%p\n", __FUNCTION__, __LINE__, path, fi);

  if (0 == strcmp("/", path)) {
    stbuf->st_mode = S_IFDIR;
    stbuf->st_nlink = 1;
    return 0;
  }
  if (0 == strcmp("/xxx.txt", path)) {
    stbuf->st_mode = S_IFREG;
    return 0;
  }

  const char *n = path + 1; // skip '/'
  n = path + 1;

  struct j2scloud_folder_resp *object = root_dir;
  j2scloud_folder_t *t = NULL;

  for (t = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
       t != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
       t = (j2scloud_folder_t *)J2SOBJECT(t)->next) {
    if (strcmp(n, t->name) == 0) {
      printf("folder id:%ld\n", (long)t->id);
      printf("folder name:%s\n", t->name);
      printf("folder create date:%s\n", t->createDate);
      printf("folder last access date:%s\n", t->lastOpTime);
      printf("folder rev:%s\n", t->rev);
      printf("folder parent id:%ld\n", (long)t->parentId);

      stbuf->st_mode = S_IFDIR;

      timespec_from_date_string(&stbuf->st_atim, t->lastOpTime);
      timespec_from_date_string(&stbuf->st_mtim, t->lastOpTime);
      
      stbuf->st_nlink = 12;
      return 0;
    }
  }

  j2scloud_file_t *f = NULL;
  for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next;
       f != (j2scloud_file_t *)J2SOBJECT(object->fileList);
       f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
    if (strcmp(n, f->name) == 0) {
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

      stbuf->st_mode = S_IFREG;
      stbuf->st_size = (long)f->size;
      timespec_from_date_string(&stbuf->st_ctim, f->createDate);
      timespec_from_date_string(&stbuf->st_atim, f->lastOpTime);
      timespec_from_date_string(&stbuf->st_mtim, f->lastOpTime);
      return 0;
    }
  }

  printf("%s(%d): .......\n", __FUNCTION__, __LINE__);

// force think as reguler files
        stbuf->st_mode = S_IFREG;
  stbuf->st_size = 1024;

        return 0;
  return -ENOENT;
}

static int tcloud_drive_access(const char *path, int mask) {
  printf("%s(%d): ........path:%s\n", __FUNCTION__, __LINE__, path);
  return 0;
}

static int tcloud_drive_opendir(const char *path, struct fuse_file_info *fi) {
  printf("%s(%d): .......path:%s\n", __FUNCTION__, __LINE__, path);

  fi->fh = (unsigned long)root_dir;
  return 0;
}

static int tcloud_drive_readdir(const char *path, void *dbuf,
                                fuse_fill_dir_t filler, off_t offset,
                                struct fuse_file_info *fi,
                                enum fuse_readdir_flags flags) {
  printf("%s(%d): ........path:%s\n", __FUNCTION__, __LINE__, path);

  if (0 == strcmp(path, "/")) {

    filler(dbuf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    filler(dbuf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    struct j2scloud_folder_resp *object = root_dir;
    j2scloud_folder_t *t = NULL;

    for (t = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
         t != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
         t = (j2scloud_folder_t *)J2SOBJECT(t)->next) {
      filler(dbuf, t->name, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
      printf("folder id:%ld\n", (long)t->id);
      printf("folder name:%s\n", t->name);
      printf("folder create date:%s\n", t->createDate);
      printf("folder last access date:%s\n", t->lastOpTime);
      printf("folder rev:%s\n", t->rev);
      printf("folder parent id:%ld\n", (long)t->parentId);
    }

    j2scloud_file_t *f = NULL;
    for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next;
         f != (j2scloud_file_t *)J2SOBJECT(object->fileList);
         f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
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

      filler(dbuf, f->name, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    }
    // j2sobject_free(J2SOBJECT(object));
    return 0;
  }
  
  const char *p = path + 1; // skip '/'
  const char *n = strchr(path + 1, '/'); // skip '/'
  do {
    char *sub = (char *)calloc(1, (n ? (n - p) : strlen(p)) + 1);
    memcpy(sub, p, n ? (n - p) : strlen(p));
    printf("sub:%s, n:%s, p:%s\n", sub, n ? n: "", p);
    
    struct j2scloud_folder_resp *object = root_dir;
    j2scloud_folder_t *t = NULL;

    for (t = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
         t != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
         t = (j2scloud_folder_t *)J2SOBJECT(t)->next) {
      filler(dbuf, "1", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
      filler(dbuf, "2", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
      filler(dbuf, "3", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
      filler(dbuf, "4", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    }



    p = n;
    if (n != NULL) {
    n = strchr(n+1, '/');

    }


    free(sub);
  } while (p != NULL);

  return 0;
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
static struct fuse_operations tcloud_drive_ops = {
    .init = tcloud_drive_init,
    .getattr = tcloud_drive_getattr,
    .access = tcloud_drive_access,
    .opendir = tcloud_drive_opendir,
    .readdir = tcloud_drive_readdir,
    .releasedir = tcloud_drive_releasedir,
    .mkdir = tcloud_drive_mkdir,
    .rmdir = tcloud_drive_rmdir,
    .rename = tcloud_drive_rename,
    .truncate = tcloud_drive_truncate,
    .utimens = tcloud_drive_utimens,
    .open = tcloud_drive_open,
    .release = tcloud_drive_release,
    .read = tcloud_drive_read,
    .write = tcloud_drive_write,
    .statfs = tcloud_drive_statfs,
    .create = tcloud_drive_create,
};

int main(int argc, char *argv[]) {
  int ret = 0;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  /* Parse options */
  if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
    return 1;

  ret = fuse_main(args.argc, args.argv, &tcloud_drive_ops, NULL);
  fuse_opt_free_args(&args);

  if (ret != 0) {
    //
  }

  return 0;
}