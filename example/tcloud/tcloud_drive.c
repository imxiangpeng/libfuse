#include <errno.h>
#include <string.h>
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stddef.h>
#include <stdio.h>

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

static void *tcloud_drive_init(struct fuse_conn_info *conn,
                               struct fuse_config *cfg) {

  (void)conn;
  (void)cfg;

  printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    return NULL;
}

static int tcloud_drive_getattr(const char *path, struct stat *stbuf,
                                struct fuse_file_info *fi) {
  printf("%s(%d): path:%s\n", __FUNCTION__, __LINE__, path);

  if (0 == strcmp("/", path)) {
  stbuf->st_mode = S_IFDIR;
  stbuf->st_nlink = 1;
        return 0;
  }
  if (0 == strcmp("/xxx.txt", path)) {
    stbuf->st_mode = S_IFREG;
    return 0;
  }
  return -ENOENT;
}

static int tcloud_drive_access(const char *path, int mask) {
  printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
  return 0;
}

static int tcloud_drive_opendir(const char *path, struct fuse_file_info *fi) {
  printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
  return 0;
}

static int tcloud_drive_readdir(const char *path, void *dbuf,
                                fuse_fill_dir_t filler, off_t offset,
                                struct fuse_file_info *fi,
                                enum fuse_readdir_flags flags) {
  printf("%s(%d): ........\n", __FUNCTION__, __LINE__);

  filler(dbuf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
  filler(dbuf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
  filler(dbuf, "xxx.txt", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
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