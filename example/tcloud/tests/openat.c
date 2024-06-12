#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#define MAX_BUF 1024 * 1024 /**1024*/

int main(int argc, char** argv) {
    // int fd = openat(AT_FDCWD, ".", O_RDONLY);
    int fd = openat(AT_FDCWD, ".", O_RDONLY);
    
    if (fd == -1) {
        perror("openat failed");
        return 1;
    }
    
    printf("Successfully opened the current directory. -> %d\n", fd);
    
    int ff = openat(fd, "openat.txt", O_CREAT | O_RDWR, 0755);
    printf("ff:%d\n",ff);
    close(ff);
    // 记得在使用后关闭文件描述符
    close(fd);
    return 0;
}
