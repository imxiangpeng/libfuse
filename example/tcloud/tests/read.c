#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#define MAX_BUF 1024 * 1024 /**1024*/

int main(int argc, char** argv) {


    int fd = openat(AT_FDCWD, ".", O_RDONLY);
    
    if (fd == -1) {
        perror("openat failed");
        return 1;
    }
    
    printf("Successfully opened the current directory.\n");
    
    // 记得在使用后关闭文件描述符
    close(fd);

    char * b = malloc(MAX_BUF);
    printf("argv:%s\n", argv[1]);
    int fd = open(argv[1], O_CREAT| O_RDWR, 0755);
    if (fd < 0) {
        printf("can not open:%s\n", argv[1]);
        return -1;
    }


    size_t rs = read(fd, b, MAX_BUF);
    printf("read size :%ld\n", rs);

    free(b);

    return 0;
}
