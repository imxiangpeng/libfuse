#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#define MAX_BUF 1024 * 1024 /**1024*/

int main(int argc, char** argv) {
    char * b = malloc(MAX_BUF);
    printf("argv:%s\n", argv[1]);
    int fd = open(argv[1], O_CREAT| O_RDWR, 0755);
    if (fd < 0) {
        printf("can not open:%s\n", argv[1]);
        return -1;
    }


    while (1) {
    ssize_t rs = write(fd, b, MAX_BUF);
    printf("read size :%ld\n", rs);
        if (rs <= 0) {
            break;
        }

    }

    free(b);

    return 0;
}
