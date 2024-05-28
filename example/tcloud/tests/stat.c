#include <stdio.h>
       #include <sys/types.h>
       #include <sys/stat.h>
       #include <unistd.h>


int main(int argc, char** argv) {
    const char* path = "/home/alex/workspace/workspace/libfuse/libfuse/build/example/dst";
	struct stat statbuf;
	int ret = stat(path, &statbuf);
    printf("stat:%d\n", ret);
	if (ret == 0) {
		/* we always want directories to appear zero size */
		if (S_ISDIR(statbuf.st_mode)) {
			statbuf.st_size = 0;
		}

    }
    return 0;
}

