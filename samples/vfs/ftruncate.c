#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/memfd.h>

int main()
{
	char filename[] = __FILE__ "_tmpfile_XXXXXX";
	int fd, size;
	size = getpagesize();
	fd = mkstemp(filename);
	if (ftruncate(fd, size)) {
		printf("error");
        return 1;
	}
    return 0;
}
