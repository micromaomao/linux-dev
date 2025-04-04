#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdbool.h>

int main(int argc, char const *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    while (true) {
        char buf[4096];
        ssize_t bytes_read = read(fd, buf, sizeof(buf)-1);
        if (bytes_read < 0) {
            perror("read");
            return 1;
        }
        buf[bytes_read] = '\0';
        printf("Read %zd bytes: %s\n", bytes_read, buf);
        printf("Press Enter to read again or Ctrl+C to exit...\n");
        while (getchar() != '\n') {}
        lseek(fd, 0, SEEK_SET);
    }
    return 0;
}
