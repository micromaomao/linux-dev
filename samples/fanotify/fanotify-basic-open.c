#define _GNU_SOURCE /* Needed to get O_LARGEFILE definition */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>

/* Read all available fanotify events from the file descriptor 'fd'. */

static void handle_events(int fd)
{
	const struct fanotify_event_metadata *metadata;
	struct fanotify_event_metadata buf[200];
	ssize_t size;
	char path[PATH_MAX];
	ssize_t path_len;
	char procfd_path[PATH_MAX];
	struct fanotify_response response;

	for (;;) {
		size = read(fd, buf, sizeof(buf));
		if (size == -1 && errno != EAGAIN) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		/* Check if end of available data reached. */

		if (size <= 0)
			break;

		/* Point to the first event in the buffer. */

		metadata = buf;

		/* Loop over all events in the buffer. */

		while (FAN_EVENT_OK(metadata, size)) {
			if (metadata->fd >= 0) {
				if (metadata->mask & FAN_OPEN) {
					printf("FAN_OPEN: ");
				}

				/* Retrieve and print pathname of the accessed file. */

				snprintf(procfd_path, sizeof(procfd_path),
					 "/proc/self/fd/%d", metadata->fd);
				path_len = readlink(procfd_path, path,
						    sizeof(path) - 1);
				if (path_len == -1) {
					perror("readlink");
					exit(EXIT_FAILURE);
				}

				path[path_len] = '\0';
				printf("File %s\n", path);

				/* Close the file descriptor of the event. */

				close(metadata->fd);
			}

			/* Advance to next event. */

			metadata = FAN_EVENT_NEXT(metadata, size);
		}
	}
}

int main(int argc, char *argv[])
{
	char buf;
	int fd, poll_num;
	nfds_t nfds;
	struct pollfd fds[2];

	/* Check mount point is supplied. */

	if (argc != 2) {
		fprintf(stderr, "Usage: %s FILE\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = fanotify_init(0, O_RDONLY | O_LARGEFILE);
	if (fd == -1) {
		perror("fanotify_init");
		exit(EXIT_FAILURE);
	}

	if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_INODE, FAN_OPEN, AT_FDCWD,
			  argv[1]) == -1) {
		perror("fanotify_mark");
		exit(EXIT_FAILURE);
	}

	while (1) {
		handle_events(fd);
	}
}
