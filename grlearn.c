#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#define GR_LEARN_PID_PATH "/etc/grsec/.grlearn.pid"

int stop_daemon(void)
{
	struct stat fstat;
	int fd;
	pid_t learn_pid;

	fd = open(GR_LEARN_PID_PATH, O_RDONLY);

	if (fd < 0)
		exit(EXIT_FAILURE);

	read(fd, &learn_pid, sizeof(learn_pid));

	kill(learn_pid, 9);

	close(fd);

	unlink(GR_LEARN_PID_PATH);

	return 0;
}
		

int write_pid_log(pid_t pid)
{
	struct stat fstat;
	int fd;
	pid_t learn_pid;

	if (!stat(GR_LEARN_PID_PATH, &fstat)) {
		fprintf(stderr, "Learning daemon possibly running already...killing process.\n");

		fd = open(GR_LEARN_PID_PATH, O_RDONLY);

		if (fd < 0) {
			fprintf(stderr, "Unable to open %s:\n"
				"%s\n", GR_LEARN_PID_PATH, strerror(errno));
			kill(pid, 9);
			exit(EXIT_FAILURE);
		}

		read(fd, &learn_pid, sizeof(learn_pid));

		kill(learn_pid, 9);

		close(fd);

		unlink(GR_LEARN_PID_PATH);
	}
		
	fd = open(GR_LEARN_PID_PATH, O_WRONLY | O_CREAT | O_EXCL, 0600);

	if (fd < 0) {
		fprintf(stderr, "Unable to open %s:\n"
			"%s\n", GR_LEARN_PID_PATH, strerror(errno));
		kill(pid, 9);
		exit(EXIT_FAILURE);
	}

	write(fd, &pid, sizeof(pid));

	close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	char buf[16384];
	struct pollfd fds;
	int fd, fd2;
	pid_t pid;

	if (argc != 2)
		return 1;
	
	if (!strcmp(argv[1], "-stop"))
		return stop_daemon();
		
	fd = open("/dev/grsec", O_RDONLY);

	if (fd < 0) {
		fprintf(stderr, "Error opening /dev/grsec:\n"
			"%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	fd2 = open(argv[1], O_WRONLY | O_APPEND | O_CREAT | O_SYNC, 0600);

	if (fd2 < 0) {
		fprintf(stderr, "Error opening %s\n"
			"%s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(fd2, F_SETFD, FD_CLOEXEC);

	pid = fork();

	if (pid > 0) {
		write_pid_log(pid);
		exit(EXIT_SUCCESS);
	} else if (!pid) {
		close(0);
		close(1);
		close(2);
	} else {
		fprintf(stderr, "Unable to fork.\n");
		exit(EXIT_FAILURE);
	}

	fds.fd = fd;
	fds.events = POLLIN;

	while (poll(&fds, 1, -1) > 0) {
		memset(&buf, 0, sizeof(buf));
		read(fd, &buf, sizeof(buf));		
		write(fd2, &buf, strlen(buf));
	}

	close(fd);
	close(fd2);

	return 0;
}
