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
#include <sys/mman.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/threads.h>


#define GR_LEARN_PID_PATH "/etc/grsec/.grlearn.pid"

int stop_daemon(void)
{
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

struct cache_entry {
	char *entryname;
	unsigned long used;
	unsigned long checked;
	unsigned char taken:1;
} *cache[640];

/* maintain a cache of most recently used items */
int check_cache(char *str)
{
	int i;
	for (i = 0; i < 640; i++) {
		if (!cache[i]->taken)
			continue;
		cache[i]->checked++;
		if (!strcmp(cache[i]->entryname, str)) {
			cache[i]->used++;
			return 1;
		}
	}

	return 0;
}

void insert_into_cache(char *str)
{
	int i;
	struct cache_entry *least;
	int start = random() % 639;

	least = cache[start];

	for (i = start + 1; i != start; i = (i + 1) % 640) {
		if (!cache[i]->taken) {
			cache[i]->taken = 1;
			least = cache[i];
			break;
		}
		if (cache[i]->used < least->used && cache[i]->checked > 1280)
			least = cache[i];
	}

	strcpy(least->entryname, str);
	least->used = 0;
	least->checked = 0;

	return;
}
		
int main(int argc, char *argv[])
{
	char *buf;
	ssize_t retval;
	struct pollfd fds;
	int fd, fd2;
	pid_t pid;
	struct sched_param schedulerparam;
	char *tmpaddr;
	int i, j;

	if (argc != 2)
		return 1;
	
	if (!strcmp(argv[1], "-stop"))
		return stop_daemon();
		
	/* perform various operations to make us act in near real-time */

	srandom(getpid());

	mlockall(MCL_CURRENT | MCL_FUTURE);

	buf = calloc(16, 16384);
	if (!buf)
		return 1;
	for(i = 0; i < 640; i++) {
		cache[i] = calloc(1, sizeof(struct cache_entry));
		if (!cache[i])
			return 1;
		cache[i]->entryname = calloc(1, 16384);
		if (!cache[i]->entryname)
			return 1;
	}

	setpriority(PRIO_PROCESS, 0, -20);
	nice(-19);
	schedulerparam.sched_priority = sched_get_priority_max(SCHED_FIFO);
	sched_setscheduler(0, SCHED_FIFO, &schedulerparam);

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
		memset(buf, 0, 16 * 16384);
		retval = read(fd, buf, 16 * 16384);

		for(i = 0; i < 16; i++) {
			tmpaddr = buf + (i * 16384);
			if (*tmpaddr == 0)
				continue;
			if (!check_cache(tmpaddr)) {
				insert_into_cache(tmpaddr);
				write(fd2, tmpaddr, strlen(tmpaddr));
			}
		}
	}

	close(fd);
	close(fd2);

	return 0;
}
