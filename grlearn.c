#include "gradm.h"

#define GR_LEARN_PID_PATH "/etc/grsec/.grlearn.pid"
#define LEARN_BUFFER_SIZE (1024 * 1024)
#define MAX_ENTRY_SIZE 16384

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
	char pathname[PATH_MAX] = {0};
	char procname[64] = {0};

	if (!stat(GR_LEARN_PID_PATH, &fstat)) {
		fd = open(GR_LEARN_PID_PATH, O_RDONLY);

		if (fd < 0) {
			fprintf(stderr, "Unable to open %s:\n"
				"%s\n", GR_LEARN_PID_PATH, strerror(errno));
			kill(pid, 9);
			exit(EXIT_FAILURE);
		}

		read(fd, &learn_pid, sizeof(learn_pid));
		close(fd);
		unlink(GR_LEARN_PID_PATH);

		snprintf(procname, sizeof(procname) - 1, "/proc/%d/exe", learn_pid);
		if (readlink(procname, pathname, PATH_MAX - 1) < 0)
			goto start;
		if (strcmp(pathname, GRLEARN_PATH))
			goto start;
		fprintf(stderr, "Learning daemon possibly running already...killing process.\n");

		kill(learn_pid, 9);
	}
start:		
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
	char *p;
	ssize_t retval;
	struct pollfd fds;
	int fd, fd2;
	pid_t pid;
	struct sched_param schedulerparam;
	int i;

	if (argc != 2)
		return 1;
	
	if (!strcmp(argv[1], "-stop"))
		return stop_daemon();
		
	/* perform various operations to make us act in near real-time */

	srandom(getpid());

	mlockall(MCL_CURRENT | MCL_FUTURE);

	buf = calloc(1, LEARN_BUFFER_SIZE);
	if (!buf)
		return 1;
	for(i = 0; i < 640; i++) {
		cache[i] = calloc(1, sizeof(struct cache_entry));
		if (!cache[i])
			return 1;
		cache[i]->entryname = calloc(1, MAX_ENTRY_SIZE);
		if (!cache[i]->entryname)
			return 1;
	}

	setpriority(PRIO_PROCESS, 0, -20);
	nice(-19);
	schedulerparam.sched_priority = sched_get_priority_max(SCHED_FIFO);
	sched_setscheduler(0, SCHED_FIFO, &schedulerparam);

	fd = open(GRDEV_PATH, O_RDONLY);

	if (fd < 0) {
		fprintf(stderr, "Error opening %s:\n"
			"%s\n", GRDEV_PATH, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fd2 = open(argv[1], O_WRONLY | O_APPEND | O_CREAT, 0600);

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
		retval = read(fd, buf, LEARN_BUFFER_SIZE);
		if (retval > 0) {
			p = buf;
			while (p < (buf + retval)) {
				if (!check_cache(p)) {
					insert_into_cache(p);
					write(fd2, p, strlen(p));
				}
				while (*p++);
			}
		}
	}

	close(fd);
	close(fd2);

	return 0;
}
