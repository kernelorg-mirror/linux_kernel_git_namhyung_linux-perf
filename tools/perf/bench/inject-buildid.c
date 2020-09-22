// SPDX-License-Identifier: GPL-2.0
#include <stdlib.h>
#include <stddef.h>
#include <ftw.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/kernel.h>
#include <linux/time64.h>
#include <linux/list.h>
#include <linux/err.h>
#include <internal/lib.h>
#include <subcmd/parse-options.h>

#include "bench.h"
#include "util/data.h"
#include "util/stat.h"
#include "util/debug.h"
#include "util/event.h"
#include "util/symbol.h"
#include "util/session.h"
#include "util/build-id.h"
#include "util/synthetic-events.h"

#define MMAP_DEV_MAJOR  8

static unsigned int iterations = 100;
static unsigned int nr_mmaps   = 100;
static unsigned int nr_samples = 100;  /* samples per mmap */

static u64 bench_sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID;
static u16 bench_id_hdr_size = 8;  /* only for pid/tid */

struct bench_data {
	int			pid;
	int			input_pipe[2];
	int			output_pipe[2];
};

struct bench_dso {
	struct list_head	list;
	char			*name;
	int			ino;
};

static int nr_dsos;
static LIST_HEAD(dso_list);

extern int cmd_inject(int argc, const char *argv[]);

static const struct option options[] = {
	OPT_UINTEGER('i', "iterations", &iterations,
		     "Number of iterations used to compute average (default: 100)"),
	OPT_UINTEGER('m', "nr-mmaps", &nr_mmaps,
		     "Number of mmap events for each iteration (default: 100)"),
	OPT_UINTEGER('n', "nr-samples", &nr_samples,
		     "Number of sample events per mmap event (default: 100)"),
	OPT_INCR('v', "verbose", &verbose,
		 "be more verbose (show iteration count, DSO name, etc)"),
	OPT_END()
};

static const char *const bench_usage[] = {
	"perf bench internals inject-build-id <options>",
	NULL
};

static int add_dso(const char *fpath, const struct stat *sb __maybe_unused,
		   int typeflag, struct FTW *ftwbuf __maybe_unused)
{
	struct bench_dso *dso;
	unsigned char build_id[BUILD_ID_SIZE];

	if (typeflag == FTW_D || typeflag == FTW_SL) {
		return 0;
	}

	if (filename__read_build_id(fpath, build_id, BUILD_ID_SIZE) < 0)
		return 0;

	dso = malloc(sizeof(*dso));
	if (dso == NULL)
		return -1;

	dso->name = realpath(fpath, NULL);
	if (dso->name == NULL) {
		free(dso);
		return -1;
	}

	dso->ino = nr_dsos++;
	list_add(&dso->list, &dso_list);
	pr_debug2("  Adding DSO: %s\n", fpath);

	/* stop if we collected 4x DSOs than needed */
	if ((unsigned)nr_dsos > 4 * nr_mmaps)
		return 1;

	return 0;
}

static void collect_dso(void)
{
	if (nftw("/usr/lib/", add_dso, 10, FTW_PHYS) < 0)
		return;

	pr_debug("  Collected %d DSOs\n", nr_dsos);
}

static void release_dso(void)
{
	struct bench_dso *dso;

	while (!list_empty(&dso_list)) {
		dso = list_first_entry(&dso_list, struct bench_dso, list);
		list_del(&dso->list);
		free(dso->name);
		free(dso);
	}
}

static u64 dso_map_addr(struct bench_dso *dso)
{
	return 0x400000ULL + dso->ino * 8192ULL;
}

static u32 synthesize_attr(struct bench_data *data)
{
	union perf_event event;

	memset(&event, 0, sizeof(event.attr) + sizeof(u64));

	event.header.type = PERF_RECORD_HEADER_ATTR;
	event.header.size = sizeof(event.attr) + sizeof(u64);

	event.attr.attr.type = PERF_TYPE_SOFTWARE;
	event.attr.attr.config = PERF_COUNT_SW_TASK_CLOCK;
	event.attr.attr.exclude_kernel = 1;
	event.attr.attr.sample_id_all = 1;
	event.attr.attr.sample_type = bench_sample_type;

	return writen(data->input_pipe[1], &event, event.header.size);
}

static u32 synthesize_fork(struct bench_data *data)
{
	union perf_event event;

	memset(&event, 0, sizeof(event.fork) + bench_id_hdr_size);

	event.header.type = PERF_RECORD_FORK;
	event.header.misc = PERF_RECORD_MISC_FORK_EXEC;
	event.header.size = sizeof(event.fork) + bench_id_hdr_size;

	event.fork.ppid = 1;
	event.fork.ptid = 1;
	event.fork.pid = data->pid;
	event.fork.tid = data->pid;

	return writen(data->input_pipe[1], &event, event.header.size);
}

static u32 synthesize_mmap(struct bench_data *data, struct bench_dso *dso)
{
	union perf_event event;
	size_t len = offsetof(struct perf_record_mmap2, filename);

	len += roundup(strlen(dso->name) + 1, 8) + bench_id_hdr_size;

	memset(&event, 0, min(len, sizeof(event.mmap2)));

	event.header.type = PERF_RECORD_MMAP2;
	event.header.misc = PERF_RECORD_MISC_USER;
	event.header.size = len;

	event.mmap2.pid = data->pid;
	event.mmap2.tid = data->pid;
	event.mmap2.maj = MMAP_DEV_MAJOR;
	event.mmap2.ino = dso->ino;

	strcpy(event.mmap2.filename, dso->name);

	event.mmap2.start = dso_map_addr(dso);
	event.mmap2.len = 4096;
	event.mmap2.prot = PROT_EXEC;

	if (len > sizeof(event.mmap2)) {
		/* write mmap2 event first */
		writen(data->input_pipe[1], &event, len - bench_id_hdr_size);
		/* write zero-filled sample id header */
		memset(&event, 0, bench_id_hdr_size);
		writen(data->input_pipe[1], &event, bench_id_hdr_size);
	} else {
		writen(data->input_pipe[1], &event, len);
	}
	return len;
}

static u32 synthesize_sample(struct bench_data *data, struct bench_dso *dso)
{
	union perf_event event;
	struct perf_sample sample = {
		.tid = data->pid,
		.pid = data->pid,
		.ip = dso_map_addr(dso),
	};

	event.header.type = PERF_RECORD_SAMPLE;
	event.header.misc = PERF_RECORD_MISC_USER;
	event.header.size = perf_event__sample_event_size(&sample, bench_sample_type, 0);

	perf_event__synthesize_sample(&event, bench_sample_type, 0, &sample);

	return writen(data->input_pipe[1], &event, event.header.size);
}

static void sigpipe_handler(int sig __maybe_unused)
{
	/* child exited */
}

static int setup_injection(struct bench_data *data)
{
	int ready_pipe[2];
	int dev_null_fd;
	char buf;

	if (pipe(ready_pipe) < 0)
		return -1;

	if (pipe(data->input_pipe) < 0)
		return -1;

	if (pipe(data->output_pipe) < 0)
		return -1;

	data->pid = fork();
	if (data->pid < 0)
		return -1;

	if (data->pid == 0) {
		const char **inject_argv;

		close(data->input_pipe[1]);
		close(data->output_pipe[0]);
		close(ready_pipe[0]);

		dup2(data->input_pipe[0], STDIN_FILENO);
		close(data->input_pipe[0]);
		dup2(data->output_pipe[1], STDOUT_FILENO);
		close(data->output_pipe[1]);

		dev_null_fd = open("/dev/null", O_WRONLY);
		if (dev_null_fd < 0)
			exit(1);

		dup2(dev_null_fd, STDERR_FILENO);

		inject_argv = calloc(3, sizeof(*inject_argv));
		if (inject_argv == NULL)
			exit(1);

		inject_argv[0] = strdup("inject");
		inject_argv[1] = strdup("-b");

		/* signal that we're ready to go */
		close(ready_pipe[1]);

		cmd_inject(2, inject_argv);

		exit(0);
	}

	signal(SIGPIPE, sigpipe_handler);

	close(ready_pipe[1]);
	close(data->input_pipe[0]);
	close(data->output_pipe[1]);

	/* wait for child ready */
	if (read(ready_pipe[0], &buf, 1) < 0)
		return -1;
	close(ready_pipe[0]);

	return 0;
}

static int inject_build_id(struct bench_data *data)
{
	int flag, status;
	unsigned int i, k;
	char buf[8192];
	u64 nread = 0;
	u64 len = nr_mmaps / 2 * sizeof(struct perf_record_header_build_id);

	flag = fcntl(data->output_pipe[0], F_GETFL, 0);
	if (fcntl(data->output_pipe[0], F_SETFL, flag | O_NONBLOCK) < 0)
		return -1;

	/* this makes the child to run */
	if (perf_header__write_pipe(data->input_pipe[1]) < 0)
		return -1;

	len += synthesize_attr(data);
	len += synthesize_fork(data);

	for (i = 0; i < nr_mmaps; i++) {
		struct bench_dso *dso;
		int idx = rand() % (nr_dsos - 1);

		dso = list_first_entry(&dso_list, struct bench_dso, list);
		while (idx--)
			dso = list_next_entry(dso, list);

		pr_debug("   [%2d] injecting: %s\n", i+1, dso->name);
		len += synthesize_mmap(data, dso);

		for (k = 0; k < nr_samples; k++)
			len += synthesize_sample(data, dso);

		/* read out data from child */
		while (true) {
			int n; 

			n = read(data->output_pipe[0], buf, sizeof(buf));
			if (n <= 0)
				break;
			nread += n;
		}
	}

	/* wait to read data at least as we wrote + some build-ids */
	while (nread < len) {
		int n;

		n = read(data->output_pipe[0], buf, sizeof(buf));
		if (n < 0)
			break;
		nread += n;
	}
	close(data->input_pipe[1]);
	close(data->output_pipe[0]);

	wait(&status);
	pr_debug("   Child %d exited with %d\n", data->pid, status);

	return 0;
}

static int do_inject_loop(struct bench_data *data)
{
	unsigned int i;
	struct stats time_stats;
	double time_average, time_stddev;

	srand(time(NULL));
	init_stats(&time_stats);
	symbol__init(NULL);

	collect_dso();
	if (nr_dsos == 0) {
		printf("  Cannot collect DSOs for injection\n");
		return -1;
	}

	for (i = 0; i < iterations; i++) {
		struct timeval start, end, diff;
		u64 runtime_us;

		pr_debug("  Iteration #%d\n", i+1);

		if (setup_injection(data) < 0) {
			printf("  Build-id injection setup failed\n");
			break;
		}

		gettimeofday(&start, NULL);
		if (inject_build_id(data) < 0) {
			printf("  Build-id injection failed\n");
			break;
		}

		gettimeofday(&end, NULL);
		timersub(&end, &start, &diff);
		runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		update_stats(&time_stats, runtime_us);
	}

	time_average = avg_stats(&time_stats) / USEC_PER_MSEC;
	time_stddev = stddev_stats(&time_stats) / USEC_PER_MSEC;
	printf("  Average build-id injection took: %.3f msec (+- %.3f msec)\n",
		time_average, time_stddev);

	/* each iteration, it processes MMAP2 + BUILD_ID + nr_samples * SAMPLE */
	time_average = avg_stats(&time_stats) / (nr_mmaps * (nr_samples + 2));
	time_stddev = stddev_stats(&time_stats) / (nr_mmaps * (nr_samples + 2));
	printf("  Average time per event: %.3f usec (+- %.3f usec)\n",
		time_average, time_stddev);

	release_dso();
	return 0;
}

int bench_inject_build_id(int argc, const char **argv)
{
	struct bench_data data;

	argc = parse_options(argc, argv, options, bench_usage, 0);
	if (argc) {
		usage_with_options(bench_usage, options);
		exit(EXIT_FAILURE);
	}

	return do_inject_loop(&data);
}

