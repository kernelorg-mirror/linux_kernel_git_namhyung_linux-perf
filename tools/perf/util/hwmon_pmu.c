// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "counts.h"
#include "debug.h"
#include "evsel.h"
#include "hashmap.h"
#include "hwmon_pmu.h"
#include "pmu.h"
#include <internal/xyarray.h>
#include <internal/threadmap.h>
#include <perf/threadmap.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <api/fs/fs.h>
#include <api/io.h>
#include <linux/zalloc.h>

struct hwmon_pmu {
	struct perf_pmu pmu;
	struct hashmap events;
	int hwmon_dir_fd;
};

bool perf_pmu__is_hwmon(const struct perf_pmu *pmu)
{
	return pmu && pmu->type >= PERF_PMU_TYPE_HWMON_START &&
		pmu->type <= PERF_PMU_TYPE_HWMON_END;
}

bool evsel__is_hwmon(const struct evsel *evsel)
{
	return perf_pmu__is_hwmon(evsel->pmu);
}

static void fix_name(char *p)
{
	char *s = strchr(p, '\n');

	if (s)
		*s = '\0';

	while (*p != '\0') {
		if (strchr(" :,/\n\t", *p))
			*p = '_';
		else
			*p = tolower(*p);
		p++;
	}
}

struct perf_pmu *hwmon_pmu__new(struct list_head *pmus, int hwmon_dir, const char *sysfs_name, const char *name)
{
	char buf[32];
	struct hwmon_pmu *hwm;

	hwm = zalloc(sizeof(*hwm));
	if (!hwm)
		return NULL;


	hwm->hwmon_dir_fd = hwmon_dir;
	hwm->pmu.type = PERF_PMU_TYPE_HWMON_START + strtoul(sysfs_name + 5, NULL, 10);
	if (hwm->pmu.type > PERF_PMU_TYPE_HWMON_END) {
		pr_err("Unable to encode hwmon type from %s in valid PMU type\n", sysfs_name);
		goto err_out;
	}
	snprintf(buf, sizeof(buf), "hwmon_%s", name);
	fix_name(buf + 6);
	hwm->pmu.name = strdup(buf);
	if (!hwm->pmu.name)
		goto err_out;
	hwm->pmu.alias_name = strdup(sysfs_name);
	if (!hwm->pmu.alias_name)
		goto err_out;
	hwm->pmu.cpus = perf_cpu_map__new("0");
	if (!hwm->pmu.cpus)
		goto err_out;
	INIT_LIST_HEAD(&hwm->pmu.format);
	INIT_LIST_HEAD(&hwm->pmu.aliases);
	INIT_LIST_HEAD(&hwm->pmu.caps);

	list_add_tail(&hwm->pmu.list, pmus);
	return &hwm->pmu;
err_out:
	free((char *)hwm->pmu.name);
	free(hwm->pmu.alias_name);
	free(hwm);
	close(hwmon_dir);
	return NULL;
}

void hwmon_pmu__exit(struct perf_pmu *pmu)
{
	struct hwmon_pmu *hwm = container_of(pmu, struct hwmon_pmu, pmu);

	close(hwm->hwmon_dir_fd);
}

int perf_pmus__read_hwmon_pmus(struct list_head *pmus)
{
	char *line = NULL;
	DIR *class_hwmon_dir;
	struct dirent *class_hwmon_ent;
	char buf[PATH_MAX];
	const char *sysfs = sysfs__mountpoint();

	if (!sysfs)
		return 0;

	scnprintf(buf, sizeof(buf), "%s/class/hwmon/", sysfs);
	class_hwmon_dir = opendir(buf);
	if (!class_hwmon_dir)
		return 0;

	while ((class_hwmon_ent = readdir(class_hwmon_dir)) != NULL) {
		size_t line_len;
		int hwmon_dir, name_fd;
		struct io io;

		if (class_hwmon_ent->d_type != DT_LNK)
			continue;

		scnprintf(buf, sizeof(buf), "%s/class/hwmon/%s", sysfs, class_hwmon_ent->d_name);
		hwmon_dir = open(buf, O_DIRECTORY);
		if (hwmon_dir == -1) {
			pr_debug("hwmon_pmu: not a directory: '%s/class/hwmon/%s'\n",
				 sysfs, class_hwmon_ent->d_name);
			continue;
		}
		name_fd = openat(hwmon_dir, "name", O_RDONLY);
		if (name_fd == -1) {
			pr_debug("hwmon_pmu: failure to open '%s/class/hwmon/%s/name'\n",
				  sysfs, class_hwmon_ent->d_name);
			close(hwmon_dir);
			continue;
		}
		io__init(&io, name_fd, buf, sizeof(buf));
		io__getline(&io, &line, &line_len);
		if (line_len > 0 && line[line_len - 1] == '\n')
			line[line_len - 1] = '\0';
		hwmon_pmu__new(pmus, hwmon_dir, class_hwmon_ent->d_name, line);
		close(name_fd);
	}
	free(line);
	closedir(class_hwmon_dir);
	return 0;
}

#define FD(e, x, y) (*(int *)xyarray__entry(e->core.fd, x, y))

int evsel__hwmon_pmu_open(struct evsel *evsel,
			  struct perf_thread_map *threads,
			  int start_cpu_map_idx, int end_cpu_map_idx)
{
	struct hwmon_pmu *hwm = container_of(evsel->pmu, struct hwmon_pmu, pmu);
	int idx = 0, thread = 0, nthreads, err = 0;

	nthreads = perf_thread_map__nr(threads);
	for (idx = start_cpu_map_idx; idx < end_cpu_map_idx; idx++) {
		for (thread = 0; thread < nthreads; thread++) {
			char buf[64];
			int fd;

			snprintf(buf, sizeof(buf), "%s_input", evsel->name);

			fd = openat(hwm->hwmon_dir_fd, buf, O_RDONLY);
			FD(evsel, idx, thread) = fd;
			if (fd < 0) {
				err = -errno;
				goto out_close;
			}
		}
	}
	return 0;
out_close:
	if (err)
		threads->err_thread = thread;

	do {
		while (--thread >= 0) {
			if (FD(evsel, idx, thread) >= 0)
				close(FD(evsel, idx, thread));
			FD(evsel, idx, thread) = -1;
		}
		thread = nthreads;
	} while (--idx >= 0);
	return err;
}

int evsel__hwmon_pmu_read(struct evsel *evsel, int cpu_map_idx, int thread)
{
	char buf[32];
	int fd;
	ssize_t len;
	struct perf_counts_values *count, *old_count = NULL;

	if (evsel->prev_raw_counts)
		old_count = perf_counts(evsel->prev_raw_counts, cpu_map_idx, thread);

	count = perf_counts(evsel->counts, cpu_map_idx, thread);
	fd = FD(evsel, cpu_map_idx, thread);
	len = pread(fd, buf, sizeof(buf), 0);
	if (len <= 0) {
		count->lost++;
		return -EINVAL;
	}
	buf[len] = '\0';
	if (old_count) {
		count->val = old_count->val + strtoll(buf, NULL, 10);
		count->run = old_count->run + 1;
		count->ena = old_count->ena + 1;
	} else {
		count->val = strtoll(buf, NULL, 10);
		count->run++;
		count->ena++;
	}
	return 0;
}
