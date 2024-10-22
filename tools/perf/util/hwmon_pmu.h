/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HWMON_PMU_H
#define __HWMON_PMU_H

#include "pmu.h"

struct list_head;

bool perf_pmu__is_hwmon(const struct perf_pmu *pmu);
bool evsel__is_hwmon(const struct evsel *evsel);

/**
 * hwmon_pmu__new() - Allocate and construct a hwmon PMU.
 *
 * @pmus: The list of PMUs to be added to.
 * @hwmon_dir: An O_DIRECTORY file descriptor for a hwmon directory.
 * @sysfs_name: Name of the hwmon sysfs directory like hwmon0.
 * @name: The contents of the "name" file in the hwmon directory.
 *
 * Exposed for testing. Regular construction should happen via
 * perf_pmus__read_hwmon_pmus.
 */
struct perf_pmu *hwmon_pmu__new(struct list_head *pmus, int hwmon_dir,
				const char *sysfs_name, const char *name);
void hwmon_pmu__exit(struct perf_pmu *pmu);

int perf_pmus__read_hwmon_pmus(struct list_head *pmus);


int evsel__hwmon_pmu_open(struct evsel *evsel,
			 struct perf_thread_map *threads,
			 int start_cpu_map_idx, int end_cpu_map_idx);
int evsel__hwmon_pmu_read(struct evsel *evsel, int cpu_map_idx, int thread);

#endif /* __HWMON_PMU_H */
