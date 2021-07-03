// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2022 Google */

#include "util/bpf_filter.h"
#include "util/cpumap.h"
#include "util/debug.h"
#include "util/evsel.h"

#include <linux/err.h>
#include <perf/evsel.h>
#include <internal/xyarray.h>

#include "bpf_skel/ibs_filter.skel.h"

static struct ibs_filter_bpf *skel;

#define FD(evt, cpu) (*(int *)xyarray__entry(evt->core.fd, cpu, 0))

int ibs_filter__prepare(struct evsel *evsel)
{
	int err, i;
	struct perf_cpu cpu;
	struct bpf_link *link;

	skel = ibs_filter_bpf__open();
	if (!skel) {
		pr_err("Failed to open ibs_filter skeleton\n");
		return -1;
	}

	err = ibs_filter_bpf__load(skel);
	if (err) {
		pr_err("Failed to load ibs_filter skeleton\n");
		goto out;
	}

	perf_cpu_map__for_each_cpu(cpu, i, evsel->core.cpus) {
		link = bpf_program__attach_perf_event(skel->progs.ibs_op_filter,
						      FD(evsel, i));
		if (IS_ERR(link)) {
			pr_err("Failed to attach to IBS event on CPU%d\n", cpu.cpu);
			goto out;
		}
	}
	return 0;

out:
	ibs_filter_bpf__destroy(skel);
	skel = NULL;
	return err;
}

void ibs_filter__finish(void)
{
	ibs_filter_bpf__destroy(skel);
}
