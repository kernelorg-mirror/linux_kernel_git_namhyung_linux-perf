/* SPDX-License-Identifier: GPL-2.0 */
#include <stdlib.h>

#include <bpf/bpf.h>
#include <linux/err.h>
#include <internal/xyarray.h>

#include "util/debug.h"
#include "util/evsel.h"

#include "util/bpf-filter.h"
#include <util/bpf-filter-flex.h>
#include <util/bpf-filter-bison.h>

#include "bpf_skel/sample-filter.h"
#include "bpf_skel/sample_filter.skel.h"

#define FD(e, x, y) (*(int *)xyarray__entry(e->core.fd, x, y))

#define __PERF_SAMPLE_TYPE(st, opt)	{ st, #st, opt }
#define PERF_SAMPLE_TYPE(_st, opt)	__PERF_SAMPLE_TYPE(PERF_SAMPLE_##_st, opt)

static const struct perf_sample_info {
	u64 type;
	const char *name;
	const char *option;
} sample_table[] = {
	/* default sample flags */
	PERF_SAMPLE_TYPE(IP, NULL),
	PERF_SAMPLE_TYPE(TID, NULL),
	PERF_SAMPLE_TYPE(PERIOD, NULL),
	/* flags mostly set by default, but still have options */
	PERF_SAMPLE_TYPE(ID, "--sample-identifier"),
	PERF_SAMPLE_TYPE(CPU, "--sample-cpu"),
	PERF_SAMPLE_TYPE(TIME, "-T"),
	/* optional sample flags */
	PERF_SAMPLE_TYPE(ADDR, "-d"),
	PERF_SAMPLE_TYPE(DATA_SRC, "-d"),
	PERF_SAMPLE_TYPE(PHYS_ADDR, "--phys-data"),
	PERF_SAMPLE_TYPE(WEIGHT, "-W"),
	PERF_SAMPLE_TYPE(WEIGHT_STRUCT, "-W"),
	PERF_SAMPLE_TYPE(TRANSACTION, "--transaction"),
	PERF_SAMPLE_TYPE(CODE_PAGE_SIZE, "--code-page-size"),
	PERF_SAMPLE_TYPE(DATA_PAGE_SIZE, "--data-page-size"),
};

static const struct perf_sample_info *get_sample_info(u64 flags)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(sample_table); i++) {
		if (sample_table[i].type == flags)
			return &sample_table[i];
	}
	return NULL;
}

static int check_sample_flags(struct evsel *evsel, struct perf_bpf_filter_expr *expr)
{
	const struct perf_sample_info *info;

	if (evsel->core.attr.sample_type & expr->sample_flags)
		return 0;

	if (expr->op == PBF_OP_GROUP_BEGIN) {
		struct perf_bpf_filter_expr *group;

		list_for_each_entry(group, &expr->groups, list) {
			if (check_sample_flags(evsel, group) < 0)
				return -1;
		}
		return 0;
	}

	info = get_sample_info(expr->sample_flags);
	if (info == NULL) {
		pr_err("Error: %s event does not have sample flags %lx\n",
		       evsel__name(evsel), expr->sample_flags);
		return -1;
	}

	pr_err("Error: %s event does not have %s\n", evsel__name(evsel), info->name);
	if (info->option)
		pr_err(" Hint: please add %s option to perf record\n", info->option);
	return -1;
}

int perf_bpf_filter__prepare(struct evsel *evsel)
{
	int i, x, y, fd, ret;
	struct sample_filter_bpf *skel;
	struct bpf_program *prog;
	struct bpf_link *link;
	struct perf_bpf_filter_expr *expr;
	struct perf_bpf_filter_entry *entry;

	entry = calloc(MAX_FILTERS, sizeof(*entry));
	if (entry == NULL)
		return -1;

	skel = sample_filter_bpf__open_and_load();
	if (!skel) {
		pr_err("Failed to load perf sample-filter BPF skeleton\n");
		ret = -EPERM;
		goto err;
	}

	i = 0;
	fd = bpf_map__fd(skel->maps.filters);
	list_for_each_entry(expr, &evsel->bpf_filters, list) {
		if (check_sample_flags(evsel, expr) < 0) {
			ret = -EINVAL;
			goto err;
		}

		if (i == MAX_FILTERS) {
			ret = -E2BIG;
			goto err;
		}

		entry[i].op = expr->op;
		entry[i].part = expr->part;
		entry[i].flags = expr->sample_flags;
		entry[i].value = expr->val;
		i++;

		if (expr->op == PBF_OP_GROUP_BEGIN) {
			struct perf_bpf_filter_expr *group;

			list_for_each_entry(group, &expr->groups, list) {
				if (i == MAX_FILTERS) {
					ret = -E2BIG;
					goto err;
				}

				entry[i].op = group->op;
				entry[i].part = group->part;
				entry[i].flags = group->sample_flags;
				entry[i].value = group->val;
				i++;
			}

			if (i == MAX_FILTERS) {
				ret = -E2BIG;
				goto err;
			}

			entry[i].op = PBF_OP_GROUP_END;
			i++;
		}
	}

	if (i < MAX_FILTERS) {
		/* to terminate the loop early */
		entry[i].op = PBF_OP_DONE;
		i++;
	}

	/* The filters map has only one entry for now */
	i = 0;
	if (bpf_map_update_elem(fd, &i, entry, BPF_ANY) < 0) {
		ret = -errno;
		pr_err("Failed to update the filter map\n");
		goto err;
	}

	prog = skel->progs.perf_sample_filter;
	for (x = 0; x < xyarray__max_x(evsel->core.fd); x++) {
		for (y = 0; y < xyarray__max_y(evsel->core.fd); y++) {
			link = bpf_program__attach_perf_event(prog, FD(evsel, x, y));
			if (IS_ERR(link)) {
				pr_err("Failed to attach perf sample-filter program\n");
				ret = PTR_ERR(link);
				goto err;
			}
		}
	}
	free(entry);
	evsel->bpf_skel = skel;
	return 0;

err:
	free(entry);
	sample_filter_bpf__destroy(skel);
	return ret;
}

int perf_bpf_filter__destroy(struct evsel *evsel)
{
	struct perf_bpf_filter_expr *expr, *tmp;

	list_for_each_entry_safe(expr, tmp, &evsel->bpf_filters, list) {
		list_del(&expr->list);
		free(expr);
	}
	sample_filter_bpf__destroy(evsel->bpf_skel);
	return 0;
}

u64 perf_bpf_filter__lost_count(struct evsel *evsel)
{
	struct sample_filter_bpf *skel = evsel->bpf_skel;

	return skel ? skel->bss->dropped : 0;
}

struct perf_bpf_filter_expr *perf_bpf_filter_expr__new(unsigned long sample_flags, int part,
						       enum perf_bpf_filter_op op,
						       unsigned long val)
{
	struct perf_bpf_filter_expr *expr;

	expr = malloc(sizeof(*expr));
	if (expr != NULL) {
		expr->sample_flags = sample_flags;
		expr->part = part;
		expr->op = op;
		expr->val = val;
		INIT_LIST_HEAD(&expr->groups);
	}
	return expr;
}

int perf_bpf_filter__parse(struct list_head *expr_head, const char *str)
{
	YY_BUFFER_STATE buffer;
	int ret;

	buffer = perf_bpf_filter__scan_string(str);

	ret = perf_bpf_filter_parse(expr_head);

	perf_bpf_filter__flush_buffer(buffer);
	perf_bpf_filter__delete_buffer(buffer);
	perf_bpf_filter_lex_destroy();

	return ret;
}
