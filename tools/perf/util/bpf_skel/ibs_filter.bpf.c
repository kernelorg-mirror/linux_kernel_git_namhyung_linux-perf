// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2022  Google
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define BR_RETIRED  (1U << 5)

int read_failed;
int lost;

SEC("perf_event")
int ibs_op_filter(struct bpf_perf_event_data *ctx)
{
	u32 ibs_op_regs[16] = { 0, };
	int len;

	len = bpf_read_raw_record(ctx, ibs_op_regs, sizeof(ibs_op_regs), 0);
	if (len < 0) {
		read_failed++;
		return 1;
	}

	if (len >= 32 && !(ibs_op_regs[6] & BR_RETIRED))
		return 0;

	lost++;
	return 1;
}
