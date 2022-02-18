/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __LINUX_LOCK_TRACE_H
#define __LINUX_LOCK_TRACE_H

#include <linux/tracepoint-defs.h>

DECLARE_TRACEPOINT(contention_begin);
DECLARE_TRACEPOINT(contention_end);

#define LCB_F_READ	(1U << 31)
#define LCB_F_WRITE	(1U << 30)
#define LCB_F_RT	(1U << 29)
#define LCB_F_PERCPU	(1U << 28)

extern void lock_contention_begin(void *lock, unsigned long ip,
				  unsigned int flags);
extern void lock_contention_end(void *lock);

#define LOCK_CONTENTION_BEGIN(_lock, _flags)				\
	do {								\
		if (tracepoint_enabled(contention_begin))		\
			lock_contention_begin(_lock, _RET_IP_, _flags);	\
	} while (0)

#define LOCK_CONTENTION_END(_lock)					\
	do {								\
		if (tracepoint_enabled(contention_end))			\
			lock_contention_end(_lock);			\
	} while (0)

#endif /* __LINUX_LOCK_TRACE_H */
