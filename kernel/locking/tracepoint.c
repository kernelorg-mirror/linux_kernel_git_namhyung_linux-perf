/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/lock_trace.h>

#define CREATE_TRACE_POINTS
#include <trace/events/lock.h>

/* these are exported via LOCK_CONTENTION_{BEGIN,END} macro */
EXPORT_TRACEPOINT_SYMBOL_GPL(contention_begin);
EXPORT_TRACEPOINT_SYMBOL_GPL(contention_end);

void lock_contention_begin(void *lock, unsigned long ip, unsigned int flags)
{
	trace_contention_begin(lock, ip, flags);
}
EXPORT_SYMBOL_GPL(lock_contention_begin);

void lock_contention_end(void *lock)
{
	trace_contention_end(lock);
}
EXPORT_SYMBOL_GPL(lock_contention_end);
