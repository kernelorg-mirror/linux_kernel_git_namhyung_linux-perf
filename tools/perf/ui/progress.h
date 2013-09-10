#ifndef _PERF_UI_PROGRESS_H_
#define _PERF_UI_PROGRESS_H_ 1

#include <../types.h>

struct ui_progress {
	void (*update)(u64, u64, const char *);
	void (*finish)(void);
};

struct perf_progress {
	u64 curr;
	u64 next;
	u64 unit;
	u64 total;
};

extern struct ui_progress *progress_fns;

void ui_progress__init(void);

void ui_progress__setup(struct perf_progress *p, u64 total);
void ui_progress__advance(struct perf_progress *p, u64 adv, const char *title);

void ui_progress__update(u64 curr, u64 total, const char *title);
void ui_progress__finish(void);

#endif
