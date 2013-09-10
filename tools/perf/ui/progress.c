#include "../cache.h"
#include "progress.h"

static void nop_progress_update(u64 curr __maybe_unused,
				u64 total __maybe_unused,
				const char *title __maybe_unused)
{
}

static struct ui_progress default_progress_fns =
{
	.update		= nop_progress_update,
};

struct ui_progress *progress_fns = &default_progress_fns;

void ui_progress__update(u64 curr, u64 total, const char *title)
{
	return progress_fns->update(curr, total, title);
}

void ui_progress__setup(struct perf_progress *p, u64 total)
{
	p->curr = 0;
	p->next = p->unit = total / 16;
	p->total = total;

}

void ui_progress__advance(struct perf_progress *p, u64 adv, const char *title)
{
	p->curr += adv;

	if (p->curr >= p->next) {
		p->next += p->unit;
		ui_progress__update(p->curr, p->total, title);
	}
}

void ui_progress__finish(void)
{
	if (progress_fns->finish)
		progress_fns->finish();
}
