#include <stdio.h>

#include "perf.h"
#include "util/util.h"
#include "util/cache.h"
#include "util/debug.h"
#include "ui/ui.h"
#include "ui/util.h"
#include "ui/browser.h"
#include "ui/libslang.h"
#include "ui/keysyms.h"
#include "ui/tui/tui.h"

static void ui_browser__file_seek(struct ui_browser *browser __maybe_unused,
				  off_t offset __maybe_unused,
				  int whence __maybe_unused)
{
	/* do nothing */
}

static void ui_browser__file_write(struct ui_browser *browser,
				   void *entry, int row)
{
	char buf[1024];
	char empty[] = " ";
	FILE *fp = perf_log.fp;
	bool current_entry = ui_browser__is_current_entry(browser, row);
	off_t *linemap = perf_log.linemap;
	unsigned int idx = *(unsigned int *)entry;
	unsigned long offset = (unsigned long)browser->priv;

	fseek(fp, linemap[idx], SEEK_SET);
	if (fgets(buf, sizeof(buf), fp) == NULL)
		return;

	ui_browser__set_color(browser, current_entry ? HE_COLORSET_SELECTED :
						       HE_COLORSET_NORMAL);

	if (offset < strlen(buf))
		slsmg_write_nstring(&buf[offset], browser->width);
	else
		slsmg_write_nstring(empty, browser->width);
}

static unsigned int ui_browser__file_refresh(struct ui_browser *browser)
{
	unsigned int row = 0;
	unsigned int idx = browser->top_idx;

	while (idx < browser->nr_entries) {
		ui_browser__gotorc(browser, row, 0);
		browser->write(browser, &idx, row);
		if (++row == browser->height)
			break;

		++idx;
	}

	return row;
}

static int log_menu__run(struct ui_browser *menu)
{
	int key;
	unsigned long offset;

	if (ui_browser__show(menu, "Log messages", "Press 'q' to exit") < 0)
		return -1;

	while (1) {
		key = ui_browser__run(menu, 0);

		switch (key) {
		case K_RIGHT:
			offset = (unsigned long)menu->priv;
			offset += 10;
			menu->priv = (void *)offset;
			continue;
		case K_LEFT:
			offset = (unsigned long)menu->priv;
			if (offset >= 10)
				offset -= 10;
			menu->priv = (void *)offset;
			continue;
		case K_ESC:
		case 'q':
		case CTRL('c'):
			key = -1;
			break;
		default:
			continue;
		}

		break;
	}

	ui_browser__hide(menu);
	return key;
}

int tui__log_window(void)
{
	struct ui_browser log_menu = {
		.refresh    = ui_browser__file_refresh,
		.seek	    = ui_browser__file_seek,
		.write	    = ui_browser__file_write,
		.nr_entries = perf_log.lines,
	};

	return log_menu__run(&log_menu);
}
