// SPDX-License-Identifier: GPL-2.0
#include "builtin.h"
#include "color.h"
#include "util/debug.h"
#include "util/header.h"
#include <tools/config.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <subcmd/parse-options.h>

struct check {
	const char *feature;
};

static struct check check;

static struct option check_options[] = {
	OPT_STRING(0, "feature", &check.feature, NULL, "check if feature(s) is built in"),
	OPT_BOOLEAN('q', "quiet", &quiet, "do not show any warnings or messages"),
	OPT_END(),
};

static const char * const check_usage[] = {
	"perf check [<options>]",
	NULL
};

struct feature_support supported_features[] = {
	FEATURE_SUPPORT("dwarf", HAVE_DWARF_SUPPORT),
	FEATURE_SUPPORT("dwarf_getlocations", HAVE_DWARF_GETLOCATIONS_SUPPORT),
	FEATURE_SUPPORT("libaudit", HAVE_LIBAUDIT_SUPPORT),
	FEATURE_SUPPORT("syscall_table", HAVE_SYSCALL_TABLE_SUPPORT),
	FEATURE_SUPPORT("libbfd", HAVE_LIBBFD_SUPPORT),
	FEATURE_SUPPORT("debuginfod", HAVE_DEBUGINFOD_SUPPORT),
	FEATURE_SUPPORT("libelf", HAVE_LIBELF_SUPPORT),
	FEATURE_SUPPORT("libnuma", HAVE_LIBNUMA_SUPPORT),
	FEATURE_SUPPORT("numa_num_possible_cpus", HAVE_LIBNUMA_SUPPORT),
	FEATURE_SUPPORT("libperl", HAVE_LIBPERL_SUPPORT),
	FEATURE_SUPPORT("libpython", HAVE_LIBPYTHON_SUPPORT),
	FEATURE_SUPPORT("libslang", HAVE_SLANG_SUPPORT),
	FEATURE_SUPPORT("libcrypto", HAVE_LIBCRYPTO_SUPPORT),
	FEATURE_SUPPORT("libunwind", HAVE_LIBUNWIND_SUPPORT),
	FEATURE_SUPPORT("libdw-dwarf-unwind", HAVE_DWARF_SUPPORT),
	FEATURE_SUPPORT("zlib", HAVE_ZLIB_SUPPORT),
	FEATURE_SUPPORT("lzma", HAVE_LZMA_SUPPORT),
	FEATURE_SUPPORT("get_cpuid", HAVE_AUXTRACE_SUPPORT),
	FEATURE_SUPPORT("bpf", HAVE_LIBBPF_SUPPORT),
	FEATURE_SUPPORT("aio", HAVE_AIO_SUPPORT),
	FEATURE_SUPPORT("zstd", HAVE_ZSTD_SUPPORT),
	FEATURE_SUPPORT("libpfm4", HAVE_LIBPFM),
	FEATURE_SUPPORT("libtraceevent", HAVE_LIBTRACEEVENT),
	FEATURE_SUPPORT("bpf_skeletons", HAVE_BPF_SKEL),

	/* this should remain at end, to know the array end */
	FEATURE_SUPPORT(NULL, _)
};

static void on_off_print(const char *status)
{
	printf("[ ");

	if (!strcmp(status, "OFF"))
		color_fprintf(stdout, PERF_COLOR_RED, "%-3s", status);
	else
		color_fprintf(stdout, PERF_COLOR_GREEN, "%-3s", status);

	printf(" ]");
}

static void status_print(const char *name, const char *macro,
			 const char *status)
{
	printf("%22s: ", name);
	on_off_print(status);
	printf("  # %s\n", macro);
}

#define STATUS(feature)                                   \
do {                                                      \
	if (feature.is_builtin)                               \
		status_print(feature.name, feature.macro, "on");  \
	else                                                  \
		status_print(feature.name, feature.macro, "OFF"); \
} while (0)

/**
 * check whether "feature" is built-in with perf
 *
 * returns:
 *    0: NOT built-in or Feature not known
 *    1: Built-in
 */
static int has_support(const char *feature)
{
	for (int i = 0; supported_features[i].name; ++i) {
		if ((strcmp(feature, supported_features[i].name) == 0) ||
		    (strcmp(feature, supported_features[i].macro) == 0)) {
			if (!quiet)
				STATUS(supported_features[i]);
			return supported_features[i].is_builtin;
		}
	}

	if (!quiet)
		color_fprintf(stdout, PERF_COLOR_RED, "Feature not known: '%s'\n", feature);

	return 0;
}

int cmd_check(int argc, const char **argv)
{
	char *feature_list;
	char *feature_name;
	int feature_enabled;

	argc = parse_options(argc, argv, check_options, check_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);

	if (check.feature) {
		/* check.feature can be a single feature name, or a comma-separated list
		 * of feature names.
		 * eg. check.feature can be "libtraceevent" or
		 * "libtraceevent,libbpf_support" etc
		 *
		 * In case of a comma-separated list, feature_enabled will be 1, only if
		 * all features passed in the string are supported
		 * Note that check.feature will get modified due to strtok and str_trim
		 */
		feature_enabled = 1;
		feature_list = malloc((strlen(check.feature)+1) * sizeof(char));
		strncpy(feature_list, check.feature, strlen(check.feature)+1);
		feature_name = strtok(feature_list, ",");

		while (feature_name) {
			feature_enabled &= has_support(feature_name);
			feature_name = strtok(NULL, ",");
		}

		free(feature_list);

		return !feature_enabled;
	}

	return 0;
}
