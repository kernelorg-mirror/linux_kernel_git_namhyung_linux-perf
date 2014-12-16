#include <linux/compiler.h>
#include "builtin.h"
#include "perf.h"
#include "debug.h"
#include "session.h"
#include "evlist.h"
#include "parse-options.h"
#include <sys/mman.h>

typedef int (*data_cmd_fn_t)(int argc, const char **argv, const char *prefix);

static const char *output_name;

struct data_cmd {
	const char	*name;
	const char	*summary;
	data_cmd_fn_t	fn;
};

static struct data_cmd data_cmds[];

#define for_each_cmd(cmd) \
	for (cmd = data_cmds; cmd && cmd->name; cmd++)

static const struct option data_options[] = {
	OPT_END()
};

static const char * const data_usage[] = {
	"perf data [<common options>] <command> [<options>]",
	NULL
};

static void print_usage(void)
{
	struct data_cmd *cmd;

	printf("Usage:\n");
	printf("\t%s\n\n", data_usage[0]);
	printf("\tAvailable commands:\n");

	for_each_cmd(cmd) {
		printf("\t %s\t- %s\n", cmd->name, cmd->summary);
	}

	printf("\n");
}

static int data_cmd_index(int argc, const char **argv, const char *prefix);

static struct data_cmd data_cmds[] = {
	{ "index", "merge data file and add index", data_cmd_index },
	{ NULL },
};

#define FD_HASH_BITS  7
#define FD_HASH_SIZE  (1 << FD_HASH_BITS)
#define FD_HASH_MASK  (FD_HASH_SIZE - 1)

struct data_index {
	struct perf_tool	tool;
	struct perf_session	*session;
	enum {
		PER_CPU,
		PER_THREAD,
	} split_mode;
	char			*tmpdir;
	int 			header_fd;
	u64			header_written;
	struct hlist_head	fd_hash[FD_HASH_SIZE];
	int			fd_hash_nr;
	int			output_fd;
};

struct fdhash_node {
	int			id;
	int			fd;
	struct hlist_node	list;
};

static struct hlist_head *get_hash(struct data_index *index, int id)
{
	return &index->fd_hash[id % FD_HASH_MASK];
}

static int perf_event__rewrite_header(struct perf_tool *tool,
				      union perf_event *event)
{
	struct data_index *index = container_of(tool, struct data_index, tool);
	ssize_t size;

	size = writen(index->header_fd, event, event->header.size);
	if (size < 0)
		return -errno;

	index->header_written += size;
	return 0;
}

static int split_other_events(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample __maybe_unused,
				struct machine *machine __maybe_unused)
{
	return perf_event__rewrite_header(tool, event);
}

static int split_sample_event(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample,
				struct perf_evsel *evsel __maybe_unused,
				struct machine *machine __maybe_unused)
{
	struct data_index *index = container_of(tool, struct data_index, tool);
	int id = index->split_mode == PER_CPU ? sample->cpu : sample->tid;
	int fd = -1;
	char buf[PATH_MAX];
	struct hlist_head *head;
	struct fdhash_node *node;

	head = get_hash(index, id);
	hlist_for_each_entry(node, head, list) {
		if (node->id == id) {
			fd = node->fd;
			break;
		}
	}

	if (fd == -1) {
		scnprintf(buf, sizeof(buf), "%s/perf.data.%d",
			  index->tmpdir, index->fd_hash_nr++);

		fd = open(buf, O_RDWR|O_CREAT|O_TRUNC, 0600);
		if (fd < 0) {
			pr_err("cannot open data file: %s: %m\n", buf);
			return -1;
		}

		node = malloc(sizeof(*node));
		if (node == NULL) {
			pr_err("memory allocation failed\n");
			return -1;
		}

		node->id = id;
		node->fd = fd;

		hlist_add_head(&node->list, head);
	}

	return writen(fd, event, event->header.size) > 0 ? 0 : -errno;
}

static int split_data_file(struct data_index *index)
{
	struct perf_session *session = index->session;
	char buf[PATH_MAX];
	u64 sample_type;
	int header_fd;

	if (asprintf(&index->tmpdir, "%s.dir", output_name) < 0) {
		pr_err("memory allocation failed\n");
		return -1;
	}

	if (mkdir(index->tmpdir, 0700) < 0) {
		pr_err("cannot create intermediate directory\n");
		return -1;
	}

	/*
	 * This is necessary to write (copy) build-id table.  After
	 * processing header, dsos list will only contain dso which
	 * was on the original build-id table.
	 */
	dsos__hit_all(session);

	scnprintf(buf, sizeof(buf), "%s/perf.header", index->tmpdir);
	header_fd = open(buf, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (header_fd < 0) {
		pr_err("cannot open header file: %s: %m\n", buf);
		return -1;
	}

	lseek(header_fd, session->header.data_offset, SEEK_SET);

	sample_type = perf_evlist__combined_sample_type(session->evlist);
	if (sample_type & PERF_SAMPLE_CPU)
		index->split_mode = PER_CPU;
	else
		index->split_mode = PER_THREAD;

	pr_debug("splitting data file for %s\n",
		 index->split_mode == PER_CPU ? "CPUs" : "threads");

	index->header_fd = header_fd;
	if (perf_session__process_events(session, &index->tool) < 0) {
		pr_err("failed to process events\n");
		return -1;
	}

	session->header.data_size = index->header_written;
	/* 
	 * This is needed for index to determine current (header) file
	 * size (including feature data).
	 */
	perf_session__write_header(session, session->evlist, header_fd, true);

	return 0;
}

static int build_index_table(struct data_index *index)
{
	int i, n;
	u64 offset;
	u64 nr_index = index->fd_hash_nr;
	struct perf_file_section *idx;
	struct perf_session *session = index->session;

	idx = calloc(nr_index, sizeof(*idx));
	if (idx == NULL)
		return -1;

	/* index data will be placed after header file */
	offset = lseek(index->header_fd, 0, SEEK_END);
	if (offset == (u64)(loff_t) -1)
		goto out;

	/* increase the offset for added index data */
	offset += sizeof(nr_index) + nr_index * sizeof(*index);
	offset = PERF_ALIGN(offset, page_size);

	for (i = n = 0; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *node;

		hlist_for_each_entry(node, &index->fd_hash[i], list) {
			struct stat stbuf;

			if (fstat(node->fd, &stbuf) < 0)
				goto out;

			idx[n].offset = offset;
			idx[n].size   = stbuf.st_size;
			n++;

			offset += PERF_ALIGN(stbuf.st_size, page_size);
		}
	}

	BUG_ON(n != (int)nr_index);

	session->header.index = idx;
	session->header.nr_index = nr_index;
	perf_header__set_feat(&session->header, HEADER_DATA_INDEX);

	perf_session__write_header(session, session->evlist,
				   index->output_fd, true);
	return 0;

out:
	free(idx);
	return -1;
}

static int cleanup_temp_files(struct data_index *index)
{
	int i;

	for (i = 0; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *pos;
		struct hlist_node *tmp;

		hlist_for_each_entry_safe(pos, tmp, &index->fd_hash[i], list) {
			hlist_del(&pos->list);
			close(pos->fd);
			free(pos);
		}
	}
	close(index->header_fd);

	rm_rf(index->tmpdir);
	zfree(&index->tmpdir);
	return 0;
}

static int __data_cmd_index(struct data_index *index)
{
	struct perf_session *session = index->session;
	char *output = NULL;
	int ret = -1;
	int i, n;

	if (!output_name) {
		if (asprintf(&output, "%s.out", session->file->path) < 0) {
			pr_err("memory allocation failed\n");
			return -1;
		}

		output_name = output;
	}

	index->output_fd = open(output_name, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (index->output_fd < 0) {
		pr_err("cannot create output file: %s\n", output_name);
		goto out;
	}

	/*
	 * This is necessary to write (copy) build-id table.  After
	 * processing header, dsos list will contain dso which was on
	 * the original build-id table.
	 */
	dsos__hit_all(session);

	if (split_data_file(index) < 0)
		goto out_clean;

	if (build_index_table(index) < 0)
		goto out_clean;

	/* copy meta-events */
	if (copyfile_offset(index->header_fd, session->header.data_offset,
			   index->output_fd, session->header.data_offset,
			   session->header.data_size) < 0)
		goto out_clean;

	/* copy sample events */
	for (i = n = 0; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *node;

		hlist_for_each_entry(node, &index->fd_hash[i], list) {
			if (copyfile_offset(node->fd, 0, index->output_fd,
					    session->header.index[n].offset,
					    session->header.index[n].size) < 0)
				goto out_clean;
			n++;
		}
	}
	ret = 0;

out_clean:
	cleanup_temp_files(index);
	close(index->output_fd);
out:
	free(output);
	return ret;
}

int data_cmd_index(int argc, const char **argv, const char *prefix __maybe_unused)
{
	bool force = false;
	struct perf_session *session;
	struct perf_data_file file = {
		.mode  = PERF_DATA_MODE_READ,
	};
	struct data_index index = {
		.tool = {
			.sample		= split_sample_event,
			.fork		= split_other_events,
			.comm		= split_other_events,
			.exit		= split_other_events,
			.mmap		= split_other_events,
			.mmap2		= split_other_events,
			.lost		= split_other_events,
			.throttle	= split_other_events,
			.unthrottle	= split_other_events,
			.ordered_events = false,
		},
	};
	const char * const index_usage[] = {
		"perf data index [<options>]",
		NULL
	};
	const struct option index_options[] = {
	OPT_STRING('i', "input", &input_name, "file", "input file name"),
	OPT_STRING('o', "output", &output_name, "file", "output directory name"),
	OPT_BOOLEAN('f', "force", &force, "don't complain, do it"),
	OPT_INCR('v', "verbose", &verbose, "be more verbose"),
	OPT_END()
	};

	argc = parse_options(argc, argv, index_options, index_usage, 0);
	if (argc)
		usage_with_options(index_usage, index_options);

	file.path = input_name;
	file.force = force;
	session = perf_session__new(&file, false, &index.tool);
	if (session == NULL)
		return -1;

	index.session = session;
	symbol__init(&session->header.env);

	__data_cmd_index(&index);

	perf_session__delete(session);
	return 0;
}

int cmd_data(int argc, const char **argv, const char *prefix)
{
	struct data_cmd *cmd;
	const char *cmdstr;

	/* No command specified. */
	if (argc < 2)
		goto usage;

	argc = parse_options(argc, argv, data_options, data_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc < 1)
		goto usage;

	cmdstr = argv[0];

	for_each_cmd(cmd) {
		if (strcmp(cmd->name, cmdstr))
			continue;

		return cmd->fn(argc, argv, prefix);
	}

	pr_err("Unknown command: %s\n", cmdstr);
usage:
	print_usage();
	return -1;
}
