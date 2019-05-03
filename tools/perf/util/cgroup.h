/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CGROUP_H__
#define __CGROUP_H__

#include <linux/refcount.h>
#include <linux/rbtree.h>

struct option;

struct cgroup {
	struct rb_node		node;
	u64			id;
	char			*name;
	int			fd;
	refcount_t		refcnt;
};

extern int nr_cgroups; /* number of explicit cgroups defined */

int cgroupfs_find_mountpoint(char *buf, size_t maxlen);
struct cgroup *cgroup__get(struct cgroup *cgroup);
void cgroup__put(struct cgroup *cgroup);

struct evlist;

struct cgroup *evlist__findnew_cgroup(struct evlist *evlist, const char *name);

void evlist__set_default_cgroup(struct evlist *evlist, struct cgroup *cgroup);

int parse_cgroups(const struct option *opt, const char *str, int unset);

struct cgroup *cgroup__findnew(uint64_t id, const char *path);
struct cgroup *cgroup__find_by_path(const char *path);

void destroy_cgroups(void);

#endif /* __CGROUP_H__ */
