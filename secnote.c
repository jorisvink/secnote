/*
 * Copyright (c) 2022 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <openssl/sha.h>

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <fts.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DUMP_PARSE_TOPIC	1
#define DUMP_PARSE_ENTRY	2

#define ENTRY_STATE_MOVED	(1 << 1)
#define ENTRY_STATE_DIFFERS	(1 << 2)
#define ENTRY_STATE_GONE	(1 << 3)
#define ENTRY_STATE_SAME	(1 << 4)
#define ENTRY_STATE_GREW	(1 << 5)
#define ENTRY_STATE_SHRUNK	(1 << 6)

#define FILE_SEPARATOR		\
    "==================================================================="

#define TAG_OPEN		"@secnote-open"
#define TAG_CLOSE		"@secnote-close"

#define MAX(a, b)		((a > b) ? a : b)
#define MIN(a, b)		((a < b) ? a : b)

struct line {
	char			*code;
	TAILQ_ENTRY(line)	list;
};

struct entry {
	int			order;

	char			*file;
	char			*code;
	char			*context;

	int			line_start;
	int			line_end;

	SHA256_CTX		shactx;
	char			digest[(SHA256_DIGEST_LENGTH * 2) + 1];

	TAILQ_HEAD(, line)	lines;
	TAILQ_ENTRY(entry)	list;
};

TAILQ_HEAD(entry_list, entry);

struct topic {
	char			*name;
	struct entry_list	entries;
	TAILQ_ENTRY(topic)	list;
};

struct file {
	FILE			*fp;
	char			*path;
};

struct context {
	int			list;
	int			pnum;
	int			full;
	int			digest;
	const char		*query;

	struct topic		*topic;
	TAILQ_HEAD(, topic)	topics;
};

static void	fatal(const char *, ...);
static int	filecmp(const FTSENT **, const FTSENT **);

static void	entry_record_line(struct entry *, const char *);
static int	entry_check_state(struct entry_list *, struct entry *,
		    struct entry **);

static void	file_close(struct file *);
static void	file_consume_newline(struct file *);
static void	file_parse(struct context *, const char *);
static int	file_read_line(struct file *, char *, size_t);
static void	file_open(struct file *, const char *, const char *);

static void	text_topic_write(struct context *, struct topic *);
static void	text_topic_header(struct context *, struct topic *);

static void	load_from_dump(struct context *, const char *);
static void	load_from_args(struct context *, int, char **);

static int	dump_parse_entry(struct context *, struct file *, char *);
static int	dump_parse_topic(struct context *, struct file *, const char *);

static void	text_topic_dump(struct context *);
static void	topic_free(struct context *, struct topic *);
static void	context_compare(struct context *, struct context *);

static struct topic	*topic_resolve(struct context *, const char *);
static struct entry	*topic_record_entry(struct context *, struct topic *,
			    const char *, const char *, int);

static void
usage(void)
{
	fprintf(stderr,
	    "Usage: secnote [-pnum] [-l [-f] | -d | -q query] [src]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int			ch;
	struct context		ctx, vfy;
	const char		*err, *verify;

	verify = NULL;

	memset(&ctx, 0, sizeof(ctx));
	memset(&vfy, 0, sizeof(vfy));

	TAILQ_INIT(&ctx.topics);
	TAILQ_INIT(&vfy.topics);

	while ((ch = getopt(argc, argv, "dfhlp:q:v:")) != -1) {
		switch (ch) {
		case 'd':
			ctx.list = 1;
			ctx.full = 1;
			ctx.digest = 1;
			break;
		case 'f':
			ctx.full = 1;
			break;
		case 'l':
			ctx.list = 1;
			break;
		case 'p':
			ctx.pnum = strtonum(optarg, 0, 255, &err);
			if (err != NULL)
				fatal("-p %s invalid: %s", optarg, err);
			vfy.pnum = ctx.pnum;
			break;
		case 'q':
			ctx.query = optarg;
			break;
		case 'v':
			verify = optarg;
			break;
		case 'h':
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	if (ctx.list && (ctx.query || verify))
		fatal("-l/-d and -q/-v are mutually exclusive");

	if (ctx.full && !ctx.list) {
		fprintf(stderr, "-f only works with -l\n");
		usage();
	}

	load_from_args(&ctx, argc, argv);

	if (verify) {
		load_from_dump(&vfy, verify);
		context_compare(&vfy, &ctx);
	} else {
		if (TAILQ_EMPTY(&ctx.topics))
			printf("no topics found\n");
		else
			text_topic_dump(&ctx);
	}

	return (0);
}

static void
context_compare(struct context *verify, struct context *ondisk)
{
	const char		*sep;
	struct topic		*t1, *t2;
	struct entry		*entry, *ent;
	int			a, b, changes, header, state;

	changes = 0;

	TAILQ_FOREACH(t1, &verify->topics, list) {
		TAILQ_FOREACH(t2, &ondisk->topics, list) {
			if (!strcmp(t2->name, t1->name))
				break;
		}

		if (t2 == NULL) {
			changes++;
			printf("topic '%s' not found in source\n", t1->name);
			continue;
		}

		header = 0;

		TAILQ_FOREACH(entry, &t1->entries, list) {
			state = entry_check_state(&t2->entries, entry, &ent);

			if (state != ENTRY_STATE_SAME && !header) {
				header = 1;
				printf("@ %s\n\n", t1->name);
			}

			switch (state) {
			case ENTRY_STATE_SAME:
				continue;
			case ENTRY_STATE_GONE:
				changes++;
				printf("chunk '%s' (%d-%d) not found\n",
				    entry->file, entry->line_start,
				    entry->line_end);
				continue;
			}

			changes++;
			sep = NULL;

			printf("chunk '%s' (%d-%d) ", entry->file,
			    entry->line_start, entry->line_end);

			a = entry->line_end - entry->line_start;
			b = ent->line_end - ent->line_start;

			if (a < b)
				state |= ENTRY_STATE_GREW;
			else if (a > b)
				state |= ENTRY_STATE_SHRUNK;

			if (state & ENTRY_STATE_MOVED) {
				sep = ", ";
				printf("moved %d-%d",
				    ent->line_start, ent->line_end);
			}

			if (state & ENTRY_STATE_DIFFERS) {
				if (sep)
					printf("%s", sep);

				printf("modified");

				if (state &
				    (ENTRY_STATE_SHRUNK | ENTRY_STATE_GREW))
					printf(" %+d lines(s)", b - a);
			}

			printf("\n");
		}

		if (header)
			printf("\n");
	}

	if (changes > 0)
		fatal("%d change%s detected", changes, changes > 1 ? "s" : "");

	printf("secnote verified\n");
}

static void
load_from_args(struct context *ctx, int argc, char **argv)
{
	struct stat		st;
	int			idx;
	FTS			*fts;
	FTSENT			*ent;
	char			*pv[2], *ext;

	for (idx = 0; idx < argc; idx++) {
		if (stat(argv[idx], &st) == -1 ||
		    access(argv[idx], R_OK) == -1) {
			fprintf(stderr, "skipping '%s' (%s)\n",
			    argv[idx], strerror(errno));
			continue;
		}

		if (S_ISREG(st.st_mode)) {
			file_parse(ctx, argv[idx]);
			continue;
		}

		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "skipping '%s'\n", argv[idx]);
			continue;
		}

		pv[0] = argv[idx];
		pv[1] = NULL;

		fts = fts_open(pv,
		    FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, filecmp);
		if (fts == NULL)
			fatal("fts_open: %s", strerror(errno));

		while ((ent = fts_read(fts)) != NULL) {
			if (!S_ISREG(ent->fts_statp->st_mode))
				continue;

			if ((ext = strrchr(ent->fts_name, '.')) == NULL)
				continue;

			if (strcmp(ext, ".c") && strcmp(ext, ".h"))
				continue;

			file_parse(ctx, ent->fts_path);
		}

		fts_close(fts);
	}
}

static void
load_from_dump(struct context *ctx, const char *path)
{
	struct file	file;
	int		state;
	char		buf[512];

	if (!strcmp(path, "-")) {
		file.fp = stdin;
		file.path = "<stdin>";
	} else {
		file_open(&file, path, "r");
	}

	state = DUMP_PARSE_TOPIC;

	while (file_read_line(&file, buf, sizeof(buf))) {
		switch (state) {
		case DUMP_PARSE_TOPIC:
			state = dump_parse_topic(ctx, &file, buf);
			break;
		case DUMP_PARSE_ENTRY:
			state = dump_parse_entry(ctx, &file, buf);
			break;
		default:
			fatal("invalid parse state %d", state);
		}
	}

	if (file.fp != stdin)
		file_close(&file);
}

static int
dump_parse_topic(struct context *ctx, struct file *file, const char *line)
{
	if (line[0] != '@')
		fatal("expected start of topic, got '%s'", line);

	ctx->topic = topic_resolve(ctx, &line[2]);
	file_consume_newline(file);

	return (DUMP_PARSE_ENTRY);
}

static int
dump_parse_entry(struct context *ctx, struct file *file, char *line)
{
	int		count;
	struct entry	*entry;
	char		**ap, *args[5], *hash, *path, *region, *context;

	(void)ctx;
	(void)file;

	if (line[0] == '\0') {
		ctx->topic = NULL;
		return (DUMP_PARSE_TOPIC);
	}

	count = 0;
	for (ap = args; ap < &args[5] &&
	    (*ap = strsep(&line, ":")) != NULL;) {
		if (**ap != '\0') {
			ap++;
			count++;
		}
	}

	if (count != 3 && count != 4)
		fatal("invalid entry in file '%s'", file->path);

	hash = args[0];
	path = args[1];
	region = args[2];

	if (count > 3)
		context = args[3];
	else
		context = NULL;

	entry = topic_record_entry(ctx, ctx->topic, path, context, -1);

	if (strlcpy(entry->digest, hash, sizeof(entry->digest)) >=
	    sizeof(entry->digest))
		fatal("invalid hash string '%s' in '%s'", hash, file->path);

	if (sscanf(region, "%d-%d", &entry->line_start, &entry->line_end) != 2)
		fatal("invalid region string '%s' in '%s'", region, file->path);

	return (DUMP_PARSE_ENTRY);
}

static void
file_open(struct file *file, const char *path, const char *mode)
{
	memset(file, 0, sizeof(*file));

	if ((file->fp = fopen(path, mode)) == NULL)
		fatal("fopen(%s): %s", path, strerror(errno));

	if ((file->path = strdup(path)) == NULL)
		fatal("strdup: %s", strerror(errno));
}

static void
file_close(struct file *file)
{
	fclose(file->fp);
	free(file->path);
}

static int
file_read_line(struct file *file, char *buf, size_t len)
{
	if (fgets(buf, len, file->fp) != NULL) {
		buf[strcspn(buf, "\n")] = '\0';
		return (1);
	}

	if (ferror(file->fp))
		fatal("I/O error while reading '%s'", file->path);

	/* assumes EOF. */
	return (0);
}

static void
file_consume_newline(struct file *file)
{
	char		buf[512];

	if (!file_read_line(file, buf, sizeof(buf)))
		fatal("expected newline, got eof in '%s'", file->path);

	if (buf[0] != '\0')
		fatal("expected newline, got '%s' in '%s'", buf, file->path);
}

static void
file_parse(struct context *ctx, const char *path)
{
	struct file		file;
	struct entry		*entry;
	struct topic		*topic;
	size_t			newsz, idx;
	const char		*context, *errstr;
	u_int8_t		digest[SHA256_DIGEST_LENGTH];
	char			buf[512], name[64], *p, **lc;
	int			len, indent, pos, line, order;

	file_open(&file, path, "r");

	line = 0;
	lc = NULL;

	while (file_read_line(&file, buf, sizeof(buf))) {
		newsz = sizeof(char *) * (line + 1);
		if ((lc = realloc(lc, newsz)) == NULL)
			fatal("realloc(%zu): %s", newsz, strerror(errno));

		if ((lc[line++] = strdup(buf)) == NULL)
			fatal("strdup: %s", strerror(errno));

		if ((p = strstr(buf, TAG_OPEN)) == NULL)
			continue;

		context = NULL;
		if (line > 0) {
			pos = line - 1;
			while (pos >= 0) {
				if (isalpha(*(unsigned char *)lc[pos]) ||
				    lc[pos][0] == '_') {
					context = lc[pos];
					break;
				}
				pos--;
			}
		}

		p += sizeof(TAG_OPEN) - 1;
		memset(name, 0, sizeof(name));

		if (sscanf(p, " topic=%63s", name) != 1) {
			fprintf(stderr, "malformed %s in %s:%d\n",
			    TAG_OPEN, path, line);
			continue;
		}

		order = -1;
		if ((p = strchr(name, ':')) != NULL) {
			*(p)++ = '\0';

			errstr = NULL;
			order = strtonum(p, 0, USHRT_MAX, &errstr);
			if (errstr != NULL) {
				fprintf(stderr, "malformed topic in %s:%d\n",
				    path, line);
				continue;
			}
		}

		topic = topic_resolve(ctx, name);
		entry = topic_record_entry(ctx, topic, path, context, order);

		indent = -1;
		entry->line_start = line + 1;

		for (;;) {
			if (!file_read_line(&file, buf, sizeof(buf)))
				fatal("EOF in '%s' before end section", path);

			newsz = sizeof(char *) * (line + 1);
			if ((lc = realloc(lc, newsz)) == NULL) {
				fatal("realloc(%zu): %s", newsz,
				    strerror(errno));
			}

			if ((lc[line++] = strdup(buf)) == NULL)
				fatal("strdup: %s", strerror(errno));

			if (strstr(buf, TAG_CLOSE))
				break;

			p = buf;

			if (indent == -1) {
				indent = 0;

				while (*p == '\t') {
					p++;
					indent++;
				}

				if (*p != '\t' && indent > 0)
					p--;
			} else {
				if (strlen(p) > (size_t)indent - 1)
					p += indent - 1;
			}

			entry_record_line(entry, p);
		}

		if (!SHA256_Final(digest, &entry->shactx))
			fatal("failed to calculate digest");

		for (idx = 0; idx < sizeof(digest); idx++) {
			len = snprintf(entry->digest + (idx * 2),
			    sizeof(entry->digest) - (idx * 2), "%02x",
			    digest[idx]);
			if (len == -1 || (size_t)len >= sizeof(entry->digest))
				fatal("failed to create hex digest");
		}

		entry->line_end = line - 1;
	}

	line = line - 1;

	while (line >= 0) {
		free(lc[line]);
		line--;
	}

	free(lc);
	file_close(&file);
}

static struct topic *
topic_resolve(struct context *ctx, const char *name)
{
	struct topic		*topic;

	topic = NULL;

	TAILQ_FOREACH(topic, &ctx->topics, list) {
		if (!strcasecmp(topic->name, name))
			break;
	}

	if (topic == NULL) {
		if ((topic = calloc(1, sizeof(*topic))) == NULL)
			fatal("%s: calloc", __func__);

		if ((topic->name = strdup(name)) == NULL)
			fatal("%s: strdup", __func__);

		TAILQ_INIT(&topic->entries);
		TAILQ_INSERT_TAIL(&ctx->topics, topic, list);
	}

	return (topic);
}

static void
topic_free(struct context *ctx, struct topic *topic)
{
	struct line	*line, *lnext;
	struct entry	*entry, *enext;

	TAILQ_REMOVE(&ctx->topics, topic, list);

	for (entry = TAILQ_FIRST(&topic->entries); entry != NULL;
	    entry = enext) {
		enext = TAILQ_NEXT(entry, list);
		TAILQ_REMOVE(&topic->entries, entry, list);

		for (line = TAILQ_FIRST(&entry->lines); line != NULL;
		    line = lnext) {
			lnext = TAILQ_NEXT(line, list);
			TAILQ_REMOVE(&entry->lines, line, list);

			free(line->code);
			free(line);
		}

		free(entry->context);
		free(entry->file);
		free(entry);
	}

	free(topic->name);
	free(topic);
}

static struct entry *
topic_record_entry(struct context *ctx, struct topic *topic, const char *file,
    const char *context, int order)
{
	const char		*p;
	int			strip;
	struct entry		*entry, *ent;

	if ((entry = calloc(1, sizeof(*entry))) == NULL)
		fatal("%s: calloc failed", __func__);

	p = file;
	strip = ctx->pnum;

	while (strip != 0 && p != NULL) {
		p = strchr(p, '/');
		if (p != NULL)
			p = p + 1;
		strip--;
	}

	if (p == NULL)
		fatal("-p%d doesn't work on '%s'", ctx->pnum, file);

	if ((entry->file = strdup(p)) == NULL)
		fatal("%s: strdup failed", __func__);

	entry->order = order;

	if (!SHA256_Init(&entry->shactx))
		fatal("failed to initialise SHA256 context");

	if (context) {
		if ((p = strchr(context, '(')) == NULL)
			p = context + strlen(context);

		if ((entry->context = strndup(context, p - context)) == NULL)
			fatal("%s: strdup failed", __func__);
	}

	ent = NULL;
	TAILQ_INIT(&entry->lines);

	if (entry->order != -1) {
		TAILQ_FOREACH(ent, &topic->entries, list) {
			if (ent->order > entry->order) {
				TAILQ_INSERT_BEFORE(ent, entry, list);
				break;
			}
		}
	}

	if (ent == NULL)
		TAILQ_INSERT_TAIL(&topic->entries, entry, list);

	return (entry);
}

static void
entry_record_line(struct entry *entry, const char *code)
{
	struct line	*line;

	if ((line = calloc(1, sizeof(*line))) == NULL)
		fatal("%s: calloc", __func__);

	if ((line->code = strdup(code)) == NULL)
		fatal("%s: strdup", __func__);

	if (!SHA256_Update(&entry->shactx, code, strlen(code)))
		fatal("failed to update digest");

	TAILQ_INSERT_TAIL(&entry->lines, line, list);
}

static int
entry_check_state(struct entry_list *head, struct entry *orig,
    struct entry **out)
{
	struct entry	*entry;
	int		a, b, state;

	TAILQ_FOREACH(entry, head, list) {
		if (strcmp(orig->file, entry->file))
			continue;

		*out = entry;

		a = MAX(orig->line_start, entry->line_start);
		b = MIN(orig->line_end, entry->line_end);

		if (a <= b) {
			if (!strcmp(entry->digest, orig->digest)) {
				state = ENTRY_STATE_SAME;
				if (orig->line_start != entry->line_start)
					return (state | ENTRY_STATE_MOVED);
				return (state);
			}

			if (orig->line_start == entry->line_start)
				return (ENTRY_STATE_DIFFERS);

			return (ENTRY_STATE_DIFFERS | ENTRY_STATE_MOVED);
		}

		if (!strcmp(entry->digest, orig->digest))
			return (ENTRY_STATE_SAME | ENTRY_STATE_MOVED);
	}

	*out = NULL;

	return (ENTRY_STATE_GONE);
}

static void
text_topic_dump(struct context *ctx)
{
	struct topic		*topic, *next;

	for (topic = TAILQ_FIRST(&ctx->topics); topic != NULL; topic = next) {
		next = TAILQ_NEXT(topic, list);

		if (ctx->list) {
			if (ctx->full)
				text_topic_write(ctx, topic);
			else
				text_topic_header(ctx, topic);

			continue;
		}

		if (ctx->query == NULL ||
		    fnmatch(ctx->query, topic->name, FNM_NOESCAPE) == 0)
			text_topic_write(ctx, topic);

		topic_free(ctx, topic);
	}
}

static void
text_topic_header(struct context *ctx, struct topic *topic)
{
	if (!ctx->list || ctx->full)
		printf("@ ");

	printf("%s", topic->name);

	printf("\n");
}

static void
text_topic_write(struct context *ctx, struct topic *topic)
{
	struct line		*line;
	const char		*last;
	struct entry		*entry;

	text_topic_header(ctx, topic);

	if (!ctx->list || ctx->full)
		printf("\n");

	last = NULL;

	TAILQ_FOREACH(entry, &topic->entries, list) {
		if (ctx->list) {
			if (ctx->digest)
				printf("%s:", entry->digest);
			printf("%s:%d-%d", entry->file,
			    entry->line_start, entry->line_end);
			if (entry->context)
				printf(":%s", entry->context);
			printf("\n");
			continue;
		}

		if (last == NULL || strcmp(last, entry->file)) {
			printf("File: %s\n", entry->file);
			printf("%s\n", FILE_SEPARATOR);
			last = entry->file;
		}

		printf("@@ %d-%d @@", entry->line_start, entry->line_end);

		if (entry->context)
			printf(" %s ", entry->context);
		else
			printf(" ");

		if (entry->order != -1)
			printf("(%d)\n", entry->order);
		else
			printf("\n");

		TAILQ_FOREACH(line, &entry->lines, list)
			printf("%s\n", line->code);

		printf("\n");
	}

	if (ctx->list)
		printf("\n");
}

static int
filecmp(const FTSENT **a1, const FTSENT **b1)
{
	const FTSENT	*a = *a1;
	const FTSENT	*b = *b1;

	return (strcmp(a->fts_name, b->fts_name));
}

static void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");
	exit(1);
}
