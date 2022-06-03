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
#include <sys/wait.h>
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

#if defined(__linux__)
#include <bsd/bsd.h>
#endif

#define FILE_TYPE_C		1
#define FILE_TYPE_PYTHON	2

#define DUMP_PARSE_TOPIC	1
#define DUMP_PARSE_ENTRY	2

#define ENTRY_STATE_MOVED	(1 << 1)
#define ENTRY_STATE_DIFFERS	(1 << 2)
#define ENTRY_STATE_GONE	(1 << 3)
#define ENTRY_STATE_SAME	(1 << 4)
#define ENTRY_STATE_RENAMED	(1 << 5)

#define FILE_SEPARATOR		\
    "==================================================================="

#define TAG_OPEN		"\x40secnote-open"
#define TAG_CLOSE		"\x40secnote-close"

#define MAX(a, b)		((a > b) ? a : b)
#define MIN(a, b)		((a < b) ? a : b)

struct line {
	char			*code;
	TAILQ_ENTRY(line)	list;
};

struct entry {
	int			order;

	char			*id;
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
	int			type;
	int			line;

	FILE			*fp;
	char			**lc;
	char			*path;
	char			buf[512];
};

struct context {
	int			db;
	int			list;
	int			pnum;
	int			full;
	const char		*query;

	struct topic		*topic;
	struct entry		*entry;

	TAILQ_HEAD(, topic)	topics;
};

static char	*xstrdup(const char *);
static void	fatal(const char *, ...);
static int	filecmp(const FTSENT **, const FTSENT **);

static void	entry_record_line(struct entry *, const char *);
static int	entry_check_state(struct entry_list *, struct entry *,
		    struct entry **);

static int	note_parse_arguments(char *, int *, char **, char **);

static void	file_close(struct file *);
static int	file_read_line(struct file *);
static void	file_consume_newline(struct file *);
static void	file_cache_line(struct file *, char *);
static void	file_parse(struct context *, const char *);
static void	file_open(struct file *, const char *, const char *);

static void	text_topic_dump(struct context *);
static int	text_chunk_new_entries(struct topic *, int *);
static void	text_topic_write(struct context *, struct topic *);
static void	text_topic_header(struct context *, struct topic *);

static void	load_from_dump(struct context *, const char *);
static void	load_from_args(struct context *, int, char **);

static int	dump_parse_topic(struct context *, struct file *);
static int	dump_parse_entry(struct context *, struct file *);

static void	topic_entry_free(struct entry *);
static void	topic_free(struct context *, struct topic *);

static void	context_compare(struct context *, struct context *);

static struct topic	*topic_resolve(struct context *, const char *);
static struct entry	*topic_record_entry(struct context *, struct topic *,
			    const char *, const char *, const char *, int);

static struct {
	const char	*ext;
	int		type;
} extlist[] = {
	{ ".c",		FILE_TYPE_C },
	{ ".h",		FILE_TYPE_C },
	{ ".py",	FILE_TYPE_PYTHON },
	{ NULL,		-1 },
};

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
			ctx.db = 1;
			ctx.list = 1;
			ctx.full = 1;
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
	struct topic		*t1, *t2;
	struct entry		*entry, *ent;
	int			a, b, changes, header, state;

	changes = 0;

	while ((t1 = TAILQ_FIRST(&verify->topics)) != NULL) {
		TAILQ_FOREACH(t2, &ondisk->topics, list) {
			if (!strcmp(t2->name, t1->name))
				break;
		}

		if (t2 == NULL) {
			changes++;
			printf("topic '%s' not found in new code\n", t1->name);
			topic_free(verify, t1);
			if (TAILQ_EMPTY(&verify->topics))
				printf("\n");
			continue;
		}

		header = 0;

		TAILQ_FOREACH(entry, &t1->entries, list) {
			state = entry_check_state(&t2->entries, entry, &ent);

			if (ent != NULL)
				TAILQ_REMOVE(&t2->entries, ent, list);

			if (state == ENTRY_STATE_SAME) {
				if (ent != NULL)
					topic_entry_free(ent);
				continue;
			}

			if (!header) {
				header = 1;
				printf("%s\n", FILE_SEPARATOR);
				printf("%s\n", t1->name);
				printf("%s\n\n", FILE_SEPARATOR);
			}

			printf("    %s in %s:%d-%d\n", entry->id, entry->file,
			    entry->line_start, entry->line_end);

			switch (state) {
			case ENTRY_STATE_RENAMED:
				printf("      - renamed %s -> %s\n",
				    entry->id, ent->id);
				if (ent != NULL)
					topic_entry_free(ent);
				continue;
			case ENTRY_STATE_GONE:
				changes++;
				printf("      - not found\n");
				if (ent != NULL)
					topic_entry_free(ent);
				continue;
			}

			changes++;

			a = entry->line_end - entry->line_start;
			b = ent->line_end - ent->line_start;

			if (state & ENTRY_STATE_MOVED) {
				printf("      - moved to %d-%d\n",
				    ent->line_start, ent->line_end);
			}

			if (entry->context != NULL && ent->context != NULL) {
				if (strcmp(entry->context, ent->context)) {
					printf("      - parent %s -> %s\n",
					    entry->context, ent->context);
				}
			}

			if (state & ENTRY_STATE_DIFFERS) {
				printf("      - modified");

				if (a != b)
					printf(" %+d lines(s)", b - a);

				printf("\n");
			}

			topic_entry_free(ent);

			if (entry != TAILQ_LAST(&t1->entries, entry_list) ||
			    !TAILQ_EMPTY(&t2->entries))
				printf("\n");
		}

		changes += text_chunk_new_entries(t2, &header);

		topic_free(verify, t1);
		topic_free(ondisk, t2);

		if (header) {
			header = 0;
			printf("\n");
		}
	}

	while ((t1 = TAILQ_FIRST(&ondisk->topics)) != NULL) {
		header = 0;
		changes += text_chunk_new_entries(t1, &header);
		topic_free(ondisk, t1);
	}

	if (changes > 0) {
		fatal("%s%d change%s detected",
		    header ? "\n" : "", changes, changes > 1 ? "s" : "");
	}

	printf("secnote identical\n");
}

static void
load_from_args(struct context *ctx, int argc, char **argv)
{
	struct stat		st;
	FTS			*fts;
	FTSENT			*ent;
	int			idx, j;
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

			for (j = 0; extlist[j].ext != NULL; j++) {
				if (!strcmp(extlist[j].ext, ext))
					break;
			}

			if (extlist[j].ext == NULL)
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

	if (!strcmp(path, "-")) {
		file.fp = stdin;
		file.path = "<stdin>";
	} else {
		file_open(&file, path, "r");
	}

	state = DUMP_PARSE_TOPIC;

	while (file_read_line(&file)) {
		switch (state) {
		case DUMP_PARSE_TOPIC:
			state = dump_parse_topic(ctx, &file);
			break;
		case DUMP_PARSE_ENTRY:
			state = dump_parse_entry(ctx, &file);
			break;
		default:
			fatal("invalid parse state %d", state);
		}
	}

	if (file.fp != stdin)
		file_close(&file);
}

static int
dump_parse_topic(struct context *ctx, struct file *file)
{
	if (file->buf[0] != '@' || file->buf[1] != ' ') {
		if (!strcmp(file->buf, "no topics found"))
			return (DUMP_PARSE_TOPIC);
		fatal("expected start of topic, got '%s'", file->buf);
	}

	ctx->topic = topic_resolve(ctx, &file->buf[2]);
	file_consume_newline(file);

	return (DUMP_PARSE_ENTRY);
}

static int
dump_parse_entry(struct context *ctx, struct file *file)
{
	int		count;
	struct entry	*entry;
	char		**ap, *args[12];
	char		*id, *line, *hash, *path, *region, *func;

	if (file->buf[0] == '\0') {
		ctx->topic = NULL;
		ctx->entry = NULL;
		return (DUMP_PARSE_TOPIC);
	}

	count = 0;
	line = file->buf;

	for (ap = args; ap < &args[12] &&
	    (*ap = strsep(&line, ":")) != NULL;) {
		if (**ap != '\0') {
			ap++;
			count++;
		}
	}

	if (count != 4 && count != 5)
		fatal("invalid entry in file '%s' (%d)", file->path, count);

	hash = args[0];
	id = args[1];
	path = args[2];
	region = args[3];

	if (count > 4)
		func = args[4];
	else
		func = NULL;

	entry = topic_record_entry(ctx, ctx->topic, id, path, func, -1);

	if (strlcpy(entry->digest, hash, sizeof(entry->digest)) >=
	    sizeof(entry->digest))
		fatal("invalid hash string '%s' in '%s'", hash, file->path);

	if (sscanf(region, "%d-%d", &entry->line_start, &entry->line_end) != 2)
		fatal("invalid region string '%s' in '%s'", region, file->path);

	ctx->entry = entry;

	return (DUMP_PARSE_ENTRY);
}

static void
file_open(struct file *file, const char *path, const char *mode)
{
	int		i;
	const char	*ext;

	memset(file, 0, sizeof(*file));

	if ((file->fp = fopen(path, mode)) == NULL)
		fatal("fopen(%s): %s", path, strerror(errno));

	file->path = xstrdup(path);

	if ((ext = strrchr(path, '.')) == NULL)
		return;

	for (i = 0; extlist[i].ext != NULL; i++) {
		if (!strcmp(extlist[i].ext, ext)) {
			file->type = extlist[i].type;
			break;
		}
	}
}

static void
file_close(struct file *file)
{
	int		line;

	if (file->line > 0 && file->lc != NULL) {
		line = file->line - 1;

		while (line >= 0) {
			free(file->lc[line]);
			line--;
		}
	}

	fclose(file->fp);

	free(file->lc);
	free(file->path);
}

static void
file_cache_line(struct file *file, char *buf)
{
	size_t		newsz;

	newsz = sizeof(char *) * (file->line + 1);
	if ((file->lc = realloc(file->lc, newsz)) == NULL)
		fatal("realloc(%zu): %s", newsz, strerror(errno));

	file->lc[file->line++] = xstrdup(buf);
}

static int
file_read_line(struct file *file)
{
	if (fgets(file->buf, sizeof(file->buf), file->fp) != NULL) {
		file->buf[strcspn(file->buf, "\n")] = '\0';
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
	if (!file_read_line(file))
		fatal("expected newline, got eof in '%s'", file->path);

	if (file->buf[0] != '\0') {
		fatal("expected newline, got '%s' in '%s'",
		    file->buf, file->path);
	}
}

static void
file_parse(struct context *ctx, const char *path)
{
	size_t			idx;
	struct file		file;
	const char		*func;
	struct entry		*entry;
	struct topic		*topic;
	char			*id, *name, *p, *s;
	int			len, indent, pos, order;
	u_int8_t		digest[SHA256_DIGEST_LENGTH];

	file_open(&file, path, "r");

	while (file_read_line(&file)) {
		file_cache_line(&file, file.buf);

		if ((p = strstr(file.buf, TAG_OPEN)) == NULL)
			continue;

		func = NULL;
		p += sizeof(TAG_OPEN) - 1;

		if (file.line > 0) {
			pos = file.line - 1;
			while (pos >= 0) {
				if (file.type == FILE_TYPE_PYTHON &&
				    ((s = strstr(file.lc[pos], "def ")))) {
					func = s + sizeof("def ") - 1;
					break;
				}
				if (isalpha(*(unsigned char *)file.lc[pos]) ||
				    file.lc[pos][0] == '_') {
					func = file.lc[pos];
					break;
				}
				pos--;
			}
		}

		if (note_parse_arguments(p, &order, &name, &id) == -1) {
			fprintf(stderr, "skipping malformed secnote in %s:%d\n",
			    file.path, file.line);
			continue;
		}

		topic = topic_resolve(ctx, name);
		entry = topic_record_entry(ctx, topic, id, path, func, order);
		if (entry == NULL) {
			fprintf(stderr, "skipping duplicate senote in %s:%d\n",
			    file.path, file.line);
			continue;
		}

		indent = -1;
		entry->line_start = file.line + 1;

		for (;;) {
			if (!file_read_line(&file))
				fatal("EOF in '%s' before end section", path);

			file_cache_line(&file, file.buf);

			if (strstr(file.buf, TAG_CLOSE))
				break;

			p = file.buf;

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

		entry->line_end = file.line - 1;
	}

	file_close(&file);
}

static int
note_parse_arguments(char *note, int *order, char **topic, char **id)
{
	const char	*errstr;
	int		idx, count;
	char		*v, *args[5], **ap, **ptr;

	*id = NULL;
	*order = -1;
	*topic = NULL;

	count = 0;
	for (ap = args; ap < &args[5] &&
	    (*ap = strsep(&note, " ")) != NULL;) {
		if (**ap != '\0') {
			ap++;
			count++;
		}
	}

	for (idx = 0; idx < count; idx++) {
		v = NULL;
		ptr = NULL;

		if (!strncmp(args[idx], "topic=", sizeof("topic=") - 1))
			ptr = topic;

		if (!strncmp(args[idx], "id=", sizeof("id=") - 1))
			ptr = id;

		if (ptr == NULL)
			continue;

		if ((v = strchr(args[idx], '=')) == NULL)
			fatal("failure to find '=' unexpected");

		*(v)++ = '\0';
		*ptr = v;
	}

	if (*topic == NULL || *id == NULL)
		return (-1);

	if ((v = strchr(*topic, ':')) != NULL) {
		*(v)++ = '\0';

		errstr = NULL;
		*order = strtonum(v, 0, USHRT_MAX, &errstr);
		if (errstr != NULL)
			return (-1);
	}

	return (0);
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

		topic->name = xstrdup(name);
		TAILQ_INIT(&topic->entries);

		TAILQ_INSERT_TAIL(&ctx->topics, topic, list);
	}

	return (topic);
}

static void
topic_free(struct context *ctx, struct topic *topic)
{
	struct entry	*entry;

	TAILQ_REMOVE(&ctx->topics, topic, list);

	while ((entry = TAILQ_FIRST(&topic->entries)) != NULL) {
		TAILQ_REMOVE(&topic->entries, entry, list);
		topic_entry_free(entry);
	}

	free(topic->name);
	free(topic);
}

static void
topic_entry_free(struct entry *entry)
{
	struct line	*line;

	while ((line = TAILQ_FIRST(&entry->lines)) != NULL) {
		TAILQ_REMOVE(&entry->lines, line, list);
		free(line->code);
		free(line);
	}

	free(entry->context);
	free(entry->id);
	free(entry->file);
	free(entry);
}

static struct entry *
topic_record_entry(struct context *ctx, struct topic *topic, const char *id,
    const char *file, const char *context, int order)
{
	int			strip;
	const char		*p, *s;
	struct entry		*entry, *ent;

	TAILQ_FOREACH(entry, &topic->entries, list) {
		if (!strcmp(entry->id, id)) {
			fprintf(stderr,
			    "duplicate id '%s' in file %s for topic '%s', ",
			    id, file, topic->name);
			fprintf(stderr, "previously used in file %s:%d\n",
			    entry->file, entry->line_start);
			return (NULL);
		}
	}

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
		fatal("-p%d makes no sense with '%s'", ctx->pnum, file);

	entry->id = xstrdup(id);
	entry->file = xstrdup(p);

	if (context) {
		s = context;
		while (isspace(*(const unsigned char *)s))
			s++;

		if ((p = strchr(s, '(')) == NULL)
			p = s + strlen(s);

		if ((entry->context = strndup(s, p - s)) == NULL)
			fatal("%s: strdup failed", __func__);
	}

	entry->order = order;

	if (!SHA256_Init(&entry->shactx))
		fatal("failed to initialise SHA256 context");

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

	line->code = xstrdup(code);

	if (!SHA256_Update(&entry->shactx, code, strlen(code)))
		fatal("failed to update digest");

	TAILQ_INSERT_TAIL(&entry->lines, line, list);
}

static int
entry_check_state(struct entry_list *head, struct entry *orig,
    struct entry **out)
{
	int		state;
	struct entry	*entry;

	*out = NULL;
	state = ENTRY_STATE_GONE;

	TAILQ_FOREACH(entry, head, list) {
		if (strcmp(orig->file, entry->file))
			continue;

		/* @secnote-open topic=note-matching id=match-id */
		/*
		 * Attemp to the match the ID of the note to resolve it.
		 * If it does not match but we see the note is otherwise
		 * the same, we mark it as renamed.
		 */
		if (strcmp(orig->id, entry->id)) {
			if (orig->line_start == entry->line_start &&
			    orig->line_end == entry->line_end &&
			    !strcmp(orig->digest, entry->digest)) {
				*out = entry;
				return (ENTRY_STATE_RENAMED);
			}

			continue;
		}
		/* @secnote-close */

		state = 0;
		*out = entry;

		/* @secnote-open topic=note-matching id=match-position */
		/*
		 * If the note moved start or end line it was considered
		 * moved from the original note.
		 */
		if (orig->line_start != entry->line_start ||
		    orig->line_end != entry->line_end)
			state |= ENTRY_STATE_MOVED;
		/* @secnote-close */

		/* @secnote-open topic=note-matching id=match-digest */
		/*
		 * Finally if the digest matches the original note its
		 * digest we know it has not changed contents.
		 */
		if (!strcmp(entry->digest, orig->digest))
			state |= ENTRY_STATE_SAME;
		else
			state |= ENTRY_STATE_DIFFERS;
		/* @secnote-close */

		break;
	}

	if (state == ENTRY_STATE_GONE)
		*out = NULL;

	return (state);
}

static int
text_chunk_new_entries(struct topic *topic, int *header)
{
	int		new;
	struct entry	*entry;

	new = 0;

	TAILQ_FOREACH(entry, &topic->entries, list) {
		if (*header == 0) {
			*header = 1;
			printf("%s\n", FILE_SEPARATOR);
			printf("%s\n", topic->name);
			printf("%s\n\n", FILE_SEPARATOR);
		}

		new++;
		printf("    %s in %s:%d-%d\n      - new\n", entry->id,
		    entry->file, entry->line_start, entry->line_end);
	}

	return (new);
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
			if (ctx->db)
				printf("%s:%s:", entry->digest, entry->id);
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

		printf("@@ %s %d-%d @@ ", entry->id,
		    entry->line_start, entry->line_end);

		if (entry->context)
			printf("%s ", entry->context);

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

static char *
xstrdup(const char *str)
{
	char	*ptr;

	if ((ptr = strdup(str)) == NULL)
		fatal("strdup: %s", strerror(errno));

	return (ptr);
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
