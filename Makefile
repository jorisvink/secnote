# secnote Makefile

BIN=secnote
CC?=cc
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin
MAN_DIR?=$(PREFIX)/share/man

SRC=	secnote.c

CFLAGS+=-Wall -Wextra -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare -std=c99 -pedantic
CFLAGS+=-fsanitize=address -fstack-protector-all

CFLAGS+=$(shell pkg-config openssl --cflags)

LDFLAGS+=-fsanitize=address
LDFLAGS+=$(shell pkg-config openssl --libs)

OBJS=	$(SRC:%.c=%.o)

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

install:
	mkdir -p $(INSTALL_DIR)
	install -m 555 $(BIN) $(INSTALL_DIR)/$(BIN)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BIN) $(OBJS)

.PHONY: all clean
