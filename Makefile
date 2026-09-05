# Makefile – minimal portable build for host testing
# On embedded targets you normally replace this with your own toolchain make.

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -std=c11
LDFLAGS ?=

PREFIX  ?= ./build
OBJDIR  := $(PREFIX)/obj
BINDIR  := $(PREFIX)/bin

$(shell mkdir -p $(OBJDIR)/src/core $(OBJDIR)/src/cli $(OBJDIR)/src/platform $(OBJDIR)/examples)

SRCS_LIB := src/core/libscan_core.c src/platform/platform.c
OBJS_LIB := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS_LIB))

CLI_SRC  := src/cli/cli.c
CLI_OBJ  := $(OBJDIR)/src/cli/cli.o

EXAMPLE_SRC := examples/example.c
EXAMPLE_OBJ := $(OBJDIR)/examples/example.o

INC      := -I include

.PHONY: all clean cli example

all: $(PREFIX)/lib/libscan.a $(BINDIR)/libscan_cli

$(OBJDIR)/%.o: %.c | $(OBJDIR)/$(dir $@)
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(PREFIX)/lib/libscan.a: $(OBJS_LIB) | $(PREFIX)/lib
	ar rcs $@ $(OBJS_LIB)

$(BINDIR)/libscan_cli: $(CLI_OBJ) $(PREFIX)/lib/libscan.a | $(BINDIR)
	$(CC) $(CFLAGS) $(CLI_OBJ) -L $(PREFIX)/lib -lscan -o $@ $(LDFLAGS)

$(BINDIR)/example: $(EXAMPLE_OBJ) $(PREFIX)/lib/libscan.a | $(BINDIR)
	$(CC) $(CFLAGS) $(EXAMPLE_OBJ) -L $(PREFIX)/lib -lscan -o $@ $(LDFLAGS)

$(OBJDIR) $(PREFIX)/lib $(BINDIR):
	mkdir -p $@

$(OBJDIR)/src/core $(OBJDIR)/src/cli $(OBJDIR)/src/platform $(OBJDIR)/examples:
	mkdir -p $@

cli: $(BINDIR)/libscan_cli

example: $(BINDIR)/example

clean:
	rm -rf $(PREFIX)
