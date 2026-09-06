# Makefile – portable host build.  Embedded integrations can compile the
# library sources with their own toolchain instead of building the CLI.

CC       ?= cc
AR       ?= ar
CPPFLAGS ?= -Iinclude
CFLAGS   ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS  ?=
LDLIBS   ?=

PREFIX ?= build
OBJDIR := $(PREFIX)/obj
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
LIB    := $(LIBDIR)/libscan.a

SRCS_LIB := src/core/libscan_core.c src/platform/platform.c
OBJS_LIB := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS_LIB))

CLI_SRC     := src/cli/cli.c
CLI_OBJ     := $(OBJDIR)/src/cli/cli.o
EXAMPLE_SRC := examples/example.c
EXAMPLE_OBJ := $(OBJDIR)/examples/example.o
CORE_TEST   := $(BINDIR)/libscan_core_api_test
PLATFORM_TEST := $(BINDIR)/libscan_platform_test

DEPS := $(OBJS_LIB:.o=.d) $(CLI_OBJ:.o=.d) $(EXAMPLE_OBJ:.o=.d)

.PHONY: all clean cli example library test

all: library cli example

library: $(LIB)
cli: $(BINDIR)/libscan_cli
example: $(BINDIR)/example
test: $(CORE_TEST) $(PLATFORM_TEST)
	$(CORE_TEST)
	$(PLATFORM_TEST)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(LIB): $(OBJS_LIB)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(BINDIR)/libscan_cli: $(CLI_OBJ) $(LIB)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $(CLI_OBJ) $(LIB) $(LDLIBS)

$(BINDIR)/example: $(EXAMPLE_OBJ) $(LIB)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $(EXAMPLE_OBJ) $(LIB) $(LDLIBS)

$(CORE_TEST): src/core/libscan_core.c tests/core_api_test.c include/libscan.h include/platform.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ \
		src/core/libscan_core.c tests/core_api_test.c $(LDLIBS)

$(PLATFORM_TEST): src/platform/platform.c tests/platform_test.c include/libscan.h include/platform.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ \
		src/platform/platform.c tests/platform_test.c $(LDLIBS)

clean:
	$(RM) -r $(PREFIX)

-include $(DEPS)
