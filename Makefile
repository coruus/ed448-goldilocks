# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.


UNAME := $(shell uname)
MACHINE := $(shell uname -m)

ifeq ($(UNAME),Darwin)
CC = clang
else
CC = gcc
endif
LD = $(CC)
ASM ?= $(CC)

ifneq (,$(findstring x86_64,$(MACHINE)))
ARCH ?= arch_x86_64
else
# no i386 port yet
ARCH ?= arch_arm_32
endif


WARNFLAGS = -pedantic -Wall -Wextra -Werror -Wunreachable-code \
	 -Wmissing-declarations -Wunused-function $(EXWARN)


INCFLAGS = -Isrc/include -Iinclude -Isrc/$(ARCH)
LANGFLAGS = -std=c11 -D__STDC_WANT_LIB_EXT1__=1
SANFLAGS = #-fsanitize=address-full -fsanitize=undefined
GENFLAGS = $(SANFLAGS) -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC
OFLAGS = -O3

ifneq (,$(findstring arm,$(MACHINE)))
ifneq (,$(findstring neon,$(ARCH)))
ARCHFLAGS += -mfpu=neon
else
ARCHFLAGS += -mfpu=vfpv3-d16
endif
ARCHFLAGS += -mcpu=cortex-a9 # FIXME
GENFLAGS = -DN_TESTS_BASE=1000 # sooooo sloooooow
else
ARCHFLAGS += -march=native#-mavx2 -mbmi2 #TODO
endif

ifeq ($(CC),clang)
WARNFLAGS += -Wgcc-compat
endif

ifeq (,$(findstring 64,$(ARCH))$(findstring gcc,$(CC)))
# ARCHFLAGS += -m32
XCFLAGS += -DGOLDI_FORCE_32_BIT=1
endif

CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
LDFLAGS = $(ARCHFLAGS) $(XLDFLAGS) $(SANFLAGS)
ASFLAGS = $(ARCHFLAGS)

.PHONY: clean all test bench todo doc lib bat
.PRECIOUS: build/%.s

HEADERS= Makefile $(shell find . -name "*.h") build/timestamp

LIBCOMPONENTS= build/goldilocks.o build/barrett_field.o build/crandom.o \
  build/p448.o build/ec_point.o build/scalarmul.o build/magic.o build/libkeccak.dylib

TESTCOMPONENTS=build/test.o build/test_scalarmul.o  \
	build/test_pointops.o build/test_arithmetic.o build/test_goldilocks.o build/magic.o

BENCHCOMPONENTS=build/bench.o

BATNAME=build/ed448-goldilocks

all: lib build/test build/bench

scan: clean
	scan-build --use-analyzer=`which clang` \
		 -enable-checker deadcode -enable-checker llvm \
		 -enable-checker osx -enable-checker security -enable-checker unix \
		make build/bench build/test build/goldilocks.so

build/bench: $(LIBCOMPONENTS) $(BENCHCOMPONENTS)
	$(LD) $(LDFLAGS) -o $@ $^

build/test: $(LIBCOMPONENTS) $(TESTCOMPONENTS)
	$(LD) $(LDFLAGS) -o $@ $^ -lgmp

lib: build/goldilocks.so

build/goldilocks.so: $(LIBCOMPONENTS)
	rm -f $@
ifeq ($(UNAME),Darwin)
	#libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  $(LIBCOMPONENTS)
	clang -shared $(SANFLAGS) -o $@ $(LIBCOMPONENTS)
else
	$(LD) -shared -Wl,-soname,goldilocks.so.1 -Wl,--gc-sections -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
	ln -sf $@ build/goldilocks.so.1
endif

build/timestamp:
	mkdir -p build
	touch $@

build/%.o: build/%.s
	$(ASM) $(ASFLAGS) -c -o $@ $<

build/%.s: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/%.s: test/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/%.s: src/$(ARCH)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

doc/timestamp:
	mkdir -p doc
	touch $@

doc: Doxyfile doc/timestamp src/*.c src/include/*.h src/$(ARCH)/*.c src/$(ARCH)/*.h
	doxygen

bat: $(BATNAME)

$(BATNAME): include/* src/* src/*/*
	rm -fr $@
	for arch in src/arch*; do \
		mkdir -p $@/`basename $$arch`; \
		cp include/* src/*.c src/include/* $$arch/* $@/`basename $$arch`; \
		perl -p -i -e 's/.*endif.*GOLDILOCKS_CONFIG_H/#define SUPERCOP_WONT_LET_ME_OPEN_FILES 1\n\n$$&/' $@/`basename $$arch`/config.h; \
		done
	echo 'Mike Hamburg' > $@/designers
	echo 'Ed448-Goldilocks sign and dh' > $@/description


todo::
	@(find * -name '*.h'; find * -name '*.c') | xargs egrep --color=auto -w \
		'HACK|TODO|FIXME|BUG|XXX|PERF|FUTURE|REMOVE|MAGIC'
	@echo '============================='
	@(for i in FIXME BUG XXX TODO HACK PERF FUTURE REMOVE MAGIC; do \
	  (find * -name '*.h'; find * -name '*.c') | xargs egrep -w $$i > /dev/null || continue; \
	  /bin/echo -n $$i'       ' | head -c 10; \
	  (find * -name '*.h'; find * -name '*.c') | xargs egrep -w $$i| wc -l; \
	done)
	@echo '============================='
	@echo -n 'Total     '
	@(find * -name '*.h'; find * -name '*.c') | xargs egrep -w \
		'HACK|TODO|FIXME|BUG|XXX|PERF|FUTURE|REMOVE|MAGIC' | wc -l

bench: build/bench
	./$<

test: build/test
	./$<

clean:
	rm -fr build doc $(BATNAME)
