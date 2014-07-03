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

ifneq (,$(findstring x86_64,$(MACHINE)))
ARCH ?= arch_x86_64
else
# no i386 port yet
ARCH ?= arch_arm_32
endif


WARNFLAGS = -pedantic -Wall -Wextra -Weverything -Wpedantic -Wunreachable-code \
	 -Wmissing-declarations -Wunused-function -Wno-documentation -Wno-padded $(EXWARN)
INCFLAGS = -Isrc/include -Iinclude -Isrc/$(ARCH)
LANGFLAGS = -std=c11
GENFLAGS = -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC
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
#ARCHFLAGS += -mssse3 -maes -mavx -mavx2 -DMUST_HAVE_AVX2 -mbmi2 #TODO
ARCHFLAGS += -march=native
endif

ifeq ($(CC),clang)
WARNFLAGS += -Wgcc-compat
endif

ifeq (,$(findstring 64,$(ARCH))$(findstring gcc,$(CC)))
# ARCHFLAGS += -m32
ARCHFLAGS += -DGOLDI_FORCE_32_BIT=1
endif

CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
LDFLAGS = $(ARCHFLAGS) $(XLDFLAGS)
ASFLAGS = $(ARCHFLAGS)

.PHONY: clean all test bench todo doc lib
.PRECIOUS: build/%.s

HEADERS= Makefile $(shell find . -name "*.h") build/timestamp

LIBCOMPONENTS= build/goldilocks.o build/barrett_field.o build/crandom.o \
  build/p448.o build/ec_point.o build/scalarmul.o build/sha512.o

TESTCOMPONENTS=build/test.o build/test_scalarmul.o build/test_sha512.o \
	build/test_pointops.o build/test_arithmetic.o build/test_goldilocks.o

BENCHCOMPONENTS=build/bench.o

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
	libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  $(LIBCOMPONENTS)
else
	$(LD) -shared -Wl,-soname,goldilocks.so.1 -Wl,--gc-sections -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
	ln -sf $@ build/goldilocks.so.1
endif

build/timestamp:
	mkdir -p build
	touch $@

build/%.o: build/%.s
	$(CC) $(ASFLAGS) -c -o $@ $<

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
	rm -fr build doc
