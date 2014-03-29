# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.

CC = clang
LD = clang

ARCH = arch_x86_64

WARNFLAGS = -pedantic -Wall -Wextra -Werror -Wunreachable-code \
	-Wgcc-compat -Wmissing-declarations
INCFLAGS = -Isrc/include -Iinclude -Isrc/$(ARCH)
LANGFLAGS = -std=c99
GENFLAGS = -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC
OFLAGS = -O3
#XFLAGS = -DN_TESTS_BASE=1000
ARCHFLAGS = -mssse3 -maes -mavx2 -DMUST_HAVE_AVX2 -mbmi2
#ARCHFLAGS = -m32 -mcpu=cortex-a9 -mfpu=vfpv3-d16

CFLAGS = $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XFLAGS)
LDFLAGS = $(ARCHFLAGS)
ASFLAGS = $(ARCHFLAGS)

.PHONY: clean all test bench todo doc lib
.PRECIOUS: build/%.s

HEADERS= Makefile $(shell find . -name "*.h") build/timestamp

LIBCOMPONENTS= build/goldilocks.o build/barrett_field.o build/crandom.o \
  build/p448.o build/ec_point.o build/scalarmul.o build/sha512.o

TESTCOMPONENTS=build/test.o build/test_scalarmul.o build/test_sha512.o \
	build/test_pointops.o

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
	$(LD) $(LDFLAGS) -o $@ $^

lib: build/goldilocks.so

build/goldilocks.so: $(LIBCOMPONENTS)
	rm -f $@
	libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  -exported_symbols_list src/exported.sym \
		  $(LIBCOMPONENTS)

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
		'HACK|TODO|FIXME|BUG|XXX|PERF|FUTURE|REMOVE'
	@echo '============================='
	@(for i in FIXME BUG XXX TODO HACK PERF FUTURE REMOVE; do \
	  (find * -name '*.h'; find * -name '*.c') | xargs egrep -w $$i > /dev/null || continue; \
	  /bin/echo -n $$i'       ' | head -c 10; \
	  (find * -name '*.h'; find * -name '*.c') | xargs egrep -w $$i| wc -l; \
	done)
	@echo '============================='
	@echo -n 'Total     '
	@(find * -name '*.h'; find * -name '*.c') | xargs egrep -w \
		'HACK|TODO|FIXME|BUG|XXX|PERF|FUTURE|REMOVE' | wc -l

bench: build/bench
	./$<

test: build/test
	./$<

clean:
	rm -fr build doc
