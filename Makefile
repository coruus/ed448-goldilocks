# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.

CC = clang
CFLAGS = -O3 -std=c99 -pedantic -Wall -Wextra -Werror  \
  -mssse3 -maes -mavx2 -DMUST_HAVE_AVX2 -mbmi2 \
  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC \
  -DEXPERIMENT_ECDH_OBLITERATE_CT=1 -DEXPERIMENT_ECDH_STIR_IN_PUBKEYS=1

.PHONY: clean all runbench todo doc
.PRECIOUS: build/%.s
	
HEADERS= Makefile $(shell find . -name "*.h") build/timestamp

LIBCOMPONENTS= build/goldilocks.o build/barrett_field.o build/crandom.o \
  build/p448.o build/ec_point.o build/scalarmul.o build/sha512.o

all: bench

bench: *.h *.c
	$(CC) $(CFLAGS) -o $@ *.c
	
build/timestamp:
	mkdir -p build
	touch $@

build/%.o: build/%.s
	$(CC) -c -o $@ $<

build/%.s: %.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/goldilocks.so: $(LIBCOMPONENTS)
	rm -f $@
	libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  -exported_symbols_list exported.sym \
		  $(LIBCOMPONENTS)

doc/timestamp:
	mkdir -p doc
	touch $@

doc: Doxyfile doc/timestamp *.c *.h
	doxygen

todo::
	@egrep --color=auto -w -i 'hack|todo|fixme|bug|xxx|perf|future|remove' *.h *.c
	@echo '============================='
	@(for i in FIXME BUG XXX TODO HACK PERF FUTURE REMOVE; do \
	  egrep -w -i $$i *.h *.c > /dev/null || continue; \
	  /bin/echo -n $$i'       ' | head -c 10; \
	  egrep -w -i $$i *.h *.c | wc -l; \
	done)
	@echo '============================='
	@echo -n 'Total     '
	@egrep -w -i 'hack|todo|fixme|bug|xxx|perf|future|remove' *.h *.c | wc -l

runbench: bench
	./$<

clean:
	rm -fr build bench *.o *.s
