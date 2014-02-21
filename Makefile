# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.

CC = clang
CFLAGS = -O3 -std=c99 -pedantic -Wall -Wextra -Werror  \
  -mavx2 -DMUST_HAVE_SSSE3 -mbmi2 \
  -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC

.PHONY: clean all runbench
.PRECIOUS: build/%.s
	
HEADERS= Makefile $(shell find . -name "*.h") build/timestamp

LIBCOMPONENTS= build/goldilocks.o build/barrett_field.o build/crandom.o \
  build/p448.o build/ec_point.o build/scalarmul.o

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
	
runbench: bench
	./$<

clean:
	rm -fr build bench *.o *.s
