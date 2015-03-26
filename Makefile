# Copyright (c) 2014 Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.


UNAME := $(shell uname)
MACHINE := $(shell uname -m)

ifeq ($(UNAME),Darwin)
CC = clang
CXX = clang++
else
CC = gcc
CXX = g++
endif
LD = $(CC)
LDXX = $(CXX)
ASM ?= $(CC)

DECAF ?= decaf

ifneq (,$(findstring x86_64,$(MACHINE)))
ARCH ?= arch_x86_64
else
# no i386 port yet
ARCH ?= arch_arm_32
endif

FIELD ?= p448

WARNFLAGS = -pedantic -Wall -Wextra -Werror -Wunreachable-code \
	 -Wmissing-declarations -Wunused-function -Wno-overlength-strings $(EXWARN)
	 
	 
INCFLAGS = -Isrc/include -Iinclude -Isrc/$(FIELD) -Isrc/$(FIELD)/$(ARCH)
LANGFLAGS = -std=c99 -fno-strict-aliasing
LANGXXFLAGS = -fno-strict-aliasing
GENFLAGS = -ffunction-sections -fdata-sections -fvisibility=hidden -fomit-frame-pointer -fPIC
OFLAGS = -O3

TODAY = $(shell date "+%Y-%m-%d")

ifneq (,$(findstring arm,$(MACHINE)))
ifneq (,$(findstring neon,$(ARCH)))
ARCHFLAGS += -mfpu=neon
else
ARCHFLAGS += -mfpu=vfpv3-d16
endif
ARCHFLAGS += -mcpu=cortex-a8 # FIXME
GENFLAGS += -DN_TESTS_BASE=1000 # sooooo sloooooow
else
ARCHFLAGS += -maes -mavx2 -mbmi2 #TODO
endif

ifeq ($(CC),clang)
WARNFLAGS += -Wgcc-compat
endif

ifeq (,$(findstring 64,$(ARCH))$(findstring gcc,$(CC)))
# ARCHFLAGS += -m32
XCFLAGS += -DGOLDI_FORCE_32_BIT=1
endif

ARCHFLAGS += $(XARCHFLAGS)
CFLAGS  = $(LANGFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
CXXFLAGS = $(LANGXXFLAGS) $(WARNFLAGS) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCXXFLAGS) 
LDFLAGS = $(ARCHFLAGS) $(XLDFLAGS)
ASFLAGS = $(ARCHFLAGS) $(XASFLAGS)

.PHONY: clean all test bench todo doc lib bat
.PRECIOUS: build/%.s

HEADERS= Makefile $(shell find . -name "*.h") $(shell find . -name "*.hxx") build/timestamp

LIBCOMPONENTS= build/goldilocks.o build/barrett_field.o build/crandom.o \
  build/$(FIELD).o build/ec_point.o build/scalarmul.o build/sha512.o build/magic.o \
	build/f_arithmetic.o build/arithmetic.o


DECAFCOMPONENTS= build/$(DECAF).o build/shake.o build/decaf_crypto.o \
	build/$(FIELD).o build/f_arithmetic.o # TODO
ifeq ($(DECAF),decaf_fast)
DECAFCOMPONENTS += build/decaf_tables.o
endif

TESTCOMPONENTS=build/test.o build/test_scalarmul.o build/test_sha512.o \
	build/test_pointops.o build/test_arithmetic.o build/test_goldilocks.o build/magic.o \
	build/shake.o

TESTDECAFCOMPONENTS=build/test_decaf.o

BENCHCOMPONENTS = build/bench.o build/shake.o

BATBASE=ed448goldilocks-bats-$(TODAY)
BATNAME=build/$(BATBASE)

all: lib decaf_lib build/test build/bench build/shakesum

scan: clean
	scan-build --use-analyzer=`which clang` \
		 -enable-checker deadcode -enable-checker llvm \
		 -enable-checker osx -enable-checker security -enable-checker unix \
		make build/bench build/test all

build/bench: $(LIBCOMPONENTS) $(BENCHCOMPONENTS) $(DECAFCOMPONENTS)
	$(LD) $(LDFLAGS) -o $@ $^

build/test: $(LIBCOMPONENTS) $(TESTCOMPONENTS) $(DECAFCOMPONENTS)
	$(LD) $(LDFLAGS) -o $@ $^ -lgmp

build/test_decaf: $(TESTDECAFCOMPONENTS) decaf_lib
	$(LDXX) $(LDFLAGS) -o $@ $< -lgmp -Lbuild -ldecaf
	
build/shakesum: build/shakesum.o build/shake.o
	$(LD) $(LDFLAGS) -o $@ $^

lib: build/libgoldilocks.so

decaf_lib: build/libdecaf.so

build/libgoldilocks.so: $(LIBCOMPONENTS)
	rm -f $@
ifeq ($(UNAME),Darwin)
	libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  $(LIBCOMPONENTS)
else
	$(LD) $(LDFLAGS) -shared -Wl,-soname,libgoldilocks.so.1 -Wl,--gc-sections -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
	ln -sf `basename $@` build/libgoldilocks.so.1
endif


build/libdecaf.so: $(DECAFCOMPONENTS)
	rm -f $@
ifeq ($(UNAME),Darwin)
	libtool -macosx_version_min 10.6 -dynamic -dead_strip -lc -x -o $@ \
		  $(DECAFCOMPONENTS)
else
	$(LD) $(LDFLAGS) -shared -Wl,-soname,libdecaf.so.1 -Wl,--gc-sections -o $@ $(DECAFCOMPONENTS)
	strip --discard-all $@
	ln -sf `basename $@` build/libdecaf.so.1
endif

build/timestamp:
	mkdir -p build
	touch $@

build/%.o: build/%.s
	$(ASM) $(ASFLAGS) -c -o $@ $<

build/decaf_gen_tables: build/decaf_gen_tables.o build/$(DECAF).o build/$(FIELD).o build/f_arithmetic.o
	$(LD) $(LDFLAGS) -o $@ $^
	
build/decaf_tables.c: build/decaf_gen_tables
	./$< > $@
	
build/decaf_tables.s: build/decaf_tables.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<
	
build/%.s: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<
	
build/%.s: src/%.cxx $(HEADERS)
	$(CXX) $(CXXFLAGS) -S -c -o $@ $<

build/%.s: test/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/%.s: test/%.cxx $(HEADERS)
	$(CXX) $(CXXFLAGS) -S -c -o $@ $<

build/%.s: src/$(FIELD)/$(ARCH)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

build/%.s: src/$(FIELD)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -S -c -o $@ $<

doc/timestamp:
	mkdir -p doc
	touch $@

doc: Doxyfile doc/timestamp include/*.h src/*.c src/include/*.h src/$(FIELD)/$(ARCH)/*.c src/$(FIELD)/$(ARCH)/*.h
	doxygen

bat: $(BATNAME)

$(BATNAME): include/* src/* src/*/* test/batarch.map
	rm -fr $@
	for prim in dh sign; do \
          targ="$@/crypto_$$prim/ed448goldilocks"; \
	  (while read arch where; do \
	    mkdir -p $$targ/`basename $$arch`; \
	    cp include/*.h src/*.c src/include/*.h src/bat/$$prim.c src/p448/$$where/*.c src/p448/$$where/*.h src/p448/*.c src/p448/*.h $$targ/`basename $$arch`; \
	    cp src/bat/api_$$prim.h $$targ/`basename $$arch`/api.h; \
	    perl -p -i -e 's/.*endif.*GOLDILOCKS_CONFIG_H/#define SUPERCOP_WONT_LET_ME_OPEN_FILES 1\n\n$$&/' $$targ/`basename $$arch`/config.h; \
	    perl -p -i -e 's/SYSNAME/'`basename $(BATNAME)`_`basename $$arch`'/g' $$targ/`basename $$arch`/api.h;  \
	    perl -p -i -e 's/__TODAY__/'$(TODAY)'/g' $$targ/`basename $$arch`/api.h;  \
	    done \
	  ) < test/batarch.map; \
	  echo 'Mike Hamburg' > $$targ/designers; \
	  echo 'Ed448-Goldilocks sign and dh' > $$targ/description; \
        done
	(cd build && tar czf $(BATBASE).tgz $(BATBASE) )
	

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

test: build/test test_decaf
	build/test
	
test_decaf: build/test_decaf
	LD_LIBRARY_PATH=`pwd`/build:$(LD_LIBRARY_PATH) build/test_decaf

clean:
	rm -fr build doc $(BATNAME)
