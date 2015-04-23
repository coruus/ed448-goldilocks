Ed448-Goldilocks, Decaf version.

This software is an experimental implementation of a new 448-bit elliptic
curve called Ed448-Goldilocks, with "Decaf" cofactor removal.

The source files here are all by Mike Hamburg. Most of them are (c)
2014-2015 Cryptography Research, Inc (a division of Rambus). All of these
files are usable under the MIT license contained in LICENSE.txt.

The Makefile is set for my 2013 MacBook Air. You can `make bench` to run
a completely arbitrary set of benchmarks and tests, or `make lib` to build
a stripped-down version of the library. For non-Haswell platforms, you may
need to replace -mavx2 -mbmi2 by an appropriate vector declaration.

I've attempted to protect against timing attacks and invalid point attacks,
but as of yet no attempt to protect against power analysis.

This software is incomplete, and lacks documentation. None of the APIs are
yet stable, though they may be getting there. The software is probably not
secure. Please consult TODO.txt for additional agenda items. Do not taunt
happy fun ball.

Cheers,
-- Mike Hamburg
