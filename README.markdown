# Ed448-Goldilocks

## README.txt

This software is an experimental implementation of a new 448-bit elliptic
curve called Ed448-Goldilocks. The implementation itself is based on that of
an earlier, unnamed 252-bit curve which should probably be referred to as
Ed252-MontgomeryStation. See http://eprint.iacr.org/2012/309 for details of
that implementation.

The source files here are all by Mike Hamburg. Most of them are (c) 2014
Cryptography Research, Inc (a division of Rambus). The cRandom
implementation is the exception: these files are from the OpenConflict video
game protection system out of Stanford, and are (c) 2011 Stanford
University. All of these files are usable under the MIT license contained in
LICENSE.txt.

The Makefile is set for my 2013 MacBook Air. You can `make runbench` to run
a completely arbitrary set of benchmarks and tests, or `make
build/goldilocks.so` to build a stripped-down version of the library. For
non-Haswell platforms, you need to replace -mavx2 -mbmi2 by an appropriate
vector declaration. For non-Mac platforms, you won't be able to build a
library with this Makefile. This is fine, because you shouldn't be using
this for much at this stage anyway.

I've attempted to protect against timing attacks and invalid point attacks,
but as of yet no attempt to protect against power analysis. This is an early
revision, so I haven't done much analysis or correctness testing of
corner-cases.

The code in ec_point.c and ec_point.h was generated with the help of a tool
written in SAGE. The field code in p448.h doesn't reduce after add/sub, and
so it requires care to prevent overflow. The SAGE tool figures out where to
put reductions and adjustments to prevent overflow. It also formally
verifies that the formulas produce points on the curve. I'm planning to add
more features to it eventually. That tool is even more experimental than
this library, though, and so I won't be releasing it just yet.

This software is incomplete, and lacks documentation. None of the APIs are
stable. The software is probably not secure. Please consult TODO.txt for
additional agenda items. Do not taunt happy fun ball.

Cheers,
-- Mike Hamburg

## SHAKE branch

This branch uses Shake -- the SHA-3 variable-output-length function -- instead
of SHA-2. Use the GOLDI_SHAKE macro in config.h to pick Shake128 or Shake256.
The default is Shake256.

The design, w.r.t. signatures:

    pk = shake(proto + ds_goldi_derivepk)
    nonceg = shake(message + pk + ds_goldi_signonce)
    challenge = shake(message + nonceg + pubkey + ds_goldi_challenge)

No double-hashing or envelope-MAC construction is needed. By postfixing --
rather than prefixing -- the nonce and public key, verifying multiple
signatures on (long) messages is much faster.

("Shake _s_" is equivalent to `Sponge[c=s*2,r=1600-c,pad10.1](Keccak-f)`. Recent
work has shown that the generic security strength of the sponge construction,
used in "keyed" modes, is equal to `c`. So Shake128 is a viable choice, even
for a target of 256-bit security strength.)

Patches under the same license.
