cryptonite
==========

Cryptonite is a haskell repository of cryptographic primitives. Each crypto
algorithm have specificities, that are hard to wrap in common APIs and types,
so instead of trying to provide a common ground for algorithms that wouldn't
allow to provide all different usage or a really complicated system, this just
provide a non-consistant low-level API.

If you have no idea what're you doing, please do not use this directly, rely on
higher level protocols or higher level implementation.

Documentation: [cryptonite on hackage](http://hackage.haskell.org/package/cryptonite)

Links
-----

* [ChaCha](http://cr.yp.to/chacha.html)
* [ChaCha-test-vectors](https://github.com/secworks/chacha_testvectors.git)

* [Salsa](http://cr.yp.to/snuffle.html)
* [Salsa128-test-vectors](https://github.com/alexwebr/salsa20/blob/master/test_vectors.128)
* [Salsa256-test-vectors](https://github.com/alexwebr/salsa20/blob/master/test_vectors.256)

TODO
----

* remove copy of read-only part of ChaCha state by splitting the stuff in two.
