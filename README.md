cryptonite
==========

[![Build Status](https://travis-ci.org/vincenthz/cryptonite.png?branch=master)](https://travis-ci.org/vincenthz/cryptonite)
[![BSD](http://b.repl.ca/v1/license-BSD-blue.png)](http://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](http://b.repl.ca/v1/language-haskell-lightgrey.png)](http://haskell.org)

Cryptonite is a haskell repository of cryptographic primitives. Each crypto
algorithm have specificities, that are hard to wrap in common APIs and types,
so instead of trying to provide a common ground for algorithms that wouldn't
allow to provide all different usage or a really complicated system, this just
provide a non-consistant low-level API.

If you have no idea what're you doing, please do not use this directly, rely on
higher level protocols or higher level implementation.

Documentation: [cryptonite on hackage](http://hackage.haskell.org/package/cryptonite)

Versioning
----------

Development versions are an incremental number prefixed by 0.
No specific meaning is associated with the versions, specially
no API stability.

Production versions : TBD

Coding Style
------------

The coding style of this project mostly follows:
[haskell-style](https://github.com/tibbe/haskell-style-guide/blob/master/haskell-style.md)

Support
-------

cryptonite supports the following platform:

* Windows >= 8
* OSX >= 10.8
* Linux

On the following architectures:

* x86-64
* i386

On the following haskell versions:

* GHC 7.0.x
* GHC 7.4.x
* GHC 7.6.x
* GHC 7.8.x
* GHC 7.10.x

Further platforms and architectures probably works too, but until maintainer(s) don't have regular
access to them, we can't commit for further support

Links
-----

* [ChaCha](http://cr.yp.to/chacha.html)
* [ChaCha-test-vectors](https://github.com/secworks/chacha_testvectors.git)
* [Poly1305](http://cr.yp.to/mac.html)
* [Poly1305-test-vectors](http://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-06#page-12)
* [Salsa](http://cr.yp.to/snuffle.html)
* [Salsa128-test-vectors](https://github.com/alexwebr/salsa20/blob/master/test_vectors.128)
* [Salsa256-test-vectors](https://github.com/alexwebr/salsa20/blob/master/test_vectors.256)

* [PBKDF2](http://tools.ietf.org/html/rfc2898)
* [PBKDF2-test-vectors](http://www.ietf.org/rfc/rfc6070.txt)
* [Scrypt](http://www.tarsnap.com/scrypt.html)

* [Curve25519](http://cr.yp.to/ecdh.html)
* [Ed25519](http://ed25519.cr.yp.to/papers.html)

TODO
----

* remove copy of read-only part of ChaCha / Salsa state by splitting the stuff in two.
* add support for XSalsa
