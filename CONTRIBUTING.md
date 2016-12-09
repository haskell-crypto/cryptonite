cryptonite guideline
--------------------

not a definitive list:

* 4-spaces for indentation
* don't use bytestring directly, use the `memory` abstraction
* hard errors should represented by the equivalent Crypto.Error.Types. Possibly reuse a matching value, otherwise create one.
* don't use 'error', use throwCryptoError (or the IO cousin) if needed
* don't add dependencies without a really really really strong motivation. only exception: `foundation`
