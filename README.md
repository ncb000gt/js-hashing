js-hashing
=============

js-hashing is a tool for hasing strings with JS.
As of now this is tightly coupled with Rhino because it relies on some Java code.
The goal is to eventually rewrite the Java parts in JS.


Usage
=============

`var salt = hash.generate_salt();`

`var hash = hash.to_base64(hash.encode('some string to be hashed', salt, 1000, 'SHA-256'));`