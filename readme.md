# tls fingerprint generator

so this just takes tls handshake data and makes a fingerprint out of it.
useful if you wanna see how a client connects, check for weird patterns, or just mess around with network stuff.

## how it works

* sniffs tls handshakes
* grabs cipher suites, extensions, etc.
* turns them into a unique string

