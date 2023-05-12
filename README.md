# jSRTP

This fork of Jitsi SRTP contains classes for encrypting and decrypting SRTP and SRTCP packets. This is a stripped down version of the original [Jitsi SRTP](https://github.com/jitsi/jitsi-srtp) without the OpenSSL provider and without the dependency on [jitsi-utils]( https://github.com/jitsi/jitsi-utils).

The jitsi logger from jitsi-utils has been replaced by the [Simple Logging Facade for Java (SLF4J)](https://www.slf4j.org/) and certain required files have been copied directly from [jitsi-utils](https://github.com/jitsi/jitsi-utils) and [libjitsi](https://github.com/jitsi/libjitsi) to this library so that this library can be used without any further jitsi dependencies.

Compile-time dependencies to bouncycastle libraries have also been removed, allowing security providers to be freely chosen.
