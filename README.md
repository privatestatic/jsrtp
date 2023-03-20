# Jitsi SRTP (basic)

This fork of Jitsi SRTP contains classes for encrypting and decrypting SRTP and SRTCP packets. This is a stripped down version of the original [Jitsi SRTP](https://github.com/jitsi/jitsi-srtp) without the OpenSSL provider and without the dependency on [jitsi-utils]( https://github.com/jitsi/jitsi-utils).

The Jitsi logger from jitsi-utils has been replaced by the [Simple Logging Facade for Java (SLF4J)](https://www.slf4j.org/) and the ByteArrayBuffer.java and ByteArrayUtils.java files have been copied directly from [jitsi-utils]( https://github.com/jitsi/jitsi-utils) to this library.
