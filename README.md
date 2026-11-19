![Build project](https://github.com/privatestatic/jsrtp/actions/workflows/maven.yml/badge.svg)

# jSRTP

jSRTP is a small, dependency-free Java library for encrypting and decrypting SRTP and SRTCP packets
([RFC 3711](https://www.rfc-editor.org/rfc/rfc3711)). It is a stripped-down fork of
[Jitsi SRTP](https://github.com/jitsi/jitsi-srtp) that runs on any JDK 11+ without native code and without further
Jitsi libraries.

## How it differs from Jitsi SRTP

- **Pure Java, no native code.** The OpenSSL provider and its JNI libraries are removed. All ciphers come from
  `javax.crypto`, so the application decides which JCE provider is used.
- **No Jitsi dependencies.** The few classes needed from [jitsi-utils](https://github.com/jitsi/jitsi-utils) and
  [libjitsi](https://github.com/jitsi/libjitsi) are copied into this library (see [Origin of the sources](#origin-of-the-sources)).
- **No compile-time Bouncy Castle.** Bouncy Castle is used by the tests only.
- **JDK logging.** The Jitsi logger is replaced by `java.lang.System.Logger`.
- **Ready-to-use packet transformers.** `SRTPTransformer` and `SRTCPTransformer` from libjitsi are included, so a
  packet can be protected or unprotected in a few lines.

The library has no runtime dependencies (`spotbugs-annotations` is optional).

## Features

| Feature | Notes |
|---|---|
| AES Counter Mode (AES-CM) with HMAC-SHA1 | 128, 192 and 256 bit keys, 80 or 32 bit tags, e.g. `AES_CM_128_HMAC_SHA1_80` |
| AES-GCM ([RFC 7714](https://www.rfc-editor.org/rfc/rfc7714)) | `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM` |
| AES-F8 | |
| NULL encryption / NULL authentication | |
| Replay protection | 64-packet window, can be switched off per direction in `SrtpPolicy` |
| Cryptex ([RFC 9335](https://www.rfc-editor.org/rfc/rfc9335)) | Receiving is always supported; sending is enabled with `SrtpPolicy.setCryptexEnabled(true)` |
| Joining a running stream | The initial rollover counter (ROC) can be passed to `SRTPTransformer` |

Twofish and Skein are not part of the JDK. They work only if the application registers a JCE provider that offers
them, such as Bouncy Castle.

## Installation

jSRTP is not on Maven Central. There are three ways to get it. Because the library has no runtime dependencies, the
single jar is all you need in each case.

### Release jar (no account needed)

Every [GitHub release](https://github.com/privatestatic/jsrtp/releases) carries `jsrtp-<version>.jar` and
`jsrtp-<version>-sources.jar`. Download the jar and put it on your classpath, or install it into your local Maven
repository:

```shell
mvn install:install-file -Dfile=jsrtp-0.0.11.jar -DgroupId=com.github -DartifactId=jsrtp -Dversion=0.0.11 -Dpackaging=jar
```

### JitPack (no account needed)

[JitPack](https://jitpack.io) builds jSRTP from its Git tags on first request. Add the repository and the dependency
to your `pom.xml`; the version is the Git tag:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.privatestatic</groupId>
    <artifactId>jsrtp</artifactId>
    <version>v0.0.12</version>
</dependency>
```

Note the different `groupId`. JitPack can build a release only if its tag contains `jitpack.yml`, which selects
JDK 11; this applies from 0.0.12 on. `main-SNAPSHOT` gives the current state of `main`.

### GitHub Packages (GitHub account needed)

Releases are published to GitHub Packages. GitHub Packages does not allow anonymous downloads, even for public
packages: you need a GitHub account and a personal access token (classic) with the `read:packages` scope, which every
GitHub user can create under *Settings → Developer settings*. Add it to your `~/.m2/settings.xml`:

```xml
<servers>
    <server>
        <id>github-jsrtp</id>
        <username>YOUR_GITHUB_USER</username>
        <password>YOUR_TOKEN</password>
    </server>
</servers>
```

Then add the repository and the dependency to your `pom.xml`:

```xml
<repositories>
    <repository>
        <id>github-jsrtp</id>
        <url>https://maven.pkg.github.com/privatestatic/jsrtp</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github</groupId>
    <artifactId>jsrtp</artifactId>
    <version>0.0.11</version>
</dependency>
```

## Usage

An `SrtpPolicy` describes the crypto suite, an `SrtpContextFactory` holds the master key and salt, and an
`SRTPTransformer` / `SRTCPTransformer` protects (`transform`) or unprotects (`reverseTransform`) `RawPacket`s. One
crypto context per SSRC is created on demand.

```java
import org.jitsi.impl.neomedia.transform.srtp.SRTCPTransformer;
import org.jitsi.impl.neomedia.transform.srtp.SRTPTransformer;
import org.jitsi.service.neomedia.RawPacket;
import org.jitsi.srtp.SrtpContextFactory;
import org.jitsi.srtp.SrtpPolicy;

// AES_CM_128_HMAC_SHA1_80: 16-byte key, 14-byte salt, 20-byte auth key, 10-byte tag
SrtpPolicy srtpPolicy = new SrtpPolicy(
        SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 10, 14);
SrtpPolicy srtcpPolicy = new SrtpPolicy(
        SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 20, 10, 14);

// Receiving side: the remote key decrypts what we receive (sender = false).
SrtpContextFactory incoming = new SrtpContextFactory(false, remoteKey, remoteSalt, srtpPolicy, srtcpPolicy);
SRTPTransformer srtpIn = new SRTPTransformer(incoming);
SRTCPTransformer srtcpIn = new SRTCPTransformer(incoming);

RawPacket rtp = srtpIn.reverseTransform(new RawPacket(udpPayload, 0, udpPayloadLength));
if (rtp == null)
{
    // authentication failed, replayed packet, or not RTP version 2: drop it
}

// Sending side: the local key encrypts what we send (sender = true).
SrtpContextFactory outgoing = new SrtpContextFactory(true, localKey, localSalt, srtpPolicy, srtcpPolicy);
SRTPTransformer srtpOut = new SRTPTransformer(outgoing);

RawPacket srtpPacket = srtpOut.transform(new RawPacket(rtpBytes, 0, rtpBytes.length));

// Clears the master keys.
srtpIn.close();
srtpOut.close();
```

`transform` and `reverseTransform` change the packet in place and return `null` when it cannot be processed. Such a
packet must be dropped and never be sent. The buffer of a `RawPacket` grows when the authentication tag is added, so
the result may use a new array: read it with `getBuffer()`, `getOffset()` and `getLength()`.

A transformer keeps one crypto context per SSRC, shared by both directions. Use one transformer per key and
direction, as above, rather than one transformer with two factories, unless the SSRCs of the two directions are
guaranteed to differ.

For AES-GCM use `SrtpPolicy.AESGCM_ENCRYPTION` with `SrtpPolicy.NULL_AUTHENTICATION`, an auth key length of 0, a tag
length of 16 and a salt length of 12. To join a stream that is already running, pass its rollover counter:
`new SRTPTransformer(factory, startRoc)`.

The integration tests in [`LiveTestIT`](src/test/java/org/jitsi/srtp/LiveTestIT.java) decrypt and re-encrypt captured
streams and are a complete example. [`CryptoSuite`](src/test/java/org/jitsi/srtp/CryptoSuite.java) maps the SDES suite
names to `SrtpPolicy` values.

## Logging

jSRTP logs through `java.lang.System.Logger`. Without further setup the JDK sends the output to
`java.util.logging`. To route it to SLF4J add `org.slf4j:slf4j-jdk-platform-logging`; for Log4j 2 add
`org.apache.logging.log4j:log4j-jpl`.

## Building

```shell
mvn verify                 # compile, unit tests, integration tests and checkstyle
mvn test -Dtest=SrtpReplayTest
mvn verify -Pcoverage      # JaCoCo report in target/site/jacoco
```

CI builds every push and pull request on JDK 11, 17, 21 and 25.

## Origin of the sources

The packages keep their original `org.jitsi.*` names. Each copied file names its source in a `forked from` comment.

| Source | Files in jSRTP | Copied from |
|---|---|---|
| [jitsi-srtp](https://github.com/jitsi/jitsi-srtp) | `org.jitsi.srtp` and its sub-packages (crypto contexts, ciphers, key derivation, policy) | Forked in March 2023 at commit `a64adcc` (2023-02-16). Upstream `master` was merged up to `1159848` (2024-11-27) in March 2025; the fixes [#72](https://github.com/jitsi/jitsi-srtp/pull/72) and [#73](https://github.com/jitsi/jitsi-srtp/pull/73) were ported in November 2026 without their OpenSSL parts. |
| [libjitsi](https://github.com/jitsi/libjitsi) | `PacketTransformer`, `SinglePacketTransformer`, `SRTPTransformer`, `SRTCPTransformer`, `RawPacket`, `ByteArrayBufferImpl`, `RTPUtils` (moved from `org.jitsi.util` to `org.jitsi.utils`) and `RTPUtilsTest` | Copied in April 2023 from `master` at commit `8640156` (2023-03-13). Adapted to drop the FMJ and Jitsi logging dependencies. |
| [jitsi-utils](https://github.com/jitsi/jitsi-utils) | `ByteArrayBuffer`, `ByteArrayUtils` and their tests | Copied unchanged in March 2023 from `master` at commit `e57838f` (2022-09-10). |

As of November 2026, the copied libjitsi and jitsi-utils files are unchanged upstream since they were copied. Changes
made in jSRTP since then (JDK logging, the initial ROC, dropping SRTCP packets that could not be protected) exist
only here.

## License

Apache License 2.0, see [LICENSE](LICENSE). The original code is © 8x8, Inc. and the Jitsi contributors.
