# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

jSRTP is a stripped-down fork of [jitsi-srtp](https://github.com/jitsi/jitsi-srtp): a Java 11 library that encrypts
and decrypts SRTP/SRTCP packets. It differs from upstream in three deliberate ways, all of which must be preserved:

- **No jitsi dependencies.** The few classes needed from `jitsi-utils` and `libjitsi` (`RawPacket`,
  `ByteArrayBuffer`, `RTPUtils`, the `PacketTransformer` hierarchy, …) are copied into this repo under their original
  `org.jitsi.*` packages. Do not add `jitsi-utils`/`libjitsi` back as dependencies.
- **No OpenSSL provider, no compile-time BouncyCastle.** Ciphers come from `javax.crypto.Cipher.getInstance(...)`, so
  the application picks the JCE provider. BouncyCastle is a test-scope dependency only.
- **Logging uses `java.lang.System.Logger`** (`System.getLogger(X.class.getName())`, `{0}`-style message formats),
  not the jitsi logger or SLF4J. Tests bridge it to `slf4j-simple` via `slf4j-jdk-platform-logging`.

The only runtime dependency is the optional `spotbugs-annotations`.

## Commands

Maven, JDK 11+ (CI builds on 11, 17, 21, 25; releases build on 11).

```powershell
mvn -B verify                       # compile, unit tests, integration tests, checkstyle (what CI runs)
mvn test                            # unit tests only (surefire, *Test classes)
mvn test -Dtest=SrtpReplayTest      # one unit test class
mvn test -Dtest=SrtpReplayTest#someMethod
mvn verify -Dtest=none -Dsurefire.failIfNoSpecifiedTests=false -Dit.test=LiveTestIT   # one integration test
mvn checkstyle:check                # style only
mvn verify -Pcoverage               # JaCoCo report in target/site/jacoco
```

CI passes `-DperformRelease=false -DskipNativeTests=true`; neither property is used by this pom (leftovers from
upstream), so plain `mvn verify` is equivalent.

Checkstyle (`checkstyle.xml`) runs in `verify` and fails the build: max line length 120, and the existing brace
style — opening braces of classes, methods and `if`/`else`/`try`/`catch`/`finally` on their own line. Follow the
surrounding code. `.editorconfig`: LF, UTF-8, 4-space indent (2 for YAML).

## Architecture

Two layers, both keyed on a master key + salt and an `SrtpPolicy`:

1. **Crypto core — `org.jitsi.srtp`.**
   - `SrtpPolicy` describes a crypto suite: encryption type (`AESCM`, `AESGCM`, `AESF8`, `TWOFISH`, `TWOFISHF8`,
     `NULL`), auth type (`HMACSHA1`, `SKEIN`, `NULL`), key/salt/tag lengths, replay-protection and cryptex flags.
   - `SrtpContextFactory` holds the master key/salt plus separate SRTP and SRTCP policies, and derives one context per
     SSRC: `deriveContext(ssrc, roc)` → `SrtpCryptoContext`, `deriveControlContext(ssrc)` → `SrtcpCryptoContext`.
     `close()` zeroes the key material.
   - `BaseSrtpCryptoContext` maps the policy to a cipher (`crypto/SrtpCipherCtr|Gcm|F8` wrapping a JCE `Cipher`
     obtained via `crypto/Aes` → `CipherFactory`) and a `Mac` (`HmacSha1`), and holds the 64-packet replay window.
   - `SrtpCryptoContext` / `SrtcpCryptoContext` do the per-packet work (`transformPacket` = protect,
     `reverseTransformPacket` = unprotect) on a `ByteArrayBuffer`, including ROC/index guessing, session-key
     derivation (`SrtpKdf`), authentication and replay checks, and RFC 9335 cryptex header-extension encryption. They
     return an `SrtpErrorStatus` instead of throwing for authentication/replay failures.

2. **Transformer API — `org.jitsi.impl.neomedia.transform`** (copied from libjitsi; this is what callers use).
   - `PacketTransformer` (array-based) ← `SinglePacketTransformer` (per-packet, adds error logging).
   - `srtp/SRTPTransformer` and `srtp/SRTCPTransformer` keep a forward (encrypt) and a reverse (decrypt)
     `SrtpContextFactory` and a lazily filled SSRC → context map. `transform`/`reverseTransform` return the same
     `RawPacket` on success and `null` on any failure. `SRTPTransformer.reverseTransform` silently drops packets
     whose RTP version is not 2.
   - `org.jitsi.service.neomedia.RawPacket` is the mutable packet buffer (implements `ByteArrayBuffer`); encryption
     happens in place, growing/shrinking the buffer for the auth tag.

`org.jitsi.utils` and `org.jitsi.srtp.utils` hold byte/RTP header helpers used by both layers.

## Tests

- `src/test/java/org/jitsi/srtp/CryptoSuite.java` is the test-side enum mapping SDES crypto-suite names
  (`AES_CM_128_HMAC_SHA1_80`, `AEAD_AES_256_GCM`, …) to `SrtpPolicy` values, with helpers that build ready
  `SRTPTransformer`s. It is the quickest way to set up a context in a new test.
- `LiveTestIT` (failsafe) is the usage reference named in the README: it decrypts/re-encrypts real captured streams
  from `src/test/resources/*.pcap` (read with `io.pkts`) and asserts byte-exact round trips. It writes
  `result_*.pcap` files into `target/test-classes`.
- `SrtpCipherF8Test` registers BouncyCastle for Twofish; the main code never does.
