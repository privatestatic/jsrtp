package org.jitsi.impl.neomedia.transform.srtp;

import static jakarta.xml.bind.DatatypeConverter.parseHexBinary;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

import org.jitsi.service.neomedia.*;
import org.jitsi.srtp.*;
import org.junit.jupiter.api.*;

class SRTCPTransformerTest
{
    /* Test case from libsrtp's srtp_driver.c. */
    private static final byte[] RTCP_PLAINTEXT =
        parseHexBinary("81c8000bcafebabe"
            + "abababababababab"
            + "abababababababab");

    private static final byte[] GCM_KEY =
        parseHexBinary("000102030405060708090a0b0c0d0e0f");

    private static final byte[] GCM_SALT =
        parseHexBinary("a0a1a2a3a4a5a6a7a8a9aaab");

    private static final SrtpPolicy GCM_POLICY =
        new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128 / 8,
            SrtpPolicy.NULL_AUTHENTICATION, 0,
            128 / 8, 96 / 8);

    /**
     * A packet whose buffer does not grow, so that protecting it with AES-GCM fails: the buffer has no room for the
     * authentication tag.
     */
    private static class FixedPacket extends RawPacket
    {
        FixedPacket(byte[] data)
        {
            super(data.clone(), 0, data.length);
        }

        @Override
        public void grow(int howMuch)
        {
        }
    }

    /**
     * A packet which the crypto context cannot protect is not returned, so that it is not sent in the clear. The
     * packets after it are protected and can be read by a receiver.
     */
    @Test
    void transformDropsPacketWhichFails() throws Exception
    {
        SrtpContextFactory senderFactory = new SrtpContextFactory(true, GCM_KEY, GCM_SALT, GCM_POLICY, GCM_POLICY);
        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, GCM_KEY, GCM_SALT, GCM_POLICY, GCM_POLICY);
        SRTCPTransformer sender = new SRTCPTransformer(senderFactory);
        SRTCPTransformer receiver = new SRTCPTransformer(receiverFactory);

        try
        {
            assertNull(sender.transform(new FixedPacket(RTCP_PLAINTEXT)));

            RawPacket pkt = new RawPacket(RTCP_PLAINTEXT.clone(), 0, RTCP_PLAINTEXT.length);
            RawPacket encrypted = sender.transform(pkt);
            assertNotNull(encrypted);
            /* The index and the authentication tag are appended. */
            assertEquals(RTCP_PLAINTEXT.length + 4 + 16, encrypted.getLength());

            RawPacket decrypted = receiver.reverseTransform(encrypted);
            assertNotNull(decrypted);
            assertArrayEquals(RTCP_PLAINTEXT, Arrays.copyOfRange(decrypted.getBuffer(), decrypted.getOffset(),
                decrypted.getOffset() + decrypted.getLength()));
        }
        finally
        {
            sender.close();
            receiver.close();
        }
    }
}
