package org.jitsi.srtp;

import static org.assertj.core.api.Assertions.*;

import org.jitsi.impl.neomedia.transform.srtp.SRTPTransformer;
import org.jitsi.service.neomedia.RawPacket;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import jakarta.xml.bind.DatatypeConverter;

import io.pkts.Pcap;
import io.pkts.PcapOutputStream;

class LiveTestIT {
    private static final Logger LOGGER = System.getLogger(LiveTestIT.class.getName());

    private static final String PCAP_20000_AES_CM_128_HMAC_SHA1_80 = Objects
            .requireNonNull(LiveTestIT.class.getResource("/20000_AES_CM_128_HMAC_SHA1_80.pcap")).getFile();
    private static final String PCAP_20002_AES_CM_128_HMAC_SHA1_80_ONLY_ROC_13 = Objects
            .requireNonNull(LiveTestIT.class.getResource("/20002_AES_CM_128_HMAC_SHA1_80_ONLY_ROC_13.pcap")).getFile();
    private static final String PCAP_20000_AEAD_AES_256_GCM = Objects
            .requireNonNull(LiveTestIT.class.getResource("/20000_AEAD_AES_256_GCM.pcap")).getFile();

    @Test
    void decryptSinglePacket_AES_CM_128_HMAC_SHA1_80() {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("q3BDq3ieE2aYlpPinNQClCkOWowRTO4SuQalqJgv");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength());
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength(), decodedKeySaltBytes.length);
        byte[] expectedDecryptedPayloadBytes = DatatypeConverter.parseHexBinary(
                "7b7efdfd7dfefffd7d7c7e7b7d7afe7efffffcfcfefd7dfd7bfffcfdfffdfb7efefefefd7efefcfd7b7b79fffdfcfafbfbfcfe7b79ff7cfd7d7bfd7cfefeff7e7d7dfcfafdfd7c76757e7efcfa7dfd7ef8fefe7afffe7a7d7bfcfc7b7a7bfefe7b7d7dfbfdfe7b7bff7d7dfeff7efe7d7e7bfefbfdfcfcfffcfbfefdfffe7e7dfffcfb7d7e7e7efcff7d7efefcfc7c787cfe7e7b7dfffbff7d7e7dfffeff7b7efdf9fd7e7b7ef97e7e7cfe7d7e7bfefcff7d797e7d78fe7e7e7e797c7e7bfe7b7efdfbff7bfa7bff7c7efe7aff7bfdff7dfdfcf9fdfbfefffcfcfffefb7e7d7c7c7dfffe7e7d7afffffefdfffcfbfafdfafbff7b7d797e7d7bfe79fbfefafa7efc7cfbfdff7efdfbfafd7d7b787d7cff7c7c7b797c79ff7dfdffffff7c7a7efd7efbfefcfefcfe7dfdfefc7c7c797b7d7dfe7cfafbfb7d7afcfffe7b7d7e7cfffe7efffffefeffffffff7e7e7eff7e7effffff7e7effff7efffefeffffffff7eff7efffeffffffffffff7efffffeffffffff7e7e7e7efffefefffeff7e7e7effff7e7e7effff7e7e7e7eff7e7e7e7effff7efffeffffff7efffefffffefe7e7e7efffeff7e7e7efffe7e7e7e7e7e7e7e7effffff7efffeffffffff7e7e7e7efffffffeffff7e7efefeffffffffffff7effff7e7e7e7e7e7e7effffffff7e7e7e7efffffffeff7e7efefeff7e7effffffff7eff7e7eff7e7efefeffffff7e7e7e7e7e7e7e7efeff7eff7e7e7e7efefefffffffffeffffff7e7efffffffefefffefffffffffffffeffffff7eff7e7e7e7e7e7e7e7e7e7e7efffefe7e7efffeffff7e7efffeff7effffff7e7e7efffeffffff7efffefeff7e7e7e7e7e7efe7e7efffffffefeffff7e7e7e7e7e7e7efffefffffe7efffefffefeffffffff7e7effffff7e7effff7e7efffffefffefeff7effffffff7efffffffefe7eff7e7d7efffffffffefefeffff7e7efffffffeff7efffffeff7e7efffeff7efffefe7eff7e7efeff7e7e7eff7e7efe7e7e7e7e7effff7e7e78f979fb7bffff7eff7bfbfcfe7efbfafc777c7a7aff7ef97bfe7bfd7dfdf9fefb7eff7bff7dfcfbfbfd7dff7dfc7d7c79fffd797cfffd78fdfdfdfafdfbfdff7cfc7e7cfefbfefe7d7dff7dfd7cfd7efcfe7eff7bfd777d7bfffefffd7a7efe7efdfe7dfbfcf97c7afcfffafffffe77fb7afe7e79fa77fcff7c7d7df8ff777c7ef8fd7b7d797bfffdfdfefbfdfffefd7d7d7779fffefefdfbfc7efffffff77dfafefffdfef9fd7a7b7d7dfd7efd7b787c7afe7b7dff7cfc79fcfefffc7bf97b7b7c7cff7aff7cff777b7df9f6fbf9fffb7affff7dfe7e7b797c7c7d7a7cfe7bfb7bfcfe7cfa7af9fefcfe797e7e");

        SRTPTransformer packetTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(false, key, salt);

        byte[] data = DatatypeConverter.parseHexBinary(
                "80000000fcceb009000000017a059abfb792b7a292dd1812682c111943942e780ddfc4fb27ba434192ae1d494b563c1fdfd0bac0c343141e379c6b719fa370861cad1b043be442f2ea362854ec2edb355e3af143cc14feeec94183d49e3218981518a47b344514dcad00ffaa31e560fd95ab39ed31025cc9c3189090d00fa98731f9141218bb14867ba4ebb794ac21a412d9d13f32a2a8392d9f98d7fa406dca78b6b01920b0283c04b6541474d4f75928fc96873202e6c695cc2b65c0df484629819249e9a7a981376750931576435c699230cadad9bb01d46654094c3547ce6bbacd2e6d5696acb2a6ed5bafe577ee25a298eef6eaf59aebbcbaff816b75b8606e34b685499211aa0aa8be0e6886f77fba5357766de8a3e63ad2ba47837d27c5214af74e0130f413796a55a6841d35924b312bf56d9592a2a8ecd9fa119296cde7e3729a3eea59eda7301b1df49c204285a163668d6259af4265cfe732b324796fccb945e5d01e4f965487bdb7bc890973279ecf1b0973d6f7d9f3cf1ffe8ac75873aa690d977b1ebad880995aad25473ddc7c079417a65dbd3bda7f3ddf11ca12bb7e5b2022a7a5ba55ff9fb9a07d6542881e1fbe98118b553791d25bafab0f304aaa476eae4902d1cc1c206432ec2f200f9dd45865387d6b6a3d80503d9584dfdda742f10fa2ad28041a360779f8294f4675d4317e2518a157fbbf83e30583159b702b9edde5911ae29278f56a2809cdee2603f9050915f630c34ded4aae9ff7f936aaa9074947ecc05c3d027f560ab77d1602c17414abc37fb48629d07323625d214af0dfb124a5869db49163a98e07cb7ed7b914498588d161296986cad72ef1658324a06524ea1fd822089f3a6ac72e6d6c7c8e6e0aba3a70aca23bf91b905236b0b0a7e012c6c67da469115f0bddd2c011dc4322d7dfe1606fb93aa844fa0774ae4853f441d36c24434ffa5c62d2e7d122eb75f832df52d50feb52c51957f981a561ff4806372ef710d1124f052b07f9786103b11db4ec658fb2a39def7b838f3983aedb3a5a6e1662cb8709ea4793fe3f947653b023ab4fa5c4d879809777adf3768a2c3882afa1907e6a4cd14c40a1766f71f8a7ce6bc421f34b93737f5a0526905c9ac5e4267a103d61d1f5be00a9d0e1947715eee541192d32b4cdeec5bf7e2fff1a4ba15ab916472515a6f5c17b03d83ceec91de7421bcde90fc602a8324f8cbcc4c932b7b37ed859705d2519f9fe97ac9efb882be5ccd187a735ac15c780f82013eb0e95686b495bfa6d1b161afd19d6dc102aa2ca296a678d45406197bf456d45e072448e8d20315b774ab674b529b7bba48f550df779043df1f4e39878e7b380643ef347c8cf77432bd988452943");
        RawPacket pkt = new RawPacket(data, 0, data.length);

        RawPacket decrypted = packetTransformer.reverseTransform(pkt);
        Assertions.assertNotNull(decrypted, "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber());
        assertThat(Arrays.equals(expectedDecryptedPayloadBytes, decrypted.getPayload())).isTrue();
    }

    @Test
    void decryptSinglePacket_AEAD_AES_256_GCM() {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("wTD/wm8qMOiqYgWA61dyDswfUWMQKqS3/i2uCeUQ3xh9saW2nG55IDh3Mnk=");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0, CryptoSuite.AEAD_AES_256_GCM.getMasterKeyLength());
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, CryptoSuite.AEAD_AES_256_GCM.getMasterKeyLength(), decodedKeySaltBytes.length);
        // The packet carries 20 ms of PCMU (PT 0) silence: 160 bytes of 0xFF.
        byte[] expectedDecryptedPayloadBytes = new byte[160];
        Arrays.fill(expectedDecryptedPayloadBytes, (byte) 0xFF);

        SRTPTransformer packetTransformer = CryptoSuite.AEAD_AES_256_GCM.createSrtpTransformer(false, key, salt);

        byte[] data = DatatypeConverter.parseHexBinary(
                "80009503d99462855c819da76794574316b0c86032f6f0442c4c1205d2aac548c28caaa74af343ea8204df819e9abd1cde1576ca938570db164e29669daa5cd570a1c5082da62d6d9846cc4c20c38a32f74fe0926c93ce76969e756e852a865bedf27f7eb8459b4ae1e6aa51244da2c3f29a9749bc7a35f51610cd2635026bf75e618cc5cc2d9464e0fd954df23bb0a66a6ee1c55d25062b653808bdd886f9b8247d978de16a49c23a5db9b8dcdf1988edc52ebd24652b2c9b2ebb53");
        RawPacket pkt = new RawPacket(data, 0, data.length);

        RawPacket decrypted = packetTransformer.reverseTransform(pkt);
        Assertions.assertNotNull(decrypted, "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber());
        assertThat(Arrays.equals(expectedDecryptedPayloadBytes, decrypted.getPayload())).isTrue();
    }

    @Test
    void encryptSinglePacket_AES_CM_128_HMAC_SHA1_80() {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("q3BDq3ieE2aYlpPinNQClCkOWowRTO4SuQalqJgv");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength());
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength(), decodedKeySaltBytes.length);
        byte[] expectedEncryptedPayloadBytes = DatatypeConverter.parseHexBinary(
                "7a059abfb792b7a292dd1812682c111943942e780ddfc4fb27ba434192ae1d494b563c1fdfd0bac0c343141e379c6b719fa370861cad1b043be442f2ea362854ec2edb355e3af143cc14feeec94183d49e3218981518a47b344514dcad00ffaa31e560fd95ab39ed31025cc9c3189090d00fa98731f9141218bb14867ba4ebb794ac21a412d9d13f32a2a8392d9f98d7fa406dca78b6b01920b0283c04b6541474d4f75928fc96873202e6c695cc2b65c0df484629819249e9a7a981376750931576435c699230cadad9bb01d46654094c3547ce6bbacd2e6d5696acb2a6ed5bafe577ee25a298eef6eaf59aebbcbaff816b75b8606e34b685499211aa0aa8be0e6886f77fba5357766de8a3e63ad2ba47837d27c5214af74e0130f413796a55a6841d35924b312bf56d9592a2a8ecd9fa119296cde7e3729a3eea59eda7301b1df49c204285a163668d6259af4265cfe732b324796fccb945e5d01e4f965487bdb7bc890973279ecf1b0973d6f7d9f3cf1ffe8ac75873aa690d977b1ebad880995aad25473ddc7c079417a65dbd3bda7f3ddf11ca12bb7e5b2022a7a5ba55ff9fb9a07d6542881e1fbe98118b553791d25bafab0f304aaa476eae4902d1cc1c206432ec2f200f9dd45865387d6b6a3d80503d9584dfdda742f10fa2ad28041a360779f8294f4675d4317e2518a157fbbf83e30583159b702b9edde5911ae29278f56a2809cdee2603f9050915f630c34ded4aae9ff7f936aaa9074947ecc05c3d027f560ab77d1602c17414abc37fb48629d07323625d214af0dfb124a5869db49163a98e07cb7ed7b914498588d161296986cad72ef1658324a06524ea1fd822089f3a6ac72e6d6c7c8e6e0aba3a70aca23bf91b905236b0b0a7e012c6c67da469115f0bddd2c011dc4322d7dfe1606fb93aa844fa0774ae4853f441d36c24434ffa5c62d2e7d122eb75f832df52d50feb52c51957f981a561ff4806372ef710d1124f052b07f9786103b11db4ec658fb2a39def7b838f3983aedb3a5a6e1662cb8709ea4793fe3f947653b023ab4fa5c4d879809777adf3768a2c3882afa1907e6a4cd14c40a1766f71f8a7ce6bc421f34b93737f5a0526905c9ac5e4267a103d61d1f5be00a9d0e1947715eee541192d32b4cdeec5bf7e2fff1a4ba15ab916472515a6f5c17b03d83ceec91de7421bcde90fc602a8324f8cbcc4c932b7b37ed859705d2519f9fe97ac9efb882be5ccd187a735ac15c780f82013eb0e95686b495bfa6d1b161afd19d6dc102aa2ca296a678d45406197bf456d45e072448e8d20315b774ab674b529b7bba48f550df779043df1f4e39878e7b380643ef347c8cf77432bd988452943");

        SRTPTransformer packetTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(true, key, salt);

        byte[] data = DatatypeConverter.parseHexBinary(
                "80000000fcceb009000000017b7efdfd7dfefffd7d7c7e7b7d7afe7efffffcfcfefd7dfd7bfffcfdfffdfb7efefefefd7efefcfd7b7b79fffdfcfafbfbfcfe7b79ff7cfd7d7bfd7cfefeff7e7d7dfcfafdfd7c76757e7efcfa7dfd7ef8fefe7afffe7a7d7bfcfc7b7a7bfefe7b7d7dfbfdfe7b7bff7d7dfeff7efe7d7e7bfefbfdfcfcfffcfbfefdfffe7e7dfffcfb7d7e7e7efcff7d7efefcfc7c787cfe7e7b7dfffbff7d7e7dfffeff7b7efdf9fd7e7b7ef97e7e7cfe7d7e7bfefcff7d797e7d78fe7e7e7e797c7e7bfe7b7efdfbff7bfa7bff7c7efe7aff7bfdff7dfdfcf9fdfbfefffcfcfffefb7e7d7c7c7dfffe7e7d7afffffefdfffcfbfafdfafbff7b7d797e7d7bfe79fbfefafa7efc7cfbfdff7efdfbfafd7d7b787d7cff7c7c7b797c79ff7dfdffffff7c7a7efd7efbfefcfefcfe7dfdfefc7c7c797b7d7dfe7cfafbfb7d7afcfffe7b7d7e7cfffe7efffffefeffffffff7e7e7eff7e7effffff7e7effff7efffefeffffffff7eff7efffeffffffffffff7efffffeffffffff7e7e7e7efffefefffeff7e7e7effff7e7e7effff7e7e7e7eff7e7e7e7effff7efffeffffff7efffefffffefe7e7e7efffeff7e7e7efffe7e7e7e7e7e7e7e7effffff7efffeffffffff7e7e7e7efffffffeffff7e7efefeffffffffffff7effff7e7e7e7e7e7e7effffffff7e7e7e7efffffffeff7e7efefeff7e7effffffff7eff7e7eff7e7efefeffffff7e7e7e7e7e7e7e7efeff7eff7e7e7e7efefefffffffffeffffff7e7efffffffefefffefffffffffffffeffffff7eff7e7e7e7e7e7e7e7e7e7e7efffefe7e7efffeffff7e7efffeff7effffff7e7e7efffeffffff7efffefeff7e7e7e7e7e7efe7e7efffffffefeffff7e7e7e7e7e7e7efffefffffe7efffefffefeffffffff7e7effffff7e7effff7e7efffffefffefeff7effffffff7efffffffefe7eff7e7d7efffffffffefefeffff7e7efffffffeff7efffffeff7e7efffeff7efffefe7eff7e7efeff7e7e7eff7e7efe7e7e7e7e7effff7e7e78f979fb7bffff7eff7bfbfcfe7efbfafc777c7a7aff7ef97bfe7bfd7dfdf9fefb7eff7bff7dfcfbfbfd7dff7dfc7d7c79fffd797cfffd78fdfdfdfafdfbfdff7cfc7e7cfefbfefe7d7dff7dfd7cfd7efcfe7eff7bfd777d7bfffefffd7a7efe7efdfe7dfbfcf97c7afcfffafffffe77fb7afe7e79fa77fcff7c7d7df8ff777c7ef8fd7b7d797bfffdfdfefbfdfffefd7d7d7779fffefefdfbfc7efffffff77dfafefffdfef9fd7a7b7d7dfd7efd7b787c7afe7b7dff7cfc79fcfefffc7bf97b7b7c7cff7aff7cff777b7df9f6fbf9fffb7affff7dfe7e7b797c7c7d7a7cfe7bfb7bfcfe7cfa7af9fefcfe797e7e");
        RawPacket pkt = new RawPacket(data, 0, data.length);

        RawPacket encrypted = packetTransformer.transform(pkt);
        Assertions.assertNotNull(encrypted, "Couldn't encrypt packet with sequence number " + pkt.getSequenceNumber());
        assertThat(Arrays.equals(expectedEncryptedPayloadBytes, encrypted.getPayload())).isTrue();
    }

    @Test
    void decryptWriteAndEncryptWholeStream_AES_CM_128_HMAC_SHA1_80() throws IOException {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("q3BDq3ieE2aYlpPinNQClCkOWowRTO4SuQalqJgv");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0,
                CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength());
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength(),
                decodedKeySaltBytes.length);

        SRTPTransformer packetTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(false, key, salt);
        SRTPTransformer encPacketTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(true, key,
                salt);

        Pcap pcap = Pcap.openStream(PCAP_20000_AES_CM_128_HMAC_SHA1_80);
        File parentFile = new File(PCAP_20000_AES_CM_128_HMAC_SHA1_80);
        File outputFile = new File(parentFile.getParentFile(), "result_AES_CM_128_HMAC_SHA1_80.pcap");

        LOGGER.log(Level.INFO, "Created new pcap file: {0}", outputFile);
        PcapOutputStream out = pcap.createOutputStream(new FileOutputStream(outputFile));

        try {
            pcap.loop(new UdpPayloadHandler(d -> {
                RawPacket pkt = new RawPacket(d, 0, d.length);
                byte[] originalBytes = Arrays.copyOf(pkt.getBuffer(), pkt.getBuffer().length);

                // decrypt
                RawPacket decrypted = packetTransformer.reverseTransform(pkt);
                Assertions.assertNotNull(decrypted,
                        "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber() + ".");
                Assertions.assertNotNull(decrypted.getBuffer());
                byte[] decryptedBytes = Arrays.copyOf(decrypted.getBuffer(), decrypted.getBuffer().length);
                Assertions.assertNotNull(decrypted,
                        "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber());
                assertThat(Arrays.equals(originalBytes, decrypted.getBuffer())).isFalse();

                // encrypt
                RawPacket reencrypted = encPacketTransformer.transform(decrypted);
                Assertions.assertNotNull(reencrypted,
                        "Couldn't reencrypt packet with sequence number " + pkt.getSequenceNumber());
                assertThat(Arrays.equals(originalBytes, reencrypted.getBuffer())).isTrue();

                return decryptedBytes;
            }, out, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getSrtcpAuthenticationTagLength()));
        } finally {
            out.flush();
            out.close();
            pcap.close();
        }
    }

    @Test
    void decryptWriteAndEncryptWholeStream_AEAD_AES_256_GCM() throws IOException {
        byte[] decodedKeySaltBytes = Base64.getDecoder()
                .decode("TyBfADxvPN8/JWahU4OFVGksaFwL2m6t81PE7EtnaFZoNpx3+fdq/65a3uk=");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0, CryptoSuite.AEAD_AES_256_GCM.getMasterKeyLength());
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, CryptoSuite.AEAD_AES_256_GCM.getMasterKeyLength(),
                decodedKeySaltBytes.length);

        SRTPTransformer packetTransformer = CryptoSuite.AEAD_AES_256_GCM.createSrtpTransformer(false, key, salt, 0);
        SRTPTransformer encPacketTransformer = CryptoSuite.AEAD_AES_256_GCM.createSrtpTransformer(true, key, salt);

        Pcap pcap = Pcap.openStream(PCAP_20000_AEAD_AES_256_GCM);
        File parentFile = new File(PCAP_20000_AEAD_AES_256_GCM);
        File outputFile = new File(parentFile.getParentFile(), "result_AEAD_AES_256_GCM.pcap");

        LOGGER.log(Level.INFO, "Created new pcap file: {0}", outputFile);
        PcapOutputStream out = pcap.createOutputStream(new FileOutputStream(outputFile));

        try {
            pcap.loop(new UdpPayloadHandler(d -> {
                RawPacket pkt = new RawPacket(d, 0, d.length);
                byte[] originalBytes = Arrays.copyOf(pkt.getBuffer(), pkt.getBuffer().length);

                // decrypt
                RawPacket decrypted = packetTransformer.reverseTransform(pkt);
                Assertions.assertNotNull(decrypted,
                        "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber() + ".");
                Assertions.assertNotNull(decrypted.getBuffer());
                byte[] decryptedBytes = Arrays.copyOf(decrypted.getBuffer(), decrypted.getBuffer().length);
                Assertions.assertNotNull(decrypted,
                        "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber());
                assertThat(Arrays.equals(originalBytes, decrypted.getBuffer())).isFalse();

                // encrypt
                RawPacket reencrypted = encPacketTransformer.transform(decrypted);
                Assertions.assertNotNull(reencrypted,
                        "Couldn't reencrypt packet with sequence number " + pkt.getSequenceNumber());
                assertThat(Arrays.equals(originalBytes, reencrypted.getBuffer())).isTrue();

                return decryptedBytes;
            }, out, CryptoSuite.AEAD_AES_256_GCM.getSrtcpAuthenticationTagLength()));
        } finally {
            out.flush();
            out.close();
            pcap.close();
        }
    }

    @Test
    void decryptWriteAndEncryptWholeStream_AES_CM_128_HMAC_SHA1_80_ONLY_ROC_13() throws IOException {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("BfVE5CD1c0OYzLU526/wr/94CXU7AB33nU3EBam+");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0,
                CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength());
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getMasterKeyLength(),
                decodedKeySaltBytes.length);

        SRTPTransformer packetTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(false, key, salt,
                13);
        SRTPTransformer encPacketTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(true, key,
                salt, 13);

        Pcap pcap = Pcap.openStream(PCAP_20002_AES_CM_128_HMAC_SHA1_80_ONLY_ROC_13);
        File parentFile = new File(PCAP_20002_AES_CM_128_HMAC_SHA1_80_ONLY_ROC_13);
        File outputFile = new File(parentFile.getParentFile(), "result_AES_CM_128_HMAC_SHA1_80_ONLY_ROC_13.pcap");

        LOGGER.log(Level.INFO, "Created new pcap file: {0}", outputFile);
        PcapOutputStream out = pcap.createOutputStream(new FileOutputStream(outputFile));

        try {
            pcap.loop(new UdpPayloadHandler(d -> {
                RawPacket pkt = new RawPacket(d, 0, d.length);
                byte[] originalBytes = Arrays.copyOf(pkt.getBuffer(), pkt.getBuffer().length);

                // decrypt
                RawPacket decrypted = packetTransformer.reverseTransform(pkt);
                Assertions.assertNotNull(decrypted,
                        "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber() + ".");
                Assertions.assertNotNull(decrypted.getBuffer());
                byte[] decryptedBytes = Arrays.copyOf(decrypted.getBuffer(), decrypted.getBuffer().length);
                Assertions.assertNotNull(decrypted,
                        "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber());
                assertThat(Arrays.equals(originalBytes, decrypted.getBuffer())).isFalse();

                // encrypt
                RawPacket reencrypted = encPacketTransformer.transform(decrypted);
                Assertions.assertNotNull(reencrypted,
                        "Couldn't reencrypt packet with sequence number " + pkt.getSequenceNumber());
                assertThat(Arrays.equals(originalBytes, reencrypted.getBuffer())).isTrue();

                return decryptedBytes;
            }, out, CryptoSuite.AES_CM_128_HMAC_SHA1_80.getSrtcpAuthenticationTagLength()));
        } finally {
            out.flush();
            out.close();
            pcap.close();
        }
    }

    /**
     * Writes a single UDP/RTP packet to a PCAP file.
     * The packet is wrapped in Ethernet, IPv4, and UDP headers.
     *
     * @param packetData the raw RTP packet data (without UDP/IP/Ethernet headers)
     * @param outputFile the file to write the PCAP to
     * @throws IOException if an I/O error occurs
     */
    public static void writePacketToPcap(byte[] packetData, File outputFile) throws IOException {
        writePacketToPcap(packetData, outputFile, 5004, 5004);
    }

    /**
     * Writes a single UDP/RTP packet to a PCAP file.
     * The packet is wrapped in Ethernet, IPv4, and UDP headers.
     *
     * @param packetData the raw RTP packet data (without UDP/IP/Ethernet headers)
     * @param outputFile the file to write the PCAP to
     * @param srcPort    the source UDP port
     * @param dstPort    the destination UDP port
     * @throws IOException if an I/O error occurs
     */
    public static void writePacketToPcap(byte[] packetData, File outputFile, int srcPort, int dstPort) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            // PCAP Global Header (24 bytes)
            // Magic number (little-endian)
            fos.write(new byte[]{(byte) 0xd4, (byte) 0xc3, (byte) 0xb2, (byte) 0xa1});
            // Version major (2)
            fos.write(new byte[]{0x02, 0x00});
            // Version minor (4)
            fos.write(new byte[]{0x04, 0x00});
            // Thiszone (GMT to local correction) - 4 bytes
            fos.write(new byte[]{0x00, 0x00, 0x00, 0x00});
            // Sigfigs (accuracy of timestamps) - 4 bytes
            fos.write(new byte[]{0x00, 0x00, 0x00, 0x00});
            // Snaplen (max length of captured packets) - 4 bytes (65535)
            fos.write(new byte[]{(byte) 0xff, (byte) 0xff, 0x00, 0x00});
            // Network (data link type) - 4 bytes (1 = Ethernet)
            fos.write(new byte[]{0x01, 0x00, 0x00, 0x00});

            // Build the full packet: Ethernet + IP + UDP + RTP payload
            int udpLength = 8 + packetData.length;
            int ipLength = 20 + udpLength;
            int totalLength = 14 + ipLength; // Ethernet header + IP packet

            byte[] fullPacket = new byte[totalLength];
            int offset = 0;

            // Ethernet Header (14 bytes)
            // Destination MAC (6 bytes) - broadcast
            System.arraycopy(new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}, 0, fullPacket, offset, 6);
            offset += 6;
            // Source MAC (6 bytes) - dummy
            System.arraycopy(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, fullPacket, offset, 6);
            offset += 6;
            // EtherType (2 bytes) - IPv4 (0x0800)
            fullPacket[offset++] = 0x08;
            fullPacket[offset++] = 0x00;

            // IPv4 Header (20 bytes, no options)
            fullPacket[offset++] = 0x45; // Version (4) + IHL (5)
            fullPacket[offset++] = 0x00; // DSCP + ECN
            fullPacket[offset++] = (byte) ((ipLength >> 8) & 0xff); // Total length (high byte)
            fullPacket[offset++] = (byte) (ipLength & 0xff); // Total length (low byte)
            fullPacket[offset++] = 0x00; // Identification (high)
            fullPacket[offset++] = 0x00; // Identification (low)
            fullPacket[offset++] = 0x40; // Flags (Don't Fragment) + Fragment offset (high)
            fullPacket[offset++] = 0x00; // Fragment offset (low)
            fullPacket[offset++] = 0x40; // TTL (64)
            fullPacket[offset++] = 0x11; // Protocol (17 = UDP)
            fullPacket[offset++] = 0x00; // Header checksum (high) - will be calculated
            fullPacket[offset++] = 0x00; // Header checksum (low)
            // Source IP (127.0.0.1)
            fullPacket[offset++] = 127;
            fullPacket[offset++] = 0;
            fullPacket[offset++] = 0;
            fullPacket[offset++] = 1;
            // Destination IP (127.0.0.1)
            fullPacket[offset++] = 127;
            fullPacket[offset++] = 0;
            fullPacket[offset++] = 0;
            fullPacket[offset++] = 1;

            // Calculate IP header checksum
            int ipHeaderStart = 14;
            int checksum = 0;
            for (int i = 0; i < 20; i += 2) {
                int word = ((fullPacket[ipHeaderStart + i] & 0xff) << 8) | (fullPacket[ipHeaderStart + i + 1] & 0xff);
                checksum += word;
            }
            while ((checksum >> 16) != 0) {
                checksum = (checksum & 0xffff) + (checksum >> 16);
            }
            checksum = ~checksum & 0xffff;
            fullPacket[ipHeaderStart + 10] = (byte) ((checksum >> 8) & 0xff);
            fullPacket[ipHeaderStart + 11] = (byte) (checksum & 0xff);

            // UDP Header (8 bytes)
            fullPacket[offset++] = (byte) ((srcPort >> 8) & 0xff); // Source port (high)
            fullPacket[offset++] = (byte) (srcPort & 0xff); // Source port (low)
            fullPacket[offset++] = (byte) ((dstPort >> 8) & 0xff); // Destination port (high)
            fullPacket[offset++] = (byte) (dstPort & 0xff); // Destination port (low)
            fullPacket[offset++] = (byte) ((udpLength >> 8) & 0xff); // UDP length (high)
            fullPacket[offset++] = (byte) (udpLength & 0xff); // UDP length (low)
            fullPacket[offset++] = 0x00; // UDP checksum (high) - optional in IPv4
            fullPacket[offset++] = 0x00; // UDP checksum (low)

            // RTP Payload
            System.arraycopy(packetData, 0, fullPacket, offset, packetData.length);

            // PCAP Packet Header (16 bytes)
            long currentTime = System.currentTimeMillis();
            int seconds = (int) (currentTime / 1000);
            int microseconds = (int) ((currentTime % 1000) * 1000);

            // Timestamp seconds (little-endian)
            fos.write(new byte[]{
                    (byte) (seconds & 0xff),
                    (byte) ((seconds >> 8) & 0xff),
                    (byte) ((seconds >> 16) & 0xff),
                    (byte) ((seconds >> 24) & 0xff)
            });
            // Timestamp microseconds (little-endian)
            fos.write(new byte[]{
                    (byte) (microseconds & 0xff),
                    (byte) ((microseconds >> 8) & 0xff),
                    (byte) ((microseconds >> 16) & 0xff),
                    (byte) ((microseconds >> 24) & 0xff)
            });
            // Captured length (little-endian)
            fos.write(new byte[]{
                    (byte) (totalLength & 0xff),
                    (byte) ((totalLength >> 8) & 0xff),
                    (byte) ((totalLength >> 16) & 0xff),
                    (byte) ((totalLength >> 24) & 0xff)
            });
            // Original length (little-endian)
            fos.write(new byte[]{
                    (byte) (totalLength & 0xff),
                    (byte) ((totalLength >> 8) & 0xff),
                    (byte) ((totalLength >> 16) & 0xff),
                    (byte) ((totalLength >> 24) & 0xff)
            });

            // Write the packet data
            fos.write(fullPacket);

            LOGGER.log(Level.INFO, "Wrote single packet to PCAP file: {0}", outputFile.getAbsolutePath());
        }
    }
}
