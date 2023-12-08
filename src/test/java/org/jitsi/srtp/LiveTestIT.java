package org.jitsi.srtp;

import static org.assertj.core.api.Assertions.*;

import org.jitsi.impl.neomedia.transform.srtp.SRTPTransformer;
import org.jitsi.service.neomedia.RawPacket;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
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

    private static final String PCAP_20230801_09_20000 = Objects
            .requireNonNull(LiveTestIT.class.getResource("/20230801_09_20000.pcap")).getFile();

    @Test
    void decryptSinglePacket() {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("q3BDq3ieE2aYlpPinNQClCkOWowRTO4SuQalqJgv");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0, 16);
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, 16, decodedKeySaltBytes.length);
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
    void encryptSinglePacket() {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("q3BDq3ieE2aYlpPinNQClCkOWowRTO4SuQalqJgv");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0, 16);
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, 16, decodedKeySaltBytes.length);
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
    void decryptWriteAndEncryptWholeStream() throws FileNotFoundException, IOException {
        byte[] decodedKeySaltBytes = Base64.getDecoder().decode("q3BDq3ieE2aYlpPinNQClCkOWowRTO4SuQalqJgv");
        byte[] key = Arrays.copyOfRange(decodedKeySaltBytes, 0, 16);
        byte[] salt = Arrays.copyOfRange(decodedKeySaltBytes, 16, decodedKeySaltBytes.length);

        SRTPTransformer packetTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(false, key, salt);

        Pcap pcap = Pcap.openStream(PCAP_20230801_09_20000);
        File parentFile = new File(PCAP_20230801_09_20000);
        File outputFile = new File(parentFile.getParentFile(), "result.pcap");

        LOGGER.log(Level.INFO, "Created new pcap file: {0}", outputFile);
        PcapOutputStream out = pcap.createOutputStream(new FileOutputStream(outputFile));

        try {
            pcap.loop(new UdpPayloadHandler(d -> {
                RawPacket pkt = new RawPacket(d, 0, d.length);
                byte[] originalBytes = Arrays.copyOf(pkt.getBuffer(), pkt.getBuffer().length);

                // decrypt
                RawPacket decrypted = packetTransformer.reverseTransform(pkt);
                byte[] decryptedBytes = Arrays.copyOf(decrypted.getBuffer(), decrypted.getBuffer().length);
                Assertions.assertNotNull(decrypted,
                        "Couldn't decrypt packet with sequence number " + pkt.getSequenceNumber());
                assertThat(Arrays.equals(originalBytes, decrypted.getBuffer())).isFalse();

                // encrypt
                SRTPTransformer encPacketTransformer = CryptoSuite.AES_CM_128_HMAC_SHA1_80.createSrtpTransformer(true,
                        key, salt);
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
}
