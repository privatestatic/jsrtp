package org.jitsi.srtp;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.function.Function;

import io.pkts.PacketHandler;
import io.pkts.PcapOutputStream;
import io.pkts.buffer.Buffer;
import io.pkts.buffer.Buffers;
import io.pkts.packet.Packet;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

public class UdpPayloadHandler implements PacketHandler {
    private final Function<byte[], byte[]> function;
    private final PcapOutputStream out;
    private final int authTagLength;

    public UdpPayloadHandler(Function<byte[], byte[]> function, PcapOutputStream out, int authTagLength)
            throws IllegalArgumentException, FileNotFoundException {
        this.function = function;
        this.out = out;
        this.authTagLength = authTagLength;
    }

    @Override
    public boolean nextPacket(Packet packet) throws IOException {
        if (packet.hasProtocol(Protocol.UDP) && packet.hasProtocol(Protocol.RTP)) {
            UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
            Buffer udpPayloadBuffer = udpPacket.getPayload();
            if (udpPayloadBuffer != null) {
                byte[] data = new byte[udpPayloadBuffer.capacity()];
                udpPayloadBuffer.getBytes(data);
                byte[] result = function.apply(data);
                Buffer payload = Buffers.wrap(result);
                if (out != null) {
                    udpPacket.write(out, payload.slice(payload.capacity() - authTagLength));
                }
            }
        }

        // Return true if you want to keep receiving next packet.
        // Return false if you want to stop traversal
        return true;
    }
}
