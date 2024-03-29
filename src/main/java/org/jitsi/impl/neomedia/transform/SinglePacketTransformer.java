/*
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * forked from project https://github.com/jitsi/libjitsi 
 * from libjitsi/src/main/java/org/jitsi/impl/neomedia/transform/SinglePacketTransformer.java
 */
package org.jitsi.impl.neomedia.transform;

import static java.lang.System.Logger.Level.*;
import java.lang.System.Logger;

import java.util.concurrent.atomic.*;
import java.util.function.*;

import org.jitsi.service.neomedia.*;
import org.jitsi.utils.*;

/**
 * Extends the <tt>PacketTransformer</tt> interface with methods which allow
 * the transformation of a single packet into a single packet.
 *
 * Eases the implementation of <tt>PacketTransformer</tt>-s which transform each
 * packet into a single transformed packet (as opposed to an array of possibly
 * more than one packet).
 *
 * @author Boris Grozev
 * @author George Politis
 */
public abstract class SinglePacketTransformer
    implements PacketTransformer
{
    /**
     * The number of <tt>Throwable</tt>s to log with a single call to
     * <tt>logger</tt>. If every <tt>Throwable</tt> is logged in either of
     * {@link #reverseTransform(RawPacket)} and {@link #transform(RawPacket)},
     * the logging may be overwhelming.
     */
    private static final int EXCEPTIONS_TO_LOG = 1000;

    /**
     * The <tt>Logger</tt> used by the <tt>SinglePacketTransformer</tt> class
     * and its instances to print debug information.
     */
    private static final Logger logger = System.getLogger(SinglePacketTransformer.class.getName());

    /**
     * The number of exceptions caught in {@link #reverseTransform(RawPacket)}.
     */
    private AtomicInteger exceptionsInReverseTransform = new AtomicInteger();

    /**
     * The number of exceptions caught in {@link #transform(RawPacket)}.
     */
    private AtomicInteger exceptionsInTransform = new AtomicInteger();

    /**
     * The idea is to have <tt>PacketTransformer</tt> implementations strictly
     * associated with a <tt>Predicate</tt> so that they only process packets
     * that they're supposed to process. For example, transformers that
     * transform RTP packets should not transform RTCP packets, if, by mistake,
     * they happen to be passed RTCP packets.
     */
    private final Predicate<ByteArrayBuffer> packetPredicate;

    /**
     * A cached link to {@link #reverseTransform(RawPacket)} method to reduce
     * calling overhead on hotpath.
     */
    private final Function<RawPacket, RawPacket> cachedReverseTransform = this::reverseTransform;

    /**
     * A cached link to {@link #transform(RawPacket)} method to reduce
     * calling overhead on hotpath.
     */
    private final Function<RawPacket, RawPacket> cachedTransform = this::transform;

    /**
     * Ctor.
     *
     * XXX At some point ideally we would get rid of this ctor and all the
     * inheritors will use the parametrized ctor. Also, we might want to move
     * this check inside the <tt>TransformEngineChain</tt> so that we only make
     * the check once per packet: The RTCP transformer is only supposed to
     * (reverse) transform RTCP packets and the RTP transformer is only
     * supposed to modify RTP packets.
     */
    public SinglePacketTransformer()
    {
        this(null);
    }

    /**
     * Ctor.
     *
     * @param packetPredicate the <tt>PacketPredicate</tt> to use to match
     * packets to (reverse) transform.
     */
    public SinglePacketTransformer(Predicate<ByteArrayBuffer> packetPredicate)
    {
        this.packetPredicate = packetPredicate;
    }

    /**
     * {@inheritDoc}
     *
     * The (default) implementation of {@code SinglePacketTransformer} does
     * nothing.
     */
    @Override
    public void close()
    {
    }

    /**
     * Reverse-transforms a specific packet.
     *
     * @param pkt the transformed packet to be restored.
     * @return the restored packet.
     */
    public abstract RawPacket reverseTransform(RawPacket pkt);

    /**
     * {@inheritDoc}
     *
     * Reverse-transforms an array of packets by calling
     * {@link #reverseTransform(RawPacket)} on each one.
     */
    @Override
    public RawPacket[] reverseTransform(RawPacket[] pkts)
    {
        return transformArray(
            pkts,
            cachedReverseTransform,
            exceptionsInReverseTransform,
            "reverseTransform");
    }

    /**
     * Transforms a specific packet.
     *
     * @param pkt the packet to be transformed.
     * @return the transformed packet.
     */
    public abstract RawPacket transform(RawPacket pkt);

    /**
     * {@inheritDoc}
     *
     * Transforms an array of packets by calling {@link #transform(RawPacket)}
     * on each one.
     */
    @Override
    public RawPacket[] transform(RawPacket[] pkts)
    {
        return transformArray(
            pkts, cachedTransform, exceptionsInTransform, "transform");
    }

    /**
     * Applies a specific transformation function to an array of
     * {@link RawPacket}s.
     * @param pkts the array to transform.
     * @param transformFunction the function to apply to each (non-null) element
     * of the array.
     * @param exceptionCounter a counter of the number of exceptions
     * encountered.
     * @param logMessage a name of the transformation function, to be used
     * when logging exceptions.
     * @return {@code pkts}.
     */
    private RawPacket[] transformArray(
        RawPacket[] pkts,
        Function<RawPacket, RawPacket> transformFunction,
        AtomicInteger exceptionCounter,
        String logMessage)
    {
        if (pkts != null)
        {
            for (int i = 0; i < pkts.length; i++)
            {
                RawPacket pkt = pkts[i];

                if (pkt != null
                    && (packetPredicate == null || packetPredicate.test(pkt)))
                {
                    try
                    {
                        pkts[i] = transformFunction.apply(pkt);
                    }
                    catch (Throwable t)
                    {
                        exceptionCounter.incrementAndGet();
                        if ((exceptionCounter.get() % EXCEPTIONS_TO_LOG) == 0
                            || exceptionCounter.get() == 1)
                        {
                            logger.log(ERROR, "Failed to {0} RawPacket(s)!\n{1}", logMessage, t);
                        }
                        if (t instanceof Error)
                        {
                            throw (Error) t;
                        }
                        else if (t instanceof RuntimeException)
                        {
                            throw (RuntimeException) t;
                        }
                        else
                        {
                            throw new RuntimeException(t);
                        }
                    }
                }
            }
        }

        return pkts;
    }
}
