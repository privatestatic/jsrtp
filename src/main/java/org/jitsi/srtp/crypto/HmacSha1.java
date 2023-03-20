/*
 * Copyright @ 2015 - present 8x8, Inc
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
package org.jitsi.srtp.crypto;

import java.security.*;
import java.util.*;
import java.util.stream.Collectors;

import javax.crypto.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements a factory for an HMAC-SHA1 {@link Mac}.
 *
 * @author Lyubomir Marinov
 */
public class HmacSha1
{   
    private static final Logger logger = LoggerFactory.getLogger(HmacSha1.class);
    
    private static synchronized List<Provider> getProviders()
    {
// Set<String> installedProvidersNames = getInstalledProvidersNames();
// logger.info("Installed provider names: {}", installedProvidersNames.stream().collect(Collectors.joining(",")));
        return Arrays.stream(Security.getProviders()).collect(Collectors.toList());
    }
    
// private static Set<String> getInstalledProvidersNames() {
// return Arrays.stream(Security.getProviders()).map(Provider::getName).collect(Collectors.toSet());
// }

    /**
     * Initializes a new {@link Mac} instance which implements a keyed-hash
     * message authentication code (HMAC) with SHA-1.
     *
     * @param parentLogger the logging context
     * @return a new {@link Mac} instance which implements a keyed-hash message
     * authentication code (HMAC) with SHA-1
     */
    public static Mac createMac()
    {
        // Try providers in order
        for (Provider p : getProviders())
        {
            try
            {
                Mac mac = Mac.getInstance("HmacSHA1", p);
                logger.debug("Using {} for HMAC", p.getName());
                return mac;
            }
            catch (NoSuchAlgorithmException e)
            {
                // continue
            }
        }

        throw new RuntimeException("No HmacSHA1 provider found");
    }

    private static class MacWrapper extends Mac
    {
        public MacWrapper(MacSpi macSpi, Provider provider, String s)
        {
            super(macSpi, provider, s);
        }
    }
}
