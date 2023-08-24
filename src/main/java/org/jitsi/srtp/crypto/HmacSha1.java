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

import static java.lang.System.Logger.Level.*;
import java.lang.System.Logger;

import java.security.*;
import java.util.*;
import javax.crypto.*;

/**
 * Implements a factory for an HMAC-SHA1 {@link Mac}.
 *
 * @author Lyubomir Marinov
 */
public class HmacSha1
{   
    private static final Logger logger = System.getLogger(HmacSha1.class.getName());
    
    private HmacSha1()
    {
        throw new UnsupportedOperationException("Instantiation not allowed!");
    }

    /**
     * Initializes a new {@link Mac} instance which implements a keyed-hash
     * message authentication code (HMAC) with SHA-1.
     *
     * @return a new {@link Mac} instance which implements a keyed-hash message
     * authentication code (HMAC) with SHA-1
     */
    public static Mac createMac()
    {
        try 
        {
            Mac mac = Mac.getInstance("HmacSHA1");
            if (logger.isLoggable(DEBUG))
                logger.log(DEBUG, "Using '{}' for HMAC",
                        Optional.ofNullable(mac).map(Mac::getProvider).map(Provider::getName).orElse("unknown"));
            return mac;
        } 
            catch (NoSuchAlgorithmException e) 
        {
            throw new RuntimeException("No HmacSHA1 provider found");
        }
    }
}
