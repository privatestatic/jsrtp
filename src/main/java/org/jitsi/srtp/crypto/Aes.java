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

import javax.crypto.*;

/**
 * Implements a factory for an AES/CTR {@link Cipher}.
 *
 * @author Lyubomir Marinov
 */
public class Aes
{

    private static CipherFactory factory;
    
    private Aes()
    {
        throw new UnsupportedOperationException("Instantiation not allowed!");
    }

    /**
     * The {@link Logger} used by the {@link Aes} class to print out debug
     * information.
     */
    private static final Logger logger = System.getLogger(Aes.class.getName());

    /**
     * Initializes a new {@link Cipher} instance which implements Advanced
     * Encryption Standard (AES) in some mode.
     * 
     * @param transformation String describing transformation to be created. Must be
     *                       an AES variant.
     *
     * @return a new {@link Cipher} instance which implements Advanced Encryption
     *         Standard (AES) in CTR mode
     */
    public static Cipher createCipher(String transformation)
    {
        synchronized (Aes.class) {
            try
            {
                if(factory == null)
                    factory = new CipherFactory();
            } 
                catch (ThreadDeath td)
            {
                throw td;
            } 
                catch (Exception e)
            {
                logger.log(WARNING, "Failed to initialize an optimized AES implementation: {}",
                        e.getLocalizedMessage());
            }
        }
        try
        {
            if (factory == null)
                throw new RuntimeException("Couldn't aquire cipher provider!");
            return factory.createCipher(transformation);
        }
            catch (RuntimeException re)
        {
            throw re;
        }
            catch (Exception ex)
        {
            throw new RuntimeException(ex);
        }
    }

}
