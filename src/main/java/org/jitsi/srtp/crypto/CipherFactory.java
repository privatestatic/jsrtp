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
 * Factory which initializes a {@link Cipher} that is implemented by a {@link
 * Provider}.
 *
 * @author Lyubomir Marinov
 */
public class CipherFactory
{
    private static final Logger logger = System.getLogger(CipherFactory.class.getName());
    
    /**
     * Creates a cipher with the factory
     *
     * @param transformation the name of the transformation
     * @return The selected cipher
     * @throws Exception On failure
     */
    public Cipher createCipher(String transformation)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance(transformation);
        if (logger.isLoggable(DEBUG))
            logger.log(DEBUG, "Using '{}' to provide cipher for transformation '{}'.",
                    Optional.ofNullable(cipher).map(Cipher::getProvider).map(Provider::getName).orElse("unknown"),
                    transformation);
        return cipher;
    }
}
