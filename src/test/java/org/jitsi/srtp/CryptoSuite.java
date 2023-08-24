package org.jitsi.srtp;

import org.jitsi.impl.neomedia.transform.srtp.SRTPTransformer;

public enum CryptoSuite {
    
    // rfc4568
    AES_CM_128_HMAC_SHA1_80(16, 14, 2 ^ 48L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 10, 10, 20, 20),
    AES_CM_128_HMAC_SHA1_32(16, 14, 2 ^ 48L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 4, 10, 20, 20),
    F8_128_HMAC_SHA1_80(16, 14, 2 ^ 48L, 2 ^ 31L, SrtpPolicy.AESF8_ENCRYPTION, 16, SrtpPolicy.HMACSHA1_AUTHENTICATION, 10, 10, 20, 20),

//    // rfc5669
//    SEED_CTR_128_HMAC_SHA1_80(),
//    SEED_128_CCM_80(),
//    SEED_128_GCM_96(),
    
    // rfc6188
    AES_192_CM_HMAC_SHA1_80(24, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 24, SrtpPolicy.HMACSHA1_AUTHENTICATION, 10, 10, 20, 20),
    AES_192_CM_HMAC_SHA1_32(24, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 24, SrtpPolicy.HMACSHA1_AUTHENTICATION, 4, 10, 20, 20),
    AES_256_CM_HMAC_SHA1_80(32, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 32, SrtpPolicy.HMACSHA1_AUTHENTICATION, 10, 10, 20, 20),
    AES_256_CM_HMAC_SHA1_32(32, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 32, SrtpPolicy.HMACSHA1_AUTHENTICATION, 4, 10, 20, 20),
    
//    // rfc7714
//    AEAD_AES_128_GCM(16, 12, 2 ^ 48L, 2 ^ 31L, SrtpPolicy.AESGCM_ENCRYPTION, 16, SrtpPolicy.NULL_AUTHENTICATION, 16, 16, 0, 0),
//    AEAD_AES_256_GCM(32, 12, 2 ^ 48L, 2 ^ 31L, SrtpPolicy.AESGCM_ENCRYPTION, 12, SrtpPolicy.NULL_AUTHENTICATION, 16, 16, 0, 0),
    
    // incorrect identifier
    AES_CM_256_HMAC_SHA1_80(32, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 32, SrtpPolicy.HMACSHA1_AUTHENTICATION, 10, 10, 20, 20),
    AES_CM_256_HMAC_SHA1_32(32, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 32, SrtpPolicy.HMACSHA1_AUTHENTICATION, 10, 10, 20, 20),
    AES_CM_192_HMAC_SHA1_32(24, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 24, SrtpPolicy.HMACSHA1_AUTHENTICATION, 4, 10, 20, 20),
    AES_CM_192_HMAC_SHA1_80(24, 14, 2 ^ 31L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 24, SrtpPolicy.HMACSHA1_AUTHENTICATION, 10, 10, 20, 20),
    
    // without authentication
    AES_CM_128(16, 14, 2 ^ 48L, 2 ^ 31L, SrtpPolicy.AESCM_ENCRYPTION, 16, SrtpPolicy.NULL_AUTHENTICATION, 0, 0, 0, 0);
    

    int masterKeyLength;
    int masterSaltLength;
    long maxSrtpLifeTime;
    long maxSrtcpLifeTime;
    int encryptionMode;
    int encryptionKeyByteLength;
    int authenticationMode;
    int srtpAuthenticationTagLength;
    int srtcpAuthenticationTagLength;
    int srtpAuthenticationKeyLength;
    int srtcpAuthenticationKeyLength;

    CryptoSuite(int masterKeyByteLength, int masterSaltByteLength, long maxSrtpLifeTime, long maxSrtcpLifeTime, int aesMode,
            int encryptionKeyByteLength, int authenticationMode, int srtpAuthenticationTagByteLength,
            int srtcpAuthenticationTagByteLength, int srtpAuthenticationKeyByteLength,
            int srtcpAuthenticationKeyByteLength) {

        this.masterKeyLength = masterKeyByteLength;
        this.masterSaltLength = masterSaltByteLength;
        this.maxSrtpLifeTime = maxSrtpLifeTime;
        this.maxSrtcpLifeTime = maxSrtcpLifeTime;
        this.encryptionMode = aesMode;
        this.encryptionKeyByteLength = encryptionKeyByteLength;
        this.authenticationMode = authenticationMode;

        this.srtpAuthenticationKeyLength = srtpAuthenticationKeyByteLength;
        this.srtpAuthenticationTagLength = srtpAuthenticationTagByteLength;

        this.srtcpAuthenticationKeyLength = srtcpAuthenticationKeyByteLength;
        this.srtcpAuthenticationTagLength = srtcpAuthenticationTagByteLength;
    }

    public int getMasterKeyLength() {
        return masterKeyLength;
    }

    public int getSaltLength() {
        return masterSaltLength;
    }

    public long getMaxSrtpLifeTime() {
        return maxSrtpLifeTime;
    }

    public long getMaxSrtcpLifeTime() {
        return maxSrtcpLifeTime;
    }

    public int getEncryptionMode() {
        return encryptionMode;
    }

    public int getEncryptionKeyLength() {
        return encryptionKeyByteLength;
    }

    public int getAuthenticationMode() {
        return authenticationMode;
    }

    public int getSrtpAuthenticationTagLength() {
        return srtpAuthenticationTagLength;
    }

    public int getSrtcpAuthenticationTagLength() {
        return srtcpAuthenticationTagLength;
    }

    public int getSrtpAuthenticationKeyLength() {
        return srtpAuthenticationKeyLength;
    }

    public int getSrtcpAuthenticationKeyLength() {
        return srtcpAuthenticationKeyLength;
    }

    private SrtpContextFactory createSrtpContextFactory(boolean sender, byte[] key, byte[] salt) {
        SrtpPolicy srtpPolicy = new SrtpPolicy(getEncryptionMode(), getEncryptionKeyLength(), getAuthenticationMode(),
                getSrtpAuthenticationKeyLength(), getSrtpAuthenticationTagLength(), getSaltLength());
        SrtpPolicy srtcpPolicy = new SrtpPolicy(getEncryptionMode(), getEncryptionKeyLength(), getAuthenticationMode(),
                getSrtcpAuthenticationKeyLength(), getSrtcpAuthenticationTagLength(), getSaltLength());
        return new SrtpContextFactory(sender, key, salt, srtpPolicy, srtcpPolicy);
    }

    public SRTPTransformer createSrtpTransformer(boolean sender, byte[] key, byte[] salt) {
        return new SRTPTransformer(createSrtpContextFactory(sender, key, salt));
    }
}
