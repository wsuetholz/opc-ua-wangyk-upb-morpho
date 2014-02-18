/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 * 
 * Unless explicitly acquired and licensed from Licensor under another 
 * license, the contents of this file are subject to the Reciprocal 
 * Community License ("RCL") Version 1.00, or subsequent versions as 
 * allowed by the RCL, and You may not copy or use this file in either 
 * source code or executable form, except in compliance with the terms and 
 * conditions of the RCL.
 * 
 * All software distributed under the RCL is provided strictly on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, 
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT 
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific 
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

package org.opcfoundation.ua.transport.tcp.impl;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.text.DateFormat;
import java.util.GregorianCalendar;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.transport.security.SecurityConfiguration;
import org.opcfoundation.ua.transport.security.SecurityConstants;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.CryptoUtil;

/**
 * Security Token of a tcp connection
 * 
 */
public class SecurityToken {
	
	private static final Charset UTF8 = Charset.forName("utf-8");
	
	private SecurityConfiguration securityProfile;	
	private int tokenId;
	private int secureChannelId;
	private long creationTime;
	private long lifetime;
	
	//TODO: Mikon lisayksia
	private byte[] localNonce;
	private byte[] remoteNonce;
	private byte[] localSigningKey;
    private byte[] localEncryptingKey;
    private byte[] localInitializationVector;
    private byte[] remoteSigningKey;
    private byte[] remoteEncryptingKey;
    private byte[] remoteInitializationVector;
    private SecretKeySpec remoteKeySpec, localKeySpec;
    
    //Key sizes
    private int hmacHashSize;
    private int signatureKeySize;
    private int encryptionKeySize;
    private int encryptionBlockSize;
	public int cipherBlockSize;    

	/**
	 * Create new security token.
	 * 
	 * @param securityProfile
	 * @param secureChannelId
	 * @param tokenId
	 * @param creationTime
	 * @param lifetime
	 * @param localNonce
	 * @param remoteNonce
	 * @throws ServiceResultException
	 */
	public SecurityToken(SecurityConfiguration securityProfile, 
			int secureChannelId, int tokenId, 
			long creationTime, long lifetime,
			byte[] localNonce, byte[] remoteNonce) 
	throws ServiceResultException
	{
		if (securityProfile==null)
			throw new IllegalArgumentException("null arg");
		this.secureChannelId = secureChannelId;
		this.securityProfile = securityProfile;
		this.tokenId = tokenId;
		this.lifetime = lifetime;
		this.creationTime = creationTime;
		
		//TODO: mikon lisaamia
		this.localNonce = localNonce;
		this.remoteNonce = remoteNonce;
		
		//Calculates symmteric Key sizes for this token
		CalculateSymmetricKeySizes();
		ComputeKeys();
	}	
	
	private void CalculateSymmetricKeySizes(){
		//key sizes are based on security policies..
		//TODO Add rest of the the policies..15.08.2008 most of the uris where not implemented in SecurityConstants-class
	
		if(securityProfile.getSecurityPolicy().getPolicyUri().equalsIgnoreCase(SecurityConstants.SECURITY_POLICY_URI_BINARY_BASIC128RSA15)){
			 hmacHashSize = 20;
             signatureKeySize = 16;
             encryptionKeySize = 16;
             encryptionBlockSize = 16;
             return;
            
		}
		else if(securityProfile.getSecurityPolicy().getPolicyUri().equalsIgnoreCase(SecurityConstants.SECURITY_POLICY_URI_BINARY_BASIC256) ){
			hmacHashSize = 20;
            signatureKeySize = 24;
            encryptionKeySize = 32;
            encryptionBlockSize = 16;
            return;
		}
		else if(securityProfile.getSecurityPolicy().getPolicyUri().equalsIgnoreCase(SecurityConstants.SECURITY_POLICY_URI_BINARY_NONE) ){
			hmacHashSize = 0;
            signatureKeySize = 0;
            encryptionKeySize = 0;
            encryptionBlockSize = 1;
            return;
		}
	}
	
	/**
	 * Computes the keys for a token.
	 * 
	 * @throws ServiceResultException Bad_SecurityPolicyRejected
	 */
    protected void ComputeKeys() throws ServiceResultException
    {    
    	//if message securitymode == NONE, we don't need to calculate keys
        if (securityProfile.getMessageSecurityMode() == MessageSecurityMode.None)
        {
            return;
        }
        //TODO 32 = signatureKeySize
        
       	//Calculate and set keys
		setLocalSigningKey(PSHA1(getRemoteNonce(), null, getLocalNonce(), 0, signatureKeySize) );
		setLocalEncryptingKey(PSHA1(getRemoteNonce(), null, getLocalNonce(), signatureKeySize, encryptionKeySize) );
		setLocalInitializationVector(PSHA1(getRemoteNonce(), null, getLocalNonce(), signatureKeySize + encryptionKeySize, encryptionBlockSize) );
		setRemoteSigningKey(PSHA1(getLocalNonce(), null, getRemoteNonce(), 0, signatureKeySize) );
		setRemoteEncryptingKey(PSHA1(getLocalNonce(), null, getRemoteNonce(), signatureKeySize, encryptionKeySize) );
		setRemoteInitializationVector(PSHA1(getLocalNonce(), null, getRemoteNonce(), signatureKeySize + encryptionKeySize, encryptionBlockSize) );
        
        if (securityProfile.getSecurityPolicy() == SecurityPolicy.BASIC128RSA15 || securityProfile.getSecurityPolicy() == SecurityPolicy.BASIC256)
        {
        	 //TODO create encryptors???????????????
        	
        	// create the HMACs.
            
        	//create server hmac
    		remoteKeySpec = new SecretKeySpec(getRemoteSigningKey(), "HmacSHA1" );
    		KeySpec localKeySpec = new SecretKeySpec(getLocalSigningKey(), "HmacSHA1" );
    		
        	return;
        }
        
        if(securityProfile.getSecurityPolicy() == SecurityPolicy.NONE){
        	return;
        }
        
        throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, securityProfile.getSecurityPolicy().getPolicyUri());
    }
    
    /**
     * Generates a Pseudo random sequence of bits using the P_SHA1 alhorithm.
     * 
     * This function conforms with C#-implementation, so that keys returned 
     * from this function matches eith C#-implementation keys.
     * 
     * @param secret
     * @param label
     * @param data
     * @param offset
     * @param length
     * @return ?
     */
    private byte[] PSHA1(byte[] secret, String label, byte[] data, int offset, int length) 
    throws ServiceResultException 
    {
        //test parameters
    	if (secret == null) throw new IllegalArgumentException("ArgumentNullException: secret");
        if (offset < 0)     throw new IllegalArgumentException("ArgumentOutOfRangeException: offset");
        if (length < 0)     throw new IllegalArgumentException("ArgumentOutOfRangeException: offset");

        // convert label to UTF-8 byte sequence.
        byte[] seed = label != null && !label.isEmpty() ? label.getBytes(UTF8) : null;

        // append data to label.
        if (data != null && data.length > 0){
            if (seed != null){
            	ByteBuffer buf = ByteBuffer.allocate(seed.length+data.length);
            	buf.put(seed);
            	buf.put(data);
//                ByteArrayBuffer seedBuffer = new ByteArrayBuffer(seed.length+data.length);//new byte[seed.length+data.length];
                //copy seed to seed2
//                seedBuffer.write(seed);
                //copy data to seed 2
//                seedBuffer.write(data);
            	buf.rewind();
                seed = buf.array();
//                seed = seedBuffer.getRawData();
            }
            else
            {
                seed = data;
            }
        }

        // check for a valid seed.
        if (seed == null)
        {
           //TODO throw EXCEPTION throw new ServiceResultException(StatusCodes.BadUnexpectedError, "The PSHA1 algorithm requires a non-null seed.");
        	System.out.println("SecurityToken, error: , line 222");
        }

        // create the hmac.
        SecretKeySpec keySpec = new SecretKeySpec(secret, "HmacSHA1" );
        SecurityPolicy policy = securityProfile.getSecurityPolicy();
		Mac hmac = CryptoUtil.createMac( policy.getSymmetricSignatureAlgorithmUri() );
        try {
			hmac.init(keySpec);
		} catch (InvalidKeyException e) {
			throw new ServiceResultException(StatusCodes.Bad_SecurityChecksFailed, e);
		}
        //update data to mac and compute it
        hmac.update(seed);
        byte[] keySeed = hmac.doFinal();
       
        byte[] prfSeed = new byte[hmac.getMacLength() + seed.length];
        
        //Copy keyseed to prfseed from starting point to keyseed.lenght
        System.arraycopy(keySeed, 0, prfSeed, 0, keySeed.length);
        //Copy seed to prfseed, put it after keyseed
        System.arraycopy(seed, 0, prfSeed, keySeed.length, seed.length);
        
                    
        // create buffer with requested size.
        byte[] output = new byte[length];

        int position = 0;

        
        do {
        	//because Mac.doFinal reseted hmac, we must update it again
        	hmac.update(prfSeed);
        	//compute always new hash from prfseed
        	byte[] hash = hmac.doFinal();

            if (offset < hash.length)
            {
                for (int ii = offset; position < length && ii < hash.length; ii++)
                {
                    output[position++] = hash[ii];
                }
            }

            if (offset > hash.length)
            {
                offset -= hash.length;
            }
            else
            {
                offset = 0;
            }

            //calculate hmac from keySeed
            hmac.update(keySeed);
            keySeed = hmac.doFinal();
            System.arraycopy(keySeed, 0, prfSeed, 0, keySeed.length);
            
        }
        while (position < length);

        // return random data.
        return output;
    }
	
    /**
     * Return security token validity. Security token is still valid if it has expired
     * up to 25% after its lifetime. (See Part 6, 5.5.2.1/3)
     * 
     * @return true if less than 125% of tokens life time has elapsed. 
     */
	public boolean isValid()
	{
		return System.currentTimeMillis() < creationTime + lifetime + (lifetime / 4);
	}
	
	/**
	 * Return security token time to renew status. 
	 * True if 75% of security tokens life-time has elapsed.
	 *  
	 * @return true if 75% of tokens life-time has passed
	 */
	public boolean isTimeToRenew()
	{
		return creationTime + (lifetime * 3) / 4 < System.currentTimeMillis();
	}
	
	/**
	 * Return security tokens expired status.
	 * Token is expired if its 100% of its life time has elapsed. Note, the token
	 * is valid for use until 125% of its life time has passed.  
	 * 
	 * @return true if 100% of security tokens life time has elapsed. 
	 */
	public boolean isExpired()
	{
		return System.currentTimeMillis() >= creationTime + lifetime;
	}

	public SecurityPolicy getSecurityPolicy() {
		return securityProfile.getSecurityPolicy();
	}
	
	public SecurityConfiguration getSecurityProfile() {
		return securityProfile;
	}
	
	public MessageSecurityMode getMessageSecurityMode() {
		return securityProfile.getMessageSecurityMode();
	}
	
	public byte[] getLocalSigningKey() {
		return localSigningKey;
	}

	public void setLocalSigningKey(byte[] localSigningKey) {
		this.localSigningKey = localSigningKey;
	}

	public byte[] getLocalEncryptingKey() {
		return localEncryptingKey;
	}

	public void setLocalEncryptingKey(byte[] localEncryptingKey) {
		this.localEncryptingKey = localEncryptingKey;
	}

	public byte[] getLocalInitializationVector() {
		return localInitializationVector;
	}

	public void setLocalInitializationVector(byte[] localInitializationVector) {
		this.localInitializationVector = localInitializationVector;
	}

	public byte[] getRemoteSigningKey() {
		return remoteSigningKey;
	}

	public void setRemoteSigningKey(byte[] remoteSigningKey) {
		this.remoteSigningKey = remoteSigningKey;
	}

	public byte[] getRemoteEncryptingKey() {
		return remoteEncryptingKey;
	}

	public void setRemoteEncryptingKey(byte[] remoteEncryptingKey) {
		this.remoteEncryptingKey = remoteEncryptingKey;
	}

	public byte[] getRemoteInitializationVector() {
		return remoteInitializationVector;
	}

	public void setRemoteInitializationVector(byte[] remoteInitializationVector) {
		this.remoteInitializationVector = remoteInitializationVector;
	}

	/**
	 * Crate new remoteHmac 
	 * 
	 * @return hmac
	 * @throws ServiceResultException 
	 */
	public Mac createRemoteHmac() throws ServiceResultException 
	{
		SecurityPolicy policy = securityProfile.getSecurityPolicy();
		Mac result = CryptoUtil.createMac( policy.getSymmetricSignatureAlgorithmUri() ); 
		try {
			result.init(remoteKeySpec);
		} catch (InvalidKeyException e) {
			throw new ServiceResultException(StatusCodes.Bad_SecurityChecksFailed, e);
		}
		return result;
	}
	
	/**
	 * Create new localHmac 
	 * 
	 * @return hmac
	 * @throws ServiceResultException 
	 */
	public Mac createLocalHmac() throws ServiceResultException 
	{
		SecurityPolicy policy = securityProfile.getSecurityPolicy();
		Mac result = CryptoUtil.createMac( policy.getSymmetricSignatureAlgorithmUri() ); 
		try {
			result.init(localKeySpec);
		} catch (InvalidKeyException e) {
			throw new ServiceResultException(StatusCodes.Bad_SecurityChecksFailed, e);
		}
		return result;
	}
	

	public byte[] getLocalNonce() {
		return localNonce;
	}

	public byte[] getRemoteNonce() {
		return remoteNonce;
	}

	public int getSecureChannelId() {
		return secureChannelId;
	}

	public int getTokenId() {
		return tokenId;
	}
	
	public long getCreationTime()
	{
		return creationTime;
	}
	
	public long getLifeTime()
	{
		return lifetime;
	}
	
	public long getRenewTime()
	{
		return creationTime + ((lifetime *3)/4);
	}

	public int getHmacHashSize() {
		return hmacHashSize;
	}

	public void setHmacHashSize(int hmacHashSize) {
		this.hmacHashSize = hmacHashSize;
	}

	public int getSignatureKeySize() {
		return signatureKeySize;
	}

	public void setSignatureKeySize(int signatureKeySize) {
		this.signatureKeySize = signatureKeySize;
	}

	public int getEncryptionKeySize() {
		return encryptionKeySize;
	}

	public void setEncryptionKeySize(int encryptionKeySize) {
		this.encryptionKeySize = encryptionKeySize;
	}

	public int getEncryptionBlockSize() {
		return encryptionBlockSize;
	}

	public void setEncryptionBlockSize(int encryptionBlockSize) {
		this.encryptionBlockSize = encryptionBlockSize;
	}

	
	@Override
	public String toString() {
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setTimeInMillis(creationTime);
		return "SecurityToken(Id="+tokenId+", secureChannelId="+secureChannelId+", creationTime="+DateFormat.getDateTimeInstance().format(cal.getTime())+", lifetime="+lifetime+")";
	}
	
}
