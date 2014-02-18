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

package org.opcfoundation.ua.utils;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.transport.security.SecurityConstants;

/**
 * This is class contains Cryptographic utilities
 *  
 * http://www.ietf.org/rfc/rfc2437.txt
 * 
 * @author Mikko Salonen (mikko.k.salonen@tut.fi)
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi) 
 */
public class CryptoUtil {

	/**
	 * Log4J Error logger. 
	 * Security failures are logged with INFO level.
	 * Security info are printed with DEBUG level.
	 * Unexpected errors are logged with ERROR level. 
	 */
	static Logger LOGGER = Logger.getLogger(CryptoUtil.class);
	
	/**
	 * Create signer instance using ua algorithm uri 
	 * 
	 * @param algorithmUri UA Specified algorithm uri 
	 * @return Signer
	 * @throws ServiceResultException if algorithm is not supported by the stack
	 */
    public static Signature getAsymmetricSignature(String algorithmUri)
    throws NoSuchAlgorithmException
    {
    	if (algorithmUri==null)
        	throw new IllegalArgumentException("null arg");
//		try {
			// RsaPkcs15Sha1_Sign
			if (algorithmUri.equals(SecurityConstants.RsaSha1))
				return Signature.getInstance("SHA1withRSA");
			throw new NoSuchAlgorithmException(algorithmUri);
//		} catch (NoSuchAlgorithmException e) {
//		}
//        throw new ServiceResultException(
//                StatusCodes.Bad_SecurityPolicyRejected, 
//                "Unsupported asymmetric signature algorithm: {0}, "+ 
//                algorithmUri);
   }

	public static int getAsymmInputBlockSize(String algorithmUri) throws ServiceResultException {
		// http://www.w3.org/2001/04/xmlenc#rsa-1_5
		if (algorithmUri.equals(SecurityConstants.Rsa15))
			return 117;
			
		// http://www.w3.org/2001/04/xmlenc#rsa-oaep
		if (algorithmUri.equals(SecurityConstants.RsaOaep))
			return 86;
				
        throw new ServiceResultException(
                StatusCodes.Bad_SecurityPolicyRejected, 
                "Unsupported asymmetric signature algorithm: {0}, "+ 
                algorithmUri);
	}
	
	// XXX Multi-chunk encryption does not work	
	public static byte[] asymmEncrypt(byte[] input, Key privKey, String algorithmUri) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ServiceResultException
	{
		Cipher cipher = CryptoUtil.getAsymmetricCipher(algorithmUri);
		cipher.init(Cipher.ENCRYPT_MODE, privKey);
		int inputBlock = CryptoUtil.getAsymmInputBlockSize(algorithmUri);
		int outputBlock = cipher.getOutputSize(inputBlock);
		int blocks = (input.length + inputBlock - 1) / inputBlock;
		// This feature does not work, TODO Implement better
		if (blocks>1)
			throw new RuntimeException("Does not work");
		byte[] result = new byte[ blocks * outputBlock ];
		int outOffset = 0;
		int inOffset = 0;
		int inLeft = input.length;
		try {
			for (int i=0; i<blocks; i++) {
				if (i==blocks-1)
					cipher.doFinal(input, inOffset, inLeft, result, outOffset);
				else
					cipher.update(input, inOffset, inputBlock, result, outOffset);
				inOffset += inputBlock;
				inLeft -= inputBlock;
				outOffset += outputBlock;
			}
		} catch (ShortBufferException e) {
			throw new RuntimeException(e);
		}
		return result;
	}
    
	/**
	 * Create signer instance using an algorithm uri.
	 *  http://www.ietf.org/rfc/rfc2437.txt
	 *  Ciphers are defined in PKCS #1: RSA Cryptography Specifications
	 * 
	 * @param algorithmUri UA Specified algorithm uri 
	 * @return Cipher
	 * @throws ServiceResultException if algorithm is not supported by the stack
	 */
    public static Cipher getAsymmetricCipher(String algorithmUri)
    throws ServiceResultException
    {
    	if (algorithmUri==null) throw new IllegalArgumentException();
    	
		try {
			// http://www.w3.org/2001/04/xmlenc#rsa-1_5
			if (algorithmUri.equals(SecurityConstants.Rsa15))
				return Cipher.getInstance("RSA");
			
			// http://www.w3.org/2001/04/xmlenc#rsa-oaep
			if (algorithmUri.equals(SecurityConstants.RsaOaep))
				return Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
				
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchPaddingException e) {
		} catch (NoSuchProviderException e) {
			throw new ServiceResultException(StatusCodes.Bad_InternalError, "BouncyCastle provider is not loaded");
		}
        throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, "Unsupported asymmetric signature algorithm: "+algorithmUri);
    }

	/**
	 * Get symmetric signature algorithm
	 * 
	 * @param algorithmUri symmetric encryption algorithm
	 * @return new signature algorithm
	 * @throws ServiceResultException Bad_SecurityPolicyRejected algorithm not supported
	 */
	public static Signature createSymmetricSignatureAlgorithm(String algorithmUri) 
	throws ServiceResultException
	{
		if (algorithmUri.equals( SecurityConstants.HmacSha1 )) {
			try {
				return Signature.getInstance("HMAC-SHA1");
			} catch (NoSuchAlgorithmException e) {
				throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, e);
			}
		}
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, algorithmUri);
	}
	
	/**
	 * Create Machine Authentication Code (MAC)
	 * 
	 * @param algorithmUri encryption algorithm uri 
	 * @return MAC
	 * @throws ServiceResultException Bad_SecurityPolicyRejected algorithm not supported
	 */
	public static Mac createMac(String algorithmUri)
	throws ServiceResultException
	{
		if (algorithmUri.equals( SecurityConstants.HmacSha1 ))
		{
			try {
				return Mac.getInstance("HmacSHA1");
			} catch (NoSuchAlgorithmException e) {
				throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, algorithmUri);
			}
		}
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, algorithmUri);
	}
	
	/**
	 * Get signature size in bytes
	 * 
	 * @param algorithmUri
	 * @param key 
	 * @return signature size in bytes
	 * @throws ServiceResultException Bad_SecurityPolicyRejected algorithm not supported
	 */
	public static int getSignatureSize(String algorithmUri, Key key)
	throws ServiceResultException
	{
		if (algorithmUri==null) return 0;
		if (algorithmUri.equals(SecurityConstants.HmacSha1))
			return 160/8;
		if (algorithmUri.equals(SecurityConstants.HmacSha256))
			return 256/8;
				
		if (algorithmUri.equals(SecurityConstants.RsaSha1)) {
			if (key instanceof RSAPublicKey)
				return ((RSAPublicKey)key).getModulus().bitLength() / 8;
			if (key instanceof RSAPrivateKey)
				return ((RSAPrivateKey)key).getModulus().bitLength() / 8;
		}
	
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, algorithmUri);
	}
	
	/**
	 * Get cipher block (=output) size in bytes
	 * 
	 * @param algorithmUri algorithm
	 * @param key Optional, required for asymmetric encryption algorithms  
	 * @return cipher block size
	 * @throws ServiceResultException Bad_SecurityPolicyRejected algorithm not supported
	 */
	public static int getCipherBlockSize(String algorithmUri, Key key)
	throws ServiceResultException
	{
		// No security
		if (algorithmUri==null) return 1;
		
		if(algorithmUri.equals(SecurityConstants.Aes128))
			return 16; /** TODO CHECK RETURN VALUE **/
		if(algorithmUri.equals(SecurityConstants.Aes256))
			return 16; /** TODO CHECK RETURN VALUE **/
		
		if (algorithmUri.equals(SecurityConstants.Rsa15) || algorithmUri.equals(SecurityConstants.RsaOaep)) {
			if (key instanceof RSAPublicKey)
				return ((RSAPublicKey) key).getModulus().bitLength() / 8;
			
			if (key instanceof RSAPrivateKey)
				return ((RSAPrivateKey)key).getModulus().bitLength() / 8;
		}
		
		if (algorithmUri.equals(SecurityConstants.RsaSha1)) {
			return 160/8;
		}
				
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, algorithmUri);
	}	
	
	/**
	 * Get plain text block (=input) size in bytes
	 * 
	 * @param algorithmUri algorithm
	 * @param key Optional, required for asymmetric encryption algorithms  
	 * @return cipher block size
	 * @throws ServiceResultException Bad_SecurityPolicyRejected algorithm not supported
	 */
	public static int getPlainTextBlockSize(String algorithmUri, Key key)
	throws ServiceResultException
	{
		// No security
		if (algorithmUri==null) return 1;
		
		if (algorithmUri.equals(SecurityConstants.Rsa15)) {
			if (key instanceof RSAPublicKey)
				return ((RSAPublicKey) key).getModulus().bitLength() / 8 - 11;
		}

		if (algorithmUri.equals(SecurityConstants.Rsa15) || algorithmUri.equals(SecurityConstants.RsaOaep)) {
			if (key instanceof RSAPublicKey)
				return ((RSAPublicKey) key).getModulus().bitLength() / 8 - 42;
		}
		
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, algorithmUri);
	}		
	
	/**
	 * Returns the length of the nonce to be used with an asymmetric encryption algorithm.
	 * 
	 * @param algorithmUri asymmetric encryption algorithm or null (=no encryption)
	 * @return the length of the nonce
	 * @throws ServiceResultException Bad_SecurityPolicyRejected algorithm not supported
	 */
    public static int getNonceLength(String algorithmUri)
	throws ServiceResultException
    {
    	if (algorithmUri == null) return 0;
    	if (algorithmUri.equals( SecurityConstants.Rsa15 ))
    		return 32;
    	if (algorithmUri.equals( SecurityConstants.RsaOaep ))
    		return 32;    	
      	 //TODO: Add rest of policies
      	 /*
      	 else if(SecurityPolicy.getSecurityPolicy(securityPolicyUri) == SecurityPolicy.BASIC128){
   	 		return 16;
      	 }
      	 else if(SecurityPolicy.getSecurityPolicy(securityPolicyUri) == SecurityPolicy.BASIC128RSA15){
      		 return 16;
      	 }
      	 else if(SecurityPolicy.getSecurityPolicy(securityPolicyUri) == SecurityPolicy.BASIC192){
      		 return 24;
      	 }
      	else if(SecurityPolicy.getSecurityPolicy(securityPolicyUri) == SecurityPolicy.BASIC192RSA15){
      	 return 24;
      	}*/
    	
    	throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, algorithmUri);    	
    }
    
    /**
 	 * Create a non-repeatable set of bytes. 
 	 * 
 	 * @param bytes number of byte
 	 * @return nonce
 	 */
 	public static byte[] createNonce(int bytes)
 	{
 		try {
 			byte[] nonce = new byte[bytes];
 			SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
 			rand.nextBytes(nonce); 
 			return nonce;
 		} catch (NoSuchAlgorithmException e) {
 			throw new Error(e);
 		}
 	}	
	
	static {
		// Load Bouncy Castle
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
}
