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
import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.opcfoundation.ua.common.RuntimeServiceResultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.CryptoUtil;

/**
 *
 * 
 */
public class ChunkSymmEncryptSigner implements Runnable {

	/**
	 * Log4J Error logger. 
	 * Security failures are logged with INFO level.
	 * Security settings are logged with DEBUG level.
	 * Unexpected errors are logged with ERROR level. 
	 */
	static Logger LOGGER = Logger.getLogger(ChunkSymmEncryptSigner.class);
	
	ByteBuffer chunk, payload;
	SecurityToken token;
	
	public ChunkSymmEncryptSigner(ByteBuffer chunk, ByteBuffer payload, SecurityToken token)
	{
		this.chunk = chunk;
		this.payload = payload;
		this.token = token;
	}
	
	@Override
	public void run() throws RuntimeServiceResultException 
	{
	  try {
    	
		int chunkSize = chunk.limit();
		int payloadSize = payload.limit();
		int sequenceHeader = 8;
		int messageHeaderSize = 8;
		int securityHeader = 8;

		//Counter is for calculation of the  final chunk size (with padding etc.)
        int count = 0;
        count += sequenceHeader;
        count += payloadSize;
        count += token.getHmacHashSize();
        
        //calculate padding
        int padding = -1;
        //TODO check SecurityMODE
        //Calculate padding
        if (token.getSecurityProfile().getMessageSecurityMode() == MessageSecurityMode.SignAndEncrypt) {
            // need to reserve one byte for the padding.
            count++;
            padding++; //at least padding size will be added to chunk, because of the securityMode..size is of course at least 0. -> -1++ = 0.
            if (count%token.getEncryptionBlockSize() != 0)
            {
            	//log.error("count%symChannel.getEncryptionBlockSize() = "+count%token.getEncryptionBlockSize());
                padding += token.getEncryptionBlockSize() - (count%token.getEncryptionBlockSize());
            }
            count += padding;
        }
        
        count += messageHeaderSize+securityHeader;
      
		// add headers
		// Write chunk size at position 4
		chunk.position(4);
		chunk.putInt(chunkSize);
		
		
		chunk.position(messageHeaderSize + securityHeader + sequenceHeader + payloadSize);
		//Write padding
		if(padding >= 0){
			
			for (int i=0; i<=padding; i++){
				chunk.put((byte)padding);
			}
    	}
		
		
		// Sign
		//take bytes to sign from buffer..that's why buffer's position is moved back to begin
        int bufPositionBeforeSigning = chunk.position();
        
        //Message written so far will be signed
        chunk.position(0);
        byte[] bytesToSign = new byte[bufPositionBeforeSigning];
        chunk.get(bytesToSign, 0, bufPositionBeforeSigning);
    	
        
        byte[] signature = sign(token, bytesToSign);
      //test signature
        if(signature != null){
        	//now we put signature to buffer
        	chunk.put(signature);
        }
        
        //Encrypt
        int afterSignature = chunk.position();
        chunk.position(0);
        byte[] flush = new byte[afterSignature];
        chunk.get(flush, 0, afterSignature);
        
        //Get bytes to encrypt
        int tmpPosition2 = chunk.position();
        //TODO calculate headersize correctly
        
        // Option A: Encrypt in different memory block
        byte[] bytesToEncrypt = new byte[tmpPosition2 - messageHeaderSize - securityHeader];
        chunk.position(messageHeaderSize+securityHeader);
        chunk.get(bytesToEncrypt, 0, bytesToEncrypt.length);
        //Encrypt
       
       int cryptedBytes = encrypt(token,bytesToEncrypt, 0, bytesToEncrypt.length,
				chunk.array(), messageHeaderSize+securityHeader);        
       
        // Option B: Encrypt in same memory block
//        int byteLenToEncrypt = tmpPosition2 - messageHeaderSize - securityHeader;
//       int cryptedBytes = encrypt(token, chunk.array(), messageHeaderSize+securityHeader + chunk.arrayOffset(), 
//    		   byteLenToEncrypt,    		    
//    		   chunk.array(), 
//				messageHeaderSize+securityHeader);
     
       
       //TODO should position of the chunk be at the starting point of the payload?
     
	  } catch (ServiceResultException e) {
		  throw new RuntimeServiceResultException(e);
	  }
	}
	
	private int encrypt(SecurityToken token, byte[] dataToEncrypt, int inputOffset, int inputLength, byte[] output, int outputOffset) 
	throws ServiceResultException
	{
		SecurityPolicy policy = token.getSecurityPolicy();		
		
    	if (policy == SecurityPolicy.NONE) {
    		//Nothing to do 
    		return dataToEncrypt.length;
    	}
    	
    	if (policy == SecurityPolicy.BASIC128RSA15 || policy== SecurityPolicy.BASIC256) {
    		if(token.getMessageSecurityMode() == MessageSecurityMode.Sign){
    			return dataToEncrypt.length;
    		}
    		return symmetricEncrypt(token, dataToEncrypt, inputOffset, inputLength, output, outputOffset);
    	}
    	
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15 
    	
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getPolicyUri());		
	}
	
	private int symmetricEncrypt(SecurityToken token, byte[] dataToEncrypt, int inputOffset, int inputLength, byte[] output, int outputOffset) throws ServiceResultException{

		//Make RijndaelEngine for encryption
		RijndaelEngine engine = new RijndaelEngine(token.getEncryptionBlockSize()*8);
		//check right instance for cipher

		try {
			//TODO should we check that mode is CBC?
			//blockCipher CBC
			BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));

			cipher.init(true, new ParametersWithIV(new KeyParameter(token.getLocalEncryptingKey()),token.getLocalInitializationVector()));
			
			//Check that input data is even with the encryption blocks
			if(dataToEncrypt.length%cipher.getBlockSize() != 0){
				//ERROR
				LOGGER.error("Input data is not an even number of encryption blocks.");
				//throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in symmetric decrypt: Input data is not an even number of encryption blocks.");
			}
			
			
			int crypted = cipher.processBytes(dataToEncrypt, inputOffset, inputLength, output, outputOffset);
			//log.error("ChunkSymmEncrypter/encrypt: Processed bytes: "+crypted);
			crypted += cipher.doFinal(output, outputOffset+crypted);
	
			return crypted;
		} //TODO remoce print  traces
		catch (DataLengthException e) {
			e.printStackTrace();
		} 
		catch (IllegalStateException e) {
			e.printStackTrace();
		} 
		catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}
		LOGGER.error("EXCEPTION from symmetric exception!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		
		throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in symmetric encrypt");
	}

	
	
    private byte[] sign(SecurityToken token, byte[] dataToSign) throws ServiceResultException
    {
		SecurityPolicy policy = token.getSecurityPolicy();
    	
    	//Check Security policy
    	if (policy == SecurityPolicy.NONE) {
    		//Nothing to do 
    		return null;
    	}
    	
    	if (policy == SecurityPolicy.BASIC128RSA15 || policy == SecurityPolicy.BASIC256) {
    		return symmetricSign(token, dataToSign);
    	}
    	
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15 
    	
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getPolicyUri());		
    }
    
    private byte[] symmetricSign(SecurityToken token, byte[] dataToSign) throws ServiceResultException{
    	SecurityPolicy policy = token.getSecurityPolicy();
    	SecretKeySpec keySpec = new SecretKeySpec(token.getLocalSigningKey(), "HmacSHA1");
		Mac hmac;
		try {
			hmac = CryptoUtil.createMac( policy.getSymmetricSignatureAlgorithmUri() );
			hmac.init(keySpec);
			//hmac.update(dataToSign);
	    	byte[] signature = hmac.doFinal(dataToSign);
	    	return signature;
		} catch (InvalidKeyException e) {
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in symmetric Sign");
		}
    }

	
}
