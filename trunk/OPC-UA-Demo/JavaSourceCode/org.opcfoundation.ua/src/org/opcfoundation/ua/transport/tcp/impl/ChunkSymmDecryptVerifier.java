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

import javax.crypto.Mac;

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


/**
 *
 * 
 */
public class ChunkSymmDecryptVerifier implements Runnable {

	/**
	 * Log4J Error logger. 
	 * Security failures are logged with INFO level.
	 * Security settings are logged with DEBUG level.
	 * Unexpected errors are logged with ERROR level. 
	 */
	static Logger LOGGER = Logger.getLogger(ChunkSymmDecryptVerifier.class);
	
	static final int sequenceHeaderSize = 8;
	static final int messageHeaderSize = 8;
	static final int securityHeaderSize = 8;
	static final int SymmetricHeaders = messageHeaderSize + securityHeaderSize; //Headers which are no crypted
	ByteBuffer chunk;
	SecurityToken token;

	public ChunkSymmDecryptVerifier(ByteBuffer chunk, SecurityToken token)
	{
		this.chunk = chunk;
		this.token = token;
	}
	
	@Override
	public void run()
	throws RuntimeServiceResultException
	{
		try {
			// Security channel will be verified elsewhere
			// verify token id
			int tokenId = ChunkUtils.getTokenId(chunk);
			if (tokenId != token.getTokenId())
				throw new ServiceResultException(
						StatusCodes.Bad_UnexpectedError);

			// Move chunk position to the starting point of the body
			
			// Option A: Decrypt to separate memory block
			
			// Get bytes that need to be decrypted
			chunk.position(SymmetricHeaders);
			byte dataToDecrypt[] = new byte[chunk.limit() - SymmetricHeaders];
			chunk.get(dataToDecrypt, 0, dataToDecrypt.length);			
			int decryptedBytes = decrypt(token, dataToDecrypt, 0,
					dataToDecrypt.length, chunk.array(), SymmetricHeaders
							+ chunk.arrayOffset());

			// Option B: Decrypt in same memory block
//			int decryptedBytes = decrypt(token, chunk.array(), SymmetricHeaders + chunk.arrayOffset(),
//					chunk.limit() - SymmetricHeaders, chunk.array(), SymmetricHeaders + chunk.arrayOffset());
			
			// Verify signature
			int signatureSize = token.getHmacHashSize();
			byte[] signature = new byte[signatureSize];
			// Extract signature from decrypted message
			// move buffer to the beginning of the signature
			chunk.position(16 + decryptedBytes - signatureSize);
			// Read signature from buffer
			chunk.get(signature, 0, signature.length);

			// Get the data to verify
			chunk.position(0);
			byte[] dataToVerify = new byte[16 + decryptedBytes - signatureSize];
			chunk.get(dataToVerify, 0, dataToVerify.length);
			// Verify
			if (!verify(token, dataToVerify, signature)) {
				throw new ServiceResultException(
						StatusCodes.Bad_SecurityChecksFailed,
						"Signature could not be VERIFIED");
			}

			// Verify padding
			int padding = -1; // If there is no padding..padding will be 0
								// because we will increment this value by at
								// least one..
			int paddingEnd = 0;
			// Padding is there only if mode is SignAndEncrypt
			if (token.getMessageSecurityMode() == MessageSecurityMode.SignAndEncrypt) {

				paddingEnd = SymmetricHeaders + decryptedBytes - signatureSize
						- 1;
				padding = chunk.get(paddingEnd);

				// check that every value in padding is the same
				for (int ii = paddingEnd - padding; ii < paddingEnd; ii++) {
					if (chunk.get(ii) != padding) {

						LOGGER.error("Padding does not match");
						throw new ServiceResultException(
								StatusCodes.Bad_SecurityChecksFailed,
								"Could not verify the padding in the message");
					}
				}
			}
			padding++; // Add the one that need to be allocated for padding

			// Calc payload size
			chunk.position(messageHeaderSize + securityHeaderSize + sequenceHeaderSize);
			chunk.limit(chunk.position() + decryptedBytes - 8 - padding - signatureSize);
			int bytesToRead = chunk.limit() - messageHeaderSize - securityHeaderSize - sequenceHeaderSize - signatureSize - padding;
			if (bytesToRead < 0) {
				// TODO Throw ServiceResultException
				// throwError(StatusCodes.Bad_CommunicationError,
				// "Invalid chunk");
			}
		} catch (ServiceResultException e) {
			throw new RuntimeServiceResultException(e);
		}
	}
	
    public int decrypt(SecurityToken token, byte[] dataToDecrypt, int inputOffset, int inputLength, byte[] output, int outputOffset) throws ServiceResultException{
		SecurityPolicy policy = token.getSecurityPolicy();

    	//Check Security policy
    	if (policy == SecurityPolicy.NONE) {
    		//Nothing to do 
    		
    		return dataToDecrypt.length;
    	}
    	
    	if (policy == SecurityPolicy.BASIC128RSA15 || policy == SecurityPolicy.BASIC256){
    		if(token.getMessageSecurityMode() == MessageSecurityMode.Sign){    			
    			return dataToDecrypt.length;
    		}    		
    		return symmetricDecrypt(token, dataToDecrypt, inputOffset, inputLength, output, outputOffset);
    	}
    	
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15 
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getPolicyUri());			
    }
    
    private int symmetricDecrypt(SecurityToken token, byte[] dataToDecrypt, int inputOffset, int inputLength, byte[] output, int outputOffset) throws ServiceResultException{
    	//Make new RijndaelEngine
    	RijndaelEngine engine = new RijndaelEngine(128);

    	//Make CBC blockcipher
		BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(engine));
		
		//find right decryption key and right initialization vector
		KeyParameter secret = new KeyParameter(token.getRemoteEncryptingKey());
		byte[] iv = token.getRemoteInitializationVector();
		
		//initialize cipher for decryption purposes
		cipher.init(false, new ParametersWithIV(secret, iv));
		
		//decrypt
		int cryptedBytes = cipher.processBytes(dataToDecrypt, inputOffset, inputLength, output, outputOffset);
		
		try {

			cryptedBytes += cipher.doFinal(output, outputOffset+cryptedBytes);

			return cryptedBytes;
			//TODO REMOVE print traces
		} catch (DataLengthException e) {
			e.printStackTrace();
			
		} catch (IllegalStateException e) {
			
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in symmetric decrypt");
    }
    
    public boolean verify(SecurityToken token, byte[] dataToVerify, byte[] signature) 
    throws ServiceResultException 
    {
    	//Check Security policy
		SecurityPolicy policy = token.getSecurityPolicy();
		
    	if (policy == SecurityPolicy.NONE){
    		//Nothing to do 
    		return true;
    	}
    	
    	if(policy == SecurityPolicy.BASIC128RSA15 || policy == SecurityPolicy.BASIC256) {
    		return symmetricVerify(token, dataToVerify, signature);
    	}
    	
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15 
    	
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getPolicyUri());		
    }
    
    private boolean symmetricVerify(SecurityToken token, byte[] dataToVerify, byte[] signature) throws ServiceResultException{
    	
    	//Get right hmac
    	Mac hmac = token.createRemoteHmac();
    	byte[] computedSignature = hmac.doFinal(dataToVerify);
    	
    	//Compare signatures
    	//First test that sizes are the same
    	if(signature.length != computedSignature.length){
    		LOGGER.error("Signatures are not the same");
    		return false;
    	}
    	//Compare byte by byte
    	for(int index = 0; index < signature.length; index++){
    		if(signature[index] != computedSignature[index]){
    			//TODO throw ServiceResultException ?!?
    			LOGGER.error("Signatures do not match");
    			return false;
    		}
    	}
    	
    	//Everything went fine, signatures matched
    	return true;
    }
	
}
