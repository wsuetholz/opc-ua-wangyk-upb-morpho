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
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.common.RuntimeServiceResultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.transport.security.SecurityConfiguration;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.CryptoUtil;

/**
 * Decrypts & Verifies Chunk secured with asymmetric encryption
 * 
 */
public class ChunkAsymmDecryptVerifier implements Runnable {

	/**
	 * Log4J Error logger. 
	 * Security failures are logged with INFO level.
	 * Security info are printed with DEBUG level.
	 * Unexpected errors are logged with ERROR level. 
	 */
	static Logger LOGGER = Logger.getLogger(ChunkAsymmDecryptVerifier.class);
	
	ByteBuffer chunk;
	SecurityConfiguration securityProfile;
	String securityPolicyUri;
	byte[] senderCertificate;
	byte[] receiverCertificateThumbPrint;
	
	
	public ChunkAsymmDecryptVerifier(ByteBuffer chunk, SecurityConfiguration securityProfile)
	{
		this.chunk = chunk;
		this.securityProfile = securityProfile;
	}
	
	@Override
	public void run() throws RuntimeServiceResultException {
		try {
			// Put chunk position to to starting point of the securityPolicyURI
			// length
			chunk.position(12);
			securityPolicyUri = ChunkUtils.getString(chunk);
			LOGGER.debug("SecurityPolicy in use: " + securityPolicyUri);
			LOGGER.debug("SecurityMode in use: " + securityProfile.getMessageSecurityMode());
			senderCertificate = ChunkUtils.getByteString(chunk);
			receiverCertificateThumbPrint = ChunkUtils.getByteString(chunk);
			int headersEnd = chunk.position();
			int payloadStarts = chunk.position() + 8;
			int payloadEnds = chunk.limit();

			// Get data to decrypt
			byte[] dataToDecrypt = new byte[payloadEnds - headersEnd];
			// set chunk's position to the starting point of the decrpyted bytes
			// (= starting point of the sequence header)
			chunk.position(headersEnd);
			// Get bytes to decrypt
			chunk.get(dataToDecrypt, 0, dataToDecrypt.length);

			// Decrypt message
			int decryptedBytes = decrypt(dataToDecrypt, securityProfile
					.getLocalCertificate(), chunk.array(), headersEnd
					+ chunk.arrayOffset());

			// verify signature
			SecurityPolicy policy = securityProfile.getSecurityPolicy();
			MessageSecurityMode mode = securityProfile.getMessageSecurityMode();
			String signatureAlgorithm = policy.getAsymmetricSignatureAlgorithmUri();
			PublicKey localPublicKey = mode.hasSigning() ? securityProfile.getLocalCertificate().getPublicKey() : null;
			int signatureSize = mode.hasSigning() ? CryptoUtil.getSignatureSize(signatureAlgorithm, localPublicKey) : 0;
			byte[] dataToVerify;
			
			// We want to verify headers and all the decrypted bytes without signature
			// 
			// The signature belongs to decrypted bytes, so we must reduce signatureSize of bytes from decryptedBytes
			dataToVerify = new byte[headersEnd + decryptedBytes - signatureSize];
			chunk.position(0);
			chunk.get(dataToVerify, 0, dataToVerify.length);

			// Extract the signature from the message
			chunk.position(headersEnd + decryptedBytes - signatureSize);
			byte[] signature = new byte[signatureSize];
			chunk.get(signature, 0, signatureSize);

			// Call the verify method
			// Verify
			if (!verify(dataToVerify, securityProfile.getRemoteCertificate(),
					signature)) {
				LOGGER.error("Signature verification fails.");
				throw new ServiceResultException(
						StatusCodes.Bad_SecurityChecksFailed,
						"Signature could not be VERIFIED");
			}

			// Verify Padding
			int padding = -1; // If there is no padding..padding will be 0
								// because we will incerement this value by at
								// least one..
			int paddingEnd = 0;
			// Padding is there only if mode is SignAndEncrypt
			if (securityProfile.getMessageSecurityMode() != MessageSecurityMode.None) {

				paddingEnd = headersEnd + decryptedBytes - signatureSize - 1;
				padding = chunk.get(paddingEnd);

				// check that every value in padding is the same
				for (int ii = paddingEnd - padding; ii < paddingEnd; ii++) {
					if (chunk.get(ii) != padding) {
						// TODO REMOVE PRINTLN
						LOGGER.error("Padding does not match");
						throw new ServiceResultException(
								StatusCodes.Bad_SecurityChecksFailed,
								"Could not verify the padding in the message");
					}
				}
			}
			padding++; // Add the one that need to be allocated for padding

			// Modify the chunk so that the payload is between position and
			// limit of the byte buffer
			chunk.position(payloadStarts);
			// chunk.limit(payloadStarts+decryptedBytes-8);
			chunk.limit(chunk.position() + decryptedBytes - 8 - padding
					- signatureSize);

		} catch (ServiceResultException e) {
			throw new RuntimeServiceResultException(e);
		}
	}

	public String getSecurityPolicyUri() {
		return securityPolicyUri;
	}

	public byte[] getSenderCertificate() {
		return senderCertificate;
	}

	public byte[] getReceiverCertificateThumbprint() {
		return receiverCertificateThumbPrint;
	}
	
	/**
	 * Decrypt a data chunk
	 * 
	 * @param dataToDecrypt
	 * @param decryptingCertificate
	 * @param output
	 * @param outputOffest
	 * @return number of bytes decrypted
	 */
	private int decrypt(byte[] dataToDecrypt, Certificate decryptingCertificate, byte[] output, int outputOffset ) 
	throws ServiceResultException
	{
		//Check which security policy is in use
		SecurityPolicy policy = securityProfile.getSecurityPolicy();
		//Default
		
		if (policy == SecurityPolicy.NONE || securityProfile.getMessageSecurityMode() == MessageSecurityMode.None) {
			return dataToDecrypt.length; //Nothing needs to be done
		}
		return rsa_Decrypt(dataToDecrypt, decryptingCertificate, output, outputOffset);
		
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15
		
//		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getUri());
	}
	
	private boolean verify(byte[] dataToVerify, Certificate signingCertificate, byte[] signature ) throws ServiceResultException{
		//Check which security policy is in use
		//Default
		SecurityPolicy policy = securityProfile.getSecurityPolicy();
		if(policy == SecurityPolicy.NONE){
			//TODO Should we check that there is not anything extra after the message body
			return true; //Nothing needs to be done
		}
		
		if (policy == SecurityPolicy.BASIC128RSA15) {
			return rsa_verify(dataToVerify, signingCertificate, signature);
		}
		
		if (policy == SecurityPolicy.BASIC256) {
			return rsa_verify(dataToVerify, signingCertificate, signature);
		}
		
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15
		
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getPolicyUri());
	}
	
	//Verifies the signature made with SHA1 with RSA encryption
	private boolean rsa_verify(byte[] dataToVerify, Certificate signingCertificate, byte[] signature ) throws ServiceResultException{
		//computethe hash of message
		try {
			
			Signature verifier = Signature.getInstance("SHA1withRSA");
			verifier.initVerify(signingCertificate);
			verifier.update(dataToVerify);
			if(verifier.verify(signature)){
					LOGGER.debug("Asym Signature Verify : OK");
					return true;
			}
			else{
					LOGGER.error("Asymmmetric Signature Verification fails");
					return false;
			
			}
			
			//TODO remove print traces
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		throw new ServiceResultException(StatusCodes.Bad_InternalError,"Exception in asym verify");
	}
	
	 /**
    /// Encrypts the message using RSA PKCS#1 v1.5 encryption.
	 * @throws ServiceResultException 
    **/
	private int rsa_Decrypt(byte[] dataToDecrypt, Certificate decryptingCertificate, byte[] output, int outputOffset) 
	throws ServiceResultException
	{
		//Get key
		SecurityPolicy policy = securityProfile.getSecurityPolicy();		
		Cipher decrypter = CryptoUtil.getAsymmetricCipher(policy.getAsymmetricEncryptionAlgorithmUri());
		RSAPrivateKey rsaPrivateKey = securityProfile.getLocalPrivateKey();
		int inputBlockSize = rsaPrivateKey.getModulus().bitLength()/8;
		
		//int outputBlocksize = getPlainTextBlockSize(decryptingCertificate, false);
		//int outputBlockSize = securityProfile.getPlainTextBlockSize();

		//Verify block sizes
		if(dataToDecrypt.length % inputBlockSize != 0){
			LOGGER.error("Wrong blockSize!!!");
			throw new ServiceResultException(StatusCodes.Bad_InternalError, "Error in asymmetric decrypt: Input data is not an even number of encryption blocks.");
		}
		
		try {
			decrypter.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
			int outputs = decrypter.getOutputSize(dataToDecrypt.length);
			
			int blocks = decrypter.getBlockSize();
			int stop = 0;
			int maxIndex = outputOffset+dataToDecrypt.length;
			//initialize return value, value tells how bytes has been stored in output 
			int totalDecryptedBytes = 0;
			//this value tells how many bytes where added to buffer in each iteration
			int amountOfDecryptedBytes = -1;
			int inputOffset = 0;
			for(int index = outputOffset; index < maxIndex; index+= inputBlockSize){
				amountOfDecryptedBytes = decrypter.doFinal(dataToDecrypt, inputOffset, inputBlockSize,
						output, outputOffset);
				inputOffset += inputBlockSize;
				outputOffset += amountOfDecryptedBytes;
				//Update amount of total decrypted bytes
				totalDecryptedBytes += amountOfDecryptedBytes;
			}
			return totalDecryptedBytes;
			
		} catch (InvalidKeyException e) {
			LOGGER.info("The provided RSA key is invalid", e);
			throw new ServiceResultException(StatusCodes.Bad_SecurityChecksFailed, e);
		} catch (ShortBufferException e) {
			LOGGER.error("Output buffer is too small to hold the result", e);
			throw new ServiceResultException(StatusCodes.Bad_InternalError, e);
		} catch (IllegalBlockSizeException e) {
			LOGGER.error("Illegal Blocksize", e);
			throw new ServiceResultException(StatusCodes.Bad_InternalError, e);
		} catch (BadPaddingException e) {
			LOGGER.error("Bad padding", e);
			throw new ServiceResultException(StatusCodes.Bad_InternalError, e);
		}
	}

	
	
}
