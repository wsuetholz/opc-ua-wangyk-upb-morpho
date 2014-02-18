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
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
 *@author Mikko Salonen
 * 
 */
public class ChunkAsymmEncryptSigner implements Runnable {

	/**
	 * Log4J Error logger. 
	 * Security failures are logged with INFO level.
	 * Security settings are logged with DEBUG level.
	 * Unexpected errors are logged with ERROR level. 
	 */
	static Logger LOGGER = Logger.getLogger(ChunkAsymmEncryptSigner.class);
	
	ByteBuffer chunk, payload;
	SecurityConfiguration profile;
	
	public ChunkAsymmEncryptSigner(ByteBuffer chunk, ByteBuffer payload, SecurityConfiguration profile)
	{
		this.chunk = chunk;
		this.payload = payload;
		this.profile = profile;
	}
	
	@Override
	public void run() 
	throws RuntimeServiceResultException{
	  try {
		int payloadSize = payload.limit();
		MessageSecurityMode securityMode = profile.getMessageSecurityMode();
		SecurityPolicy policy = profile.getSecurityPolicy();
		int sequenceHeader = 8;
		String signatureAlgorithm = policy.getAsymmetricSignatureAlgorithmUri();
		int signatureSize = securityMode.hasSigning() ? CryptoUtil.getSignatureSize(signatureAlgorithm, profile.getLocalPrivateKey()) : 0;
		
		//At this point padding has already added to the chunk, check AsymChunkfactory
		
		//Get bytes that need to be signed
		//Amount of bytes to sign depends on policy (mode) in use
//		log.debug("SecurityMode in asymm enc: "+ securityMode.getValue());
		byte[] bytesToSign;
		//When using asymmetric security, there are two options available (either messages are encrypted&signed or no
		//security ).
		if(securityMode == MessageSecurityMode.None){
			bytesToSign = new byte[payload.arrayOffset()+payloadSize];
			
		}
		else{
			//Because of the signAndEncryptMode, padding exists (+ 1 byte for padding size)
			bytesToSign = new byte[payload.arrayOffset()+payloadSize+1+getPaddingSize()];
		}
        //Get the data from buffer that needs to be signed..
        //Because of the get-method, chunk position will be set to the end of message 
        //(End of padding), because padding is the last thing that needs to be signed
        
        //set position to beginning of the chunk
        chunk.rewind();
        chunk.get(bytesToSign, 0, bytesToSign.length);
        
        //Sign
        byte[] signature = Sign(bytesToSign,profile.getLocalPrivateKey());
        
        //Test signature
        if(signature != null){
        	//put signature to chunk
        	chunk.put(signature);
        	
        	//now we put signature to buffer
        }
		
        //Get bytes to encrypt
        //We want to encrypt everything but the messageHeader and securityHeader
        //payload tells where the body of this message begins...
        //there is sequenceHeader (size = 8) before the body and we want to encrypt that too 
        
        //Get amount of padding, which depends on security policy (mode) in use
        byte[] bytesToEncrypt = null;
        
        if (securityMode == MessageSecurityMode.None) {
        	bytesToEncrypt = new byte[sequenceHeader+payloadSize];
        }
        else{ //if mode == Sign || Sign&Encrypt, we MUST encrypt
        	//Just check that we have either sign or signAndEncrypt as mode
        	if(!(securityMode == MessageSecurityMode.SignAndEncrypt || securityMode==MessageSecurityMode.Sign  ) ){
        		throw new ServiceResultException(StatusCodes.Bad_SecurityChecksFailed, "Security mode check failed");
        	}
        	int padding = getPaddingSize();
        	bytesToEncrypt = new byte[sequenceHeader+payloadSize+padding+1+signatureSize];
        }
        
        //Encrypt
        chunk.position(payload.arrayOffset()-sequenceHeader);
        chunk.get(bytesToEncrypt, 0, bytesToEncrypt.length);
        encrypt(bytesToEncrypt, profile.getRemoteCertificate(), 
				 
				chunk.array(), payload.arrayOffset()-sequenceHeader);
       
        //set chunk's position to the starting point of payload
		chunk.position(payload.arrayOffset());
	  } catch (ServiceResultException e) {
		  throw new RuntimeServiceResultException(e);
	  }
	}
	
	//Returns the padding size 
	private int getPaddingSize(){
		
		int firstPaddingBytePosition = payload.arrayOffset()+payload.limit();
		byte paddingByte = chunk.get(firstPaddingBytePosition);
		return paddingByte;
		
	}
	
	//This function checks how the encryption is done.
	private void encrypt(byte[] dataToEncrypt, Certificate encryptingCertificate,byte[] output, int outputOffset ) throws ServiceResultException{
		
		//Check which security policy is in use
		//Default
		SecurityPolicy policy = profile.getSecurityPolicy();
		if(policy == SecurityPolicy.NONE || profile.getMessageSecurityMode() == MessageSecurityMode.None){
			return; //Nothing needs to be done
		}
		
		if (policy == SecurityPolicy.BASIC128RSA15){
			rsa_Encrypt(dataToEncrypt, encryptingCertificate, output, outputOffset, false);
			return;
		}
		
		if (policy == SecurityPolicy.BASIC256){
			rsa_Encrypt(dataToEncrypt, encryptingCertificate, output, outputOffset, true);
			return;
		}
		
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15
		
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getPolicyUri());		
	}
	
	//Encrpytion method.
	private void rsa_Encrypt(byte[] dataToEncrypt, Certificate encryptingCertificate,byte[] output, int outputOffset, boolean useOAEP ) throws ServiceResultException{
		RSAPublicKey serverPublic =  (RSAPublicKey) encryptingCertificate.getPublicKey();
		Cipher encrypter = null;
		
		SecurityPolicy policy = profile.getSecurityPolicy();
		MessageSecurityMode mode = profile.getMessageSecurityMode();
		
		int inputBlockSize = 1;
		if (policy != SecurityPolicy.NONE) {			
			Key key = profile.getRemoteCertificate().getPublicKey();
			inputBlockSize = CryptoUtil.getPlainTextBlockSize(policy.getAsymmetricEncryptionAlgorithmUri(), key);
		}
		
		//int inputBlockSize = getPlainTextBlockSize(encryptingCertificate, false);
		
		//get RSAPublicKey from Certificate
		int ouputBlockSize = serverPublic.getModulus().bitLength() / 8;
		int length = dataToEncrypt.length/inputBlockSize;
		
		//verify that the input data has the correct block size
		if(dataToEncrypt.length % inputBlockSize !=0){
			LOGGER.error("Wrong block size in asym encryption");
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric encrypt: Input data is not an even number of encryption blocks.");
		}
		
		try {
			
		if(!useOAEP){
				encrypter = Cipher.getInstance("RSA");
			}
			else{
				//TODO: is this correct??
				encrypter = CryptoUtil.getAsymmetricCipher(profile.getSecurityPolicy().getAsymmetricEncryptionAlgorithmUri());
				// Nope, its Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");				

			}
			 //TODO remove print traces
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric encrypt");
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric encrypt");
		}
		try {
			encrypter.init(Cipher.ENCRYPT_MODE, serverPublic);
			
			//encrypt one block at time
			int maxIndex = outputOffset+dataToEncrypt.length;
			
			int inputOffset = 0;
			for(int index = outputOffset; index < maxIndex; index += inputBlockSize){
				int amountOfEncryptedBytes = encrypter.doFinal(
						dataToEncrypt, inputOffset, 
						inputBlockSize, 
						output, outputOffset); //vika 0 kuuluu olla index
				inputOffset += inputBlockSize;
				outputOffset += amountOfEncryptedBytes;				
				LOGGER.debug("Asym ecryption: Total decrypted bytes: "+amountOfEncryptedBytes);
				LOGGER.debug("Asym encryption: Offsets: "+inputOffset+" outputOffset: "+outputOffset+" and index : "+index);				
			}
			
			//TODO remove print traces
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric encrypt");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric encrypt");
		} catch (BadPaddingException e) {
			e.printStackTrace();
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric encrypt");
		} catch (ShortBufferException e) {
			e.printStackTrace();
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric encrypt");
		}
		
	}
	
	public byte[] Sign(byte[] dataToSign, RSAPrivateKey senderPrivate) throws ServiceResultException{		
		SecurityPolicy policy = profile.getSecurityPolicy();
		
		//Default
		if(policy == SecurityPolicy.NONE){
			return null;
		}
		
		//Other policies use the same funktion...
		if (policy == SecurityPolicy.BASIC128RSA15 || policy == SecurityPolicy.BASIC256) {
			return rsaPkcs15Sha1_Sign(dataToSign, senderPrivate);
		}
		
		//TODO SecurityPolicy.Basic128
		//TODO SecurityPolicy.Basic192
		//TODO SecurityPolicy.Basic192Rsa15
		//TODO SecurityPolicy.Basic256Rsa15 
		
		throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, policy.getPolicyUri());			
	}
	
	private byte[] rsaPkcs15Sha1_Sign(byte[] dataToSign, RSAPrivateKey senderPrivate) throws ServiceResultException{
		//XXX now we only sign with basic256rsa15 and basic256
		try {
			Signature signer = Signature.getInstance("SHA1withRSA");
			signer.initSign(senderPrivate);
			//signer.update(dataToSign);
	        
			//compute hash of the message

			signer.update(dataToSign);
			byte[] signature = signer.sign();
			
			
			return signature;
			
			//TODO remove print traces
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} 
		throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in asymmetric Sign");
	}
	
	public boolean Verify(byte[] dataToVerify, Certificate signingCertificate, byte[] signature ) throws ServiceResultException{
		RSAPublicKey rsa = (RSAPublicKey) signingCertificate.getPublicKey();
		if(rsa == null){
			throw new ServiceResultException(StatusCodes.Bad_InternalError,"Error in symmetric Sign");
		}
		//computethe hash of message
		try {
			
			Signature verifier = Signature.getInstance("SHA1withRSA");
			verifier.initVerify(rsa);
			verifier.update(dataToVerify);
			if(verifier.verify(signature)){
				LOGGER.debug("Asym Signature Verify : OK");
			}
			else{
				LOGGER.error("Asymmetric Signature Verification fails");			
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}

}
