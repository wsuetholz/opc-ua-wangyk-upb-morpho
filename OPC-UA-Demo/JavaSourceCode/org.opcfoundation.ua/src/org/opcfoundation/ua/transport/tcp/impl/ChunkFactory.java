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
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.security.Key;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.common.RuntimeServiceResultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.transport.security.SecurityConfiguration;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.CryptoUtil;
import org.opcfoundation.ua.utils.bytebuffer.ByteBufferFactory;

/**
 * Chunk factory constructs byte buffers to be used for writing.
 * The byte buffer will be backed by an array that can fit the chunk.
 * The writable portion of the byte buffer (position -> limit) reflects 
 * to writable payload region.
 * <p>
 * Padding and the size of the message is pre-written to the chunk. 
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 * @author Mikko Salonen
 */
public class ChunkFactory extends ByteBufferFactory {

	public int maxChunkSize;
	public int maxPayloadSize;
	public int messageHeaderSize;
	public int securityHeader;
	public int sequenceHeader;
	public int cipherBlockSize;
	public int signatureSize;
	public MessageSecurityMode securityMode = MessageSecurityMode.Invalid;
	
	/** Logger */
	static Logger log = Logger.getLogger(ChunkFactory.class);
	
	public ChunkFactory(
		int maxChunkSize, 
		int messageHeaderSize,
		int securityHeaderSize, 
		int sequenceHeaderSize,
		int signatureSize,
		int cipherBlockSize,
		MessageSecurityMode securityMode)
	{
		this.maxChunkSize = maxChunkSize;
		this.messageHeaderSize = messageHeaderSize;
		this.securityHeader = securityHeaderSize;
		this.sequenceHeader = sequenceHeaderSize;
		this.cipherBlockSize = cipherBlockSize;
		this.signatureSize = signatureSize;
		this.securityMode = securityMode;
		
		if (securityMode==MessageSecurityMode.None || securityMode==MessageSecurityMode.Invalid)
		{
			maxPayloadSize = maxChunkSize - messageHeaderSize - securityHeaderSize - sequenceHeader;
			assert(signatureSize==0);
			assert(cipherBlockSize==1);
		} 
		else
		if (securityMode==MessageSecurityMode.Sign)
		{
			maxPayloadSize = maxChunkSize - messageHeaderSize - securityHeaderSize - sequenceHeader - signatureSize;
			assert(cipherBlockSize==1);
		} 
		if (securityMode==MessageSecurityMode.SignAndEncrypt)
		{			
			int minPaddingSize = 1;
			
			// Calculate max encrypt block size
			int maxEncryptBlockSize = maxChunkSize - messageHeaderSize - securityHeaderSize - minPaddingSize;
			maxEncryptBlockSize -= maxEncryptBlockSize % cipherBlockSize;						
			maxPayloadSize = maxEncryptBlockSize - sequenceHeaderSize - signatureSize - minPaddingSize; 
		} 
	}
	
	
	/**
	 * Allocate chunk. 
	 * 
	 * @return payload writeable byte buffer backed by byte[] size of the chunk. 
	 */
	public ByteBuffer allocate(int payloadSize) {
		payloadSize = Math.min(payloadSize, maxPayloadSize);
		int padding = 0;
		// calculate Padding
		if (securityMode == MessageSecurityMode.SignAndEncrypt) {
			
			int encryptedBlockSizeExcludingPadding = payloadSize + sequenceHeader + signatureSize;
			
			// Minimum encrypted block size
			int encryptedBlockSizeWithMinimalPadding = encryptedBlockSizeExcludingPadding + 1;
			
			// How many cipher blocks?
			int cipherBlockCount = (encryptedBlockSizeWithMinimalPadding / cipherBlockSize) + (encryptedBlockSizeWithMinimalPadding % cipherBlockSize == 0?0:1);
			
			padding = cipherBlockCount * cipherBlockSize - encryptedBlockSizeExcludingPadding;
		}
		
		int chunkSize = payloadSize + messageHeaderSize + securityHeader + sequenceHeader + signatureSize + padding;
		assert(chunkSize<=maxChunkSize);
		ByteBuffer result = ByteBuffer.allocate(chunkSize);
		result.order(ByteOrder.LITTLE_ENDIAN);
		
		// Write chunk size at position 4
		result.position(4);
		result.putInt(chunkSize);
		
		// Write padding
		if (padding>0) {
			result.position(messageHeaderSize + securityHeader + sequenceHeader + payloadSize);
			byte b = (byte) (padding-1);
			for (int i=0; i<padding; i++)
				result.put(b);
		}
		
		// Change limit and offset
		result.position(messageHeaderSize + securityHeader + sequenceHeader);
		result = result.slice(); // Slice forgets byte order
		result.order(ByteOrder.LITTLE_ENDIAN);
		result.limit(payloadSize);				
		return result;
	}

	public void signChunk(ByteBuffer chunk)
	{
		
	}
	
	public void encryptChunk(ByteBuffer chunk)
	{
		
	}
	
	/**
	 * Expand allocated bytebuffer to complete chunk.
	 * 
	 * ByteBuffer allocated with allocate() returns a buffer that 
	 * has only payload as writable portion. This method expands the 
	 * ByteBuffer to include header and footer.
	 * 
	 * The result is rewound. 
	 *  
	 * @param payload
	 * @return chunk
	 */
	public ByteBuffer expandToCompleteChunk(ByteBuffer payload)
	{ 
		return ByteBuffer.wrap(payload.array()).order(ByteOrder.LITTLE_ENDIAN);
	}

	public ByteBuffer[] expandToCompleteChunk(ByteBuffer[] payloads)
	{ 
		ByteBuffer[] chunks = new ByteBuffer[payloads.length];
		for (int i=0; i<chunks.length; i++)
			chunks[i] = expandToCompleteChunk(payloads[i]); 
		return chunks;
	}
	
	public static class HelloChunkFactory extends ChunkFactory {
		public HelloChunkFactory() {
			super(8192, 8, 0, 0, 0, 0, MessageSecurityMode.Invalid);
			maxChunkSize = 8192;
			messageHeaderSize = 8;
			maxPayloadSize = maxChunkSize - 8; 
		}
		
	}
	
	public static class AcknowledgeChunkFactory extends ChunkFactory {
		public AcknowledgeChunkFactory() {
			super(8192, 8, 0, 0, 0, 1, MessageSecurityMode.Invalid);
			maxChunkSize = 8192;
			messageHeaderSize = 8;
			maxPayloadSize = maxChunkSize - 8; 
		}		
	}
	
	public static class ErrorMessageChunkFactory extends ChunkFactory {
		public ErrorMessageChunkFactory() {
			super(4096+4, 8, 0, 0, 0, 1, MessageSecurityMode.Invalid);
			maxChunkSize = 4096+4+8;
			messageHeaderSize = 8;
			maxPayloadSize = 4096+4 - 8; 
		}		
	}
	/*
	public static class SecureChannelChunkFactory extends ChunkFactory {
		SecurityToken token;
		int requestId;
		public SecureChannelChunkFactory(int maxChunkSize, SecurityToken token)
		{
			super(maxChunkSize, 8, 8, 8, token.getSignatureSize(), token.getCipherBlockSize(), token.getMessageSecurityMode());
			this.token = token;
		}
		public SecurityToken getToken() {
			return token;
		}
		public int getRequestId() {
			return requestId;
		}
		public void setRequestId(int requestId) {
			this.requestId = requestId;
		}
	}

	//TODO ADD ALLOCATE
*/	
	

	public static class AsymmMsgChunkFactory extends ChunkFactory {
		private static final Charset UTF8 = Charset.forName("utf-8");
		SecurityConfiguration profile;
		 
		public AsymmMsgChunkFactory(
				int maxChunkSize, 
				SecurityConfiguration profile) throws ServiceResultException {
			super(
				maxChunkSize, 
				12, 
				12 + 
				profile.getSecurityPolicy().getEncodedPolicyUri().length +
				(profile.getEncodedLocalCertificate()!=null ? profile.getEncodedLocalCertificate().length : 0) +
				(profile.getEncodedRemoteCertificateThumbprint()!=null ? profile.getEncodedRemoteCertificateThumbprint().length : 0), 
				8,

				// Asymm Signature Size
				profile.getMessageSecurityMode().hasSigning() ?
				CryptoUtil.getSignatureSize( profile.getSecurityPolicy().getAsymmetricSignatureAlgorithmUri(), profile.getLocalPrivateKey() ) :0,
				
				// Cipher block size
				profile.getMessageSecurityMode() != MessageSecurityMode.None ?
				CryptoUtil.getCipherBlockSize(
						profile.getSecurityPolicy().getAsymmetricEncryptionAlgorithmUri(), 
						profile.getRemoteCertificate().getPublicKey()  
						) : 1,
				MessageSecurityMode.SignAndEncrypt
			);
		
			this.profile = profile;
		}
		
		@Override
		public ByteBuffer allocate(int payloadSize) {
			payloadSize = Math.min(payloadSize, maxPayloadSize);
			int padding = 0;
			int encryptedBlocks = -1; //initialize blocksize and ciphertext size
			int cipherTextSize = -1;
			int encryptPlainTextSize = payloadSize + sequenceHeader;
			
			int plainTextBlockSize = 1;					
			try {
				SecurityPolicy policy = profile.getSecurityPolicy();
				MessageSecurityMode mode = profile.getMessageSecurityMode();
				
				if (policy != SecurityPolicy.NONE) {
					Key key = profile.getReceiverCertificate().getPublicKey();
					plainTextBlockSize = CryptoUtil.getPlainTextBlockSize(policy.getAsymmetricEncryptionAlgorithmUri(), key);					
				}
				
			} catch (ServiceResultException e) {
				throw new RuntimeServiceResultException(e);
			}
			
			int chunkSize = -1;
				
			
			//TODO Remove padding calculation to ChunkCrypterSigner
			
			if (securityMode == MessageSecurityMode.SignAndEncrypt) {
				//Sign and encrypt...so add the signatureSize to plainttext size
				 encryptPlainTextSize += signatureSize;
				 
				//add place for padding (size)..
				encryptPlainTextSize++;
				
				//calculate padding
	            if (encryptPlainTextSize%plainTextBlockSize != 0)
	            {
//	            	log.debug("AsymmMSGChunkFactory: calculating padding, plainTextSize%plainTextBlockSize = "+encryptPlainTextSize%plainTextBlockSize);
	                padding += plainTextBlockSize - (encryptPlainTextSize%plainTextBlockSize);
	            }
	            //update plaintextsize that needs to be encrypted
	            encryptPlainTextSize += padding;
	            
	            encryptedBlocks = encryptPlainTextSize/plainTextBlockSize; //TODO Check that PlainTextBlockSize is not null
				cipherTextSize = encryptedBlocks*cipherBlockSize;
				
			}
			else if(securityMode == MessageSecurityMode.Sign){
				//Only signing is used, so no padding, but signatureSize must be added
				encryptPlainTextSize +=signatureSize;
				
				
			}
			
			if(securityMode != MessageSecurityMode.SignAndEncrypt){
				chunkSize = messageHeaderSize + securityHeader +  encryptPlainTextSize;//By default chunksize is this (without encryption)
			}
			else{
				//Encyption must be notest here!!!
				
				//!!!Calculate new chunksize, which adds bytes that encryption algorithm appends to plaintext!!!
				//calculate the number of blocks to encrypt and size of the encrypted data
				//Example..if plaintext size is 234 and block size is 117, then we need to 
				//encrypt 2 blocks
				
				
				//Update chunkSize
				chunkSize = messageHeaderSize + securityHeader +  cipherTextSize;
			}
			
			
			
			
			ByteBuffer result = ByteBuffer.allocate(chunkSize);
			result.order(ByteOrder.LITTLE_ENDIAN);
			
			// Write chunk size at position 4
			result.position(4);
			result.putInt(chunkSize);
			
			// Write padding
			if (padding>0) {
				result.position(messageHeaderSize + securityHeader + sequenceHeader + payloadSize);
				//byte b = (byte) (padding-1);
				for(int i=0; i<=padding; i++){
					result.put((byte)padding);
				}
			}
			
			// Change limit and offset
			result.position(messageHeaderSize + securityHeader + sequenceHeader);
			result = result.slice(); // Slice forgets byte order
			result.order(ByteOrder.LITTLE_ENDIAN);
			result.limit(payloadSize);				
			return result;
			//return super.allocate(arg0);
		}
	}

}
