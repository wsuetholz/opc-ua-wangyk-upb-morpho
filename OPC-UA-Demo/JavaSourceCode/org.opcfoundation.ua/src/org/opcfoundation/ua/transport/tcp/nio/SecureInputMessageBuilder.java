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

package org.opcfoundation.ua.transport.tcp.nio;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.encoding.EncoderContext;
import org.opcfoundation.ua.encoding.IEncodeable;
import org.opcfoundation.ua.encoding.binary.BinaryDecoder;
import org.opcfoundation.ua.transport.security.SecurityConfiguration;
import org.opcfoundation.ua.transport.tcp.impl.ChunkAsymmDecryptVerifier;
import org.opcfoundation.ua.transport.tcp.impl.ChunkSymmDecryptVerifier;
import org.opcfoundation.ua.transport.tcp.impl.ChunkUtils;
import org.opcfoundation.ua.transport.tcp.impl.SecurityToken;
import org.opcfoundation.ua.transport.tcp.impl.TcpConnectionParameters;
import org.opcfoundation.ua.transport.tcp.impl.TcpMessageType;
import org.opcfoundation.ua.utils.StackUtils;
import org.opcfoundation.ua.utils.bytebuffer.IncubationBuffer;
import org.opcfoundation.ua.utils.bytebuffer.InputStreamReadable;

/**
 * SecureInputMessageBuilder deciphers and decodes chunks into messages.
 * <p>
 * Message is decoded and chunks are deciphered and validated in background thread.
 * Deciphering is executed in StackUtils.getNonBlockerExecutor() which has one thread for each CPU core.  
 * Decoding is executed in StackUtils.getBlockerExecutor() which creates new threads as needed.  
 */
public class SecureInputMessageBuilder implements InputMessage {
	
	/** Message completition / error callback listener */
	MessageListener								listener;
	/** Token, {@link SecurityToken} if symmetric, {@link SecurityConfiguration} if asymmetric encryption */
	Object										token;
	/** Chunk assumptions from hand-shake */
	TcpConnectionParameters						ctx;
	/** Encoder Parameters */
	EncoderContext								encoderCtx;
	/** Stored error */
	Exception									error;
	/** Producer for decoder, consumer for chunk validator&decrypter */
	IncubationBuffer				chunkSink;
//	OrderedByteBufferInputStream chunkSink;
	/** Decode work */
	Runnable									messageDecoderRun;
	/** Chunks added counter */
	int											chunksAdded;
	/** The end result */
	IEncodeable									msg;
	Integer										requestId;
	Integer										securityChannelId;
	int											messageType;
	boolean										acceptsChunks = true; // set to false when final chunk is added  
	boolean										done; // set to true when the whole message is decoded or until an error occurs 
	String										securityPolicyUri;
	byte[]										senderCertificate;
	byte[]										receiverCertificateThumbPrint;
	List<Integer>								chunkSequenceNumbers = new ArrayList<Integer>(1);
	AtomicInteger								expectedSequenceNumber;
	static Logger 								log = Logger.getLogger(SecureInputMessageBuilder.class);

	public interface MessageListener {
		/**
		 * On message completed or error occured. 
		 * Use {@link InputMessage#getMessage()} to get the message, 
		 * if null get the error with {@link InputMessage#getError()}. 
		 * 
		 * @param sender 
		 */
		void onMessageComplete(InputMessage sender);
	}
	
	/**
	 * Create message builder. Message builder compiles inbound chunks into a message.
	 * 
	 * @param token {@link SecurityToken} (symm) or {@link SecurityConfiguration} (asymm) 
	 * @param listener
	 * @param ctx
	 * @param expectedSequenceNumber
	 */
	public SecureInputMessageBuilder(Object token, MessageListener listener, TcpConnectionParameters ctx, EncoderContext encoderCtx, AtomicInteger expectedSequenceNumber)
	{
		assert(token!=null);
		this.listener = listener;
		this.token = token;
		this.ctx = ctx;
		this.encoderCtx = encoderCtx;
		
		this.expectedSequenceNumber = expectedSequenceNumber;
		log.debug("SecureInputMessageBuilder: expectedSequenceNumber="+expectedSequenceNumber);
		// chunkSink is a byte input stream that is handed over to message decoder
		// New bytes become available as chunks are added by handleChunkRuns (see addChunk()). 
		chunkSink = new IncubationBuffer();		
//		chunkSink = new OrderedByteBufferInputStream();
		int maxRecvSize = ctx.maxRecvMessageSize==0 ? Integer.MAX_VALUE : ctx.maxRecvMessageSize;
		InputStreamReadable isr = new InputStreamReadable(chunkSink, maxRecvSize);
		isr.order(ByteOrder.LITTLE_ENDIAN);		
		final BinaryDecoder messageDecoder = new BinaryDecoder(isr);
		messageDecoder.setEncoderContext(encoderCtx);
		
		// Runnable that starts decoding the message. 
		// It is started in a thread right after the first chunk is added (addChunk())
		messageDecoderRun = new Runnable() {
			public void run() {				
				try {					
					// Decode the message using the chunk sink (set in dec)
					// Decoding proceeds as chunks are added to the chunk sink. 
					IEncodeable message = messageDecoder.getMessage();
					
					// assert sequence numbers are consecutive
					if (!(SecureInputMessageBuilder.this.token instanceof SecurityToken))
						for (int i=1; i<chunkSequenceNumbers.size(); i++)
							if (chunkSequenceNumbers.get(i) != chunkSequenceNumbers.get(i-1)-1) {
								String msg = "Sequence numbers of chunks are not consecutive";
								log.error(msg);
								setError(new ServiceResultException(msg));
								return;
							}
					
					// Notify listener that message is ready
					setMessage( message );
				} catch (Exception e) {
					// Notify listener about an error
					setError(e);
				}
			}};
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("token="+token);
		sb.append(", secureChannelId="+securityChannelId);
		sb.append(", more="+moreChunksRequired());
		return sb.toString();
	}

	public synchronized void addChunk(final ByteBuffer chunk) throws ServiceResultException
	{
		if (!acceptsChunks) throw new ServiceResultException(StatusCodes.Bad_UnexpectedError, "Final chunk added to message builder");
		final int chunkNumber = chunksAdded++;	
		chunkSequenceNumbers.add(null);
		int type = ChunkUtils.getMessageType(chunk);
		int messageType = type & TcpMessageType.MESSAGE_TYPE_MASK;
		int chunkType = type & TcpMessageType.CHUNK_TYPE_MASK;
		if (chunkType == TcpMessageType.FINAL) acceptsChunks = false;
		final Integer expectedSequenceNumber = this.expectedSequenceNumber!=null ? this.expectedSequenceNumber.getAndIncrement() : null;
			log.debug("addChunk: expectedSequenceNumber="+expectedSequenceNumber);
		if (chunkType == TcpMessageType.ABORT) {
			setMessage(null);
		}
		
		if (chunkNumber==0) {
			this.messageType = messageType;
			this.securityChannelId = ChunkUtils.getSecureChannelId(chunk);
		}		
		
		chunkSink.incubate(chunk);
		Runnable handleChunkRun = new Runnable() {
			public void run() {
				if (error!=null) return;
				try {	
					log.debug("token: "+token);
					if (token instanceof SecurityToken)
						new ChunkSymmDecryptVerifier(chunk, (SecurityToken)token).run();
					else if (token instanceof SecurityConfiguration) {
						ChunkAsymmDecryptVerifier asdf = new ChunkAsymmDecryptVerifier(chunk, (SecurityConfiguration)token);
						asdf.run();						
						securityPolicyUri = asdf.getSecurityPolicyUri();
						senderCertificate = asdf.getSenderCertificate();
						receiverCertificateThumbPrint = asdf.getReceiverCertificateThumbprint();
					}
					
					int pos = chunk.position();
					byte[] dada = new byte[chunk.remaining()];
					chunk.get(dada);
					chunk.position(pos);
					
					int payloadStart = chunk.position();
					chunk.position(payloadStart-8);
					int chunkSequenceNumber = chunk.getInt();
					chunkSequenceNumbers.set(chunkNumber, chunkSequenceNumber);
					if (expectedSequenceNumber!=null && expectedSequenceNumber!=chunkSequenceNumber)
					{
						log.error("chunkSequenceNumber="+chunkSequenceNumber+", expectedSequenceNumber="+expectedSequenceNumber);
						throw new ServiceResultException(StatusCodes.Bad_UnexpectedError, "chunkSequenceNumber="+chunkSequenceNumber+", expectedSequenceNumber="+expectedSequenceNumber);
					}
					int requestId = chunk.getInt();
					setRequestId( requestId );

					// verify secure channel id
					int secureChannelId = ChunkUtils.getSecureChannelId(chunk);
					if (secureChannelId!=SecureInputMessageBuilder.this.securityChannelId)
						throw new ServiceResultException(StatusCodes.Bad_UnexpectedError, "secureChannelId="+secureChannelId+", expected Id");
					
					chunk.position(payloadStart);
					chunkSink.hatch(chunk);
//					chunkSink.offer(chunkNumber, chunk);
				} catch (Exception e) {
					e.printStackTrace();
					chunkSink.forceClose();
					setError(e);
				}				
			}};
			
		// Validate chunk
		StackUtils.getNonBlockingWorkExecutor().execute(handleChunkRun);
		
		// Start decoding message
		if (chunkNumber==0)
			StackUtils.getBlockingWorkExecutor().execute(messageDecoderRun);		
	}	
	
	protected void fireComplete() {
		if (listener!=null) listener.onMessageComplete(this);
	}
	
	protected synchronized void setError(Exception e)
	{
		if (done) {
			e.printStackTrace();
			return;
		}
		done = true;
		this.error = e;
		chunkSink.forceClose();
		fireComplete();
	}	
	
	protected synchronized void setMessage(IEncodeable msg)
	{
		if (done) return;
		chunkSink.close();
		done = true;
		this.msg = msg;
		fireComplete();
	}
	
	private synchronized void setRequestId(int requestId) throws ServiceResultException 
	{
		if (this.requestId!=null && this.requestId!=requestId)
			throw new ServiceResultException(StatusCodes.Bad_UnexpectedError);
		this.requestId = requestId;
	}
	
	public int getRequestId() {
		return requestId;
	}
	
	public synchronized boolean isDone() {
		return done;
	}
	
	public synchronized boolean moreChunksRequired() {
		return acceptsChunks;
	}
	
	public void close() {
		if (done) return;
		done = true;
		chunkSink.forceClose();
	}
	
	public IEncodeable getMessage() {
		return msg;
	}
	
	public Exception getError() {
		return error;
	}
		
	public int getMessageType() {
		return messageType;
	}
	
	public int getSecureChannelId() {
		return securityChannelId;
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
	 * Return sequence number of each chunk
	 * @return list of sequnce numbers
	 */
	public List<Integer> getSequenceNumbers() {
		return chunkSequenceNumbers;
	}

	@Override
	public Object getToken() {
		return token;
	}
	
}