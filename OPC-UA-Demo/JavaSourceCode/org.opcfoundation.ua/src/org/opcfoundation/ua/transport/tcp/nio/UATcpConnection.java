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

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.encoding.EncoderContext;
import org.opcfoundation.ua.encoding.EncoderMode;
import org.opcfoundation.ua.encoding.IEncodeable;
import org.opcfoundation.ua.encoding.binary.BinaryEncoder;
import org.opcfoundation.ua.encoding.binary.EncoderCalc;
import org.opcfoundation.ua.transport.AsyncWrite;
import org.opcfoundation.ua.transport.CloseableObject;
import org.opcfoundation.ua.transport.CloseableObjectState;
import org.opcfoundation.ua.transport.Connection;
import org.opcfoundation.ua.transport.IConnectionListener;
import org.opcfoundation.ua.transport.ServerSecureChannel;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.SecurityConfiguration;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.transport.tcp.impl.Acknowledge;
import org.opcfoundation.ua.transport.tcp.impl.ChunkAsymmEncryptSigner;
import org.opcfoundation.ua.transport.tcp.impl.ChunkFactory;
import org.opcfoundation.ua.transport.tcp.impl.ChunkSymmEncryptSigner;
import org.opcfoundation.ua.transport.tcp.impl.ChunkUtils;
import org.opcfoundation.ua.transport.tcp.impl.ErrorMessage;
import org.opcfoundation.ua.transport.tcp.impl.Hello;
import org.opcfoundation.ua.transport.tcp.impl.SecurityToken;
import org.opcfoundation.ua.transport.tcp.impl.TcpConnectionParameters;
import org.opcfoundation.ua.transport.tcp.impl.TcpMessageType;
import org.opcfoundation.ua.transport.tcp.impl.ChunkFactory.AcknowledgeChunkFactory;
import org.opcfoundation.ua.transport.tcp.impl.ChunkFactory.ErrorMessageChunkFactory;
import org.opcfoundation.ua.transport.tcp.nio.Channel.ChannelListener;
import org.opcfoundation.ua.transport.tcp.nio.SecureInputMessageBuilder.MessageListener;
import org.opcfoundation.ua.transport.tcp.nio.UATcpServer.UATcpServerConnection;
import org.opcfoundation.ua.utils.AbstractState;
import org.opcfoundation.ua.utils.CryptoUtil;
import org.opcfoundation.ua.utils.IStatefulObject;
import org.opcfoundation.ua.utils.IncubationQueue;
import org.opcfoundation.ua.utils.StackUtils;
import org.opcfoundation.ua.utils.StateListener;
import org.opcfoundation.ua.utils.asyncsocket.AsyncInputStream;
import org.opcfoundation.ua.utils.asyncsocket.AsyncSocket;
import org.opcfoundation.ua.utils.asyncsocket.BufferMonitorState;
import org.opcfoundation.ua.utils.asyncsocket.MonitorListener;
import org.opcfoundation.ua.utils.asyncsocket.SocketState;
import org.opcfoundation.ua.utils.bytebuffer.ByteBufferArrayWriteable2;
import org.opcfoundation.ua.utils.bytebuffer.ByteBufferArrayWriteable2.ChunkListener;

/**
 * This class contains mechanisms that is commont to its sub-classes {@link UATcpClientConnection} and {@link UATcpServerConnection}.
 * 
 * Common mechanisms are:
 *  - Sending & Receiving Chunks
 *  - Sending & Receiving Messages
 *  - Encryption & Decryption
 *  - Socket and connection state 
 *  - SecureChannels, Listening of secure channels 
 *  - Connection Parameters
 *  - Sequence Numbers
 */
public abstract class UATcpConnection extends AbstractState<CloseableObjectState, ServiceResultException> implements Connection, CloseableObject {
	
	/** Protocol Version after hand shake */
	int agreedProtocolVersion = 0;
	/** Security settings for asymmetric encryption */
	SecurityConfiguration securityConfiguration;
	/** Event based asynchronous socket */
	AsyncSocket s;	
	/** Socket connect/disconnect state change listener */
	StateListener<SocketState> socketListener;
	/** Connection parameters */
	TcpConnectionParameters ctx = new TcpConnectionParameters();
	/** Encoder params */
	EncoderContext encoderCtx = EncoderContext.getDefault();
	/** Message builder, complies chunks into complete messages */
	SecureInputMessageBuilder secureMessageBuilder;
	/** List of secure channels open in this connection */
	Map<Integer, ServerSecureChannel> secureChannels = Collections.synchronizedMap( new HashMap<Integer, ServerSecureChannel>() );
	/** List of secure channel listener */
	CopyOnWriteArrayList<SecureChannelListener> secureChannelListeners = new CopyOnWriteArrayList<SecureChannelListener>();	
	/** Logger */
	static Logger log = Logger.getLogger(UATcpConnection.class);
	/** Chunk incubate (are encoded and signed) before sending to stream */
	IncubationQueue<ByteBuffer> chunkIncubator = new IncubationQueue<ByteBuffer>(true);

	CopyOnWriteArrayList<ChannelListener> channelListeners = new CopyOnWriteArrayList<ChannelListener>();
	
	CopyOnWriteArrayList<IConnectionListener> connectionListeners = new CopyOnWriteArrayList<IConnectionListener>();
	
	
	UATcpConnection(AsyncSocket s)
	{
		super(CloseableObjectState.Closed);
		this.s = s;
		
		// Monitor the state of the socket, make changes reflect to the state of the UATcpConnection
		StateListener<SocketState> socketListener =
			new StateListener<SocketState>() {
				@Override
				public void onStateTransition(IStatefulObject<SocketState, ?> monitor, SocketState oldState, SocketState newState) {
					if (newState==SocketState.Error) 
					{
						setError( StackUtils.toServiceResultException( UATcpConnection.this.s.getStateMonitor().getError() ) );
					}				
					if (newState==SocketState.Closed)
					{
						close();
					}
				}
		};
		s.getStateMonitor().addStateListener(socketListener);
		
		s.getInputStream().createMonitor(8, inputListener);
	}
	
	@Override
	public SocketAddress getLocalAddress() {
		Socket socket = s.socket();
		if (socket==null) return null;
		return socket.getLocalSocketAddress();
	}

	@Override
	public SocketAddress getRemoteAddress() {
		Socket socket = s.socket();
		if (socket==null) return null;
		return socket.getRemoteSocketAddress();
	}

	public synchronized CloseableObject close() {
//		CloseableObjectState state = getState();
//		if (state==CloseableObjectState.Closed) return this;
		try {
			setState(CloseableObjectState.Closing);
		} finally {
			try {
				s.close();
			} catch (IOException e) {
			}
			setState(CloseableObjectState.Closed);
		}
		return this;
	}
	
		
	// Handles incoming data //	
	MonitorListener inputListener =
		new MonitorListener() {
			@Override
			public void onStateTransition(IStatefulObject<BufferMonitorState, ?> sender,
					BufferMonitorState oldState, BufferMonitorState newState) {
				
				// Trigger is unreachable
				if (newState.isUnreachable()) {
					if (secureMessageBuilder!=null) {
						secureMessageBuilder.close();
						secureMessageBuilder = null;
					}
					return;
				}
				
				if (newState != BufferMonitorState.Triggered) 
				{
					System.out.println("Unexpected trigger state "+newState);
					return;
				}
					
				// -- assert -- atleast 8 bytes are available --
				
				AsyncInputStream is = s.getInputStream(); 
				ByteBuffer hdr = is.peek(8);
				hdr.order(ByteOrder.LITTLE_ENDIAN);
				hdr.getInt();
				int chunkSize = hdr.getInt();
				
				if (chunkSize<12) {
					setError(StatusCodes.Bad_TcpInternalError);
					if (secureMessageBuilder!=null) 
						secureMessageBuilder.close();
					return;
				}
				
				if (chunkSize > ctx.maxRecvChunkSize)
				{
					if (!hasError())
					try {
						sendError(new ErrorMessage(StatusCodes.Bad_CommunicationError, "Chunk size ("+chunkSize+") exceeded maximum ("+ctx.maxRecvChunkSize+")"));
					} catch (Exception e) {
					}
					setError(StatusCodes.Bad_TcpMessageTooLarge);
					if (secureMessageBuilder!=null) 
						secureMessageBuilder.close();
					return;
				}
				
				if (is.available()>=chunkSize) {
					// Chunk is readable
					ByteBuffer chunk = is.read(chunkSize);					
					chunk.rewind();
					try {
						onChunk(chunk);
					} catch (ServiceResultException se) {
						se.printStackTrace();
						setError(se);
					} catch (RuntimeException e) {
						log.debug(e, e);
						log.error( "Unexpected Error: ", e );
						setError( StackUtils.toServiceResultException(e) );
					}
					
					// Wait for next chunk header
					is.createMonitor(is.getPosition()+8, this);

				} else {
					// Wake me up when the chunk is fully readable
					is.createMonitor(is.getPosition()+chunkSize, this);					
				}
			}
	};
		
	protected void onChunk(ByteBuffer chunk) throws ServiceResultException {
		int type = ChunkUtils.getMessageType(chunk);		
		int messageType = type & TcpMessageType.MESSAGE_TYPE_MASK;
		// Secure message
		if (messageType == TcpMessageType.MESSAGE) {
			onSecureChunk(chunk);			
		} else if (messageType == TcpMessageType.CLOSE) {
			onCloseChunk(chunk);			
		} else if (messageType == TcpMessageType.OPEN) {
			onAsymmSecureChunk(chunk);			
		} else if (messageType == TcpMessageType.HELLO || messageType == TcpMessageType.ACKNOWLEDGE || messageType == TcpMessageType.ERROR) {
			onRawChunk(chunk);
		} else {
			// Unknown chunk
			close();
		}
	}

	protected void onRawChunk(ByteBuffer chunk) {
		int type = ChunkUtils.getMessageType(chunk);
		int messageType = type & TcpMessageType.MESSAGE_TYPE_MASK;
		int chunkType = type & TcpMessageType.CHUNK_TYPE_MASK;
		if (chunkType != TcpMessageType.FINAL) {
			close();
		}
		chunk.position(8);
		try {
			if (messageType == TcpMessageType.HELLO) {
				ChunksToMessage c2m = new ChunksToMessage(ctx, encoderCtx, Hello.class, chunk);
				onHello( (Hello) c2m.call() );
			} else if (messageType == TcpMessageType.ACKNOWLEDGE) {
				ChunksToMessage c2m = new ChunksToMessage(ctx, encoderCtx, Acknowledge.class, chunk);
				onAcknowledge( (Acknowledge) c2m.call() );
			} else if (messageType == TcpMessageType.ERROR) {
				ChunksToMessage c2m = new ChunksToMessage(ctx, encoderCtx, ErrorMessage.class, chunk);
				onError( (ErrorMessage) c2m.call() );
			}
		} catch (Exception e) {
			setError( StackUtils.toServiceResultException(e) );
		}
	}
	
	protected void onCloseChunk(ByteBuffer chunk) throws ServiceResultException {
		close();
	}
	
	protected void onSecureChunk(ByteBuffer chunk) throws ServiceResultException {
		int secureChannelId = ChunkUtils.getSecureChannelId(chunk);
		int tokenId = ChunkUtils.getTokenId(chunk);		
		chunk.rewind();
		
		UATcpSecureChannel channel = (UATcpSecureChannel) secureChannels.get(secureChannelId);
		if (channel==null) 
			throw new ServiceResultException(StatusCodes.Bad_TcpSecureChannelUnknown);
		SecurityToken token = channel.getSecurityToken(tokenId);
		if (token==null) 
			throw new ServiceResultException(StatusCodes.Bad_SecureChannelTokenUnknown);
		if (!token.isValid()) 
			token = channel.getLatestNonExpiredToken();
		if (token==null || !token.isValid()) {
			System.err.println("Token expired");
			throw new ServiceResultException(StatusCodes.Bad_SecureChannelClosed);
		}
		
		SecurityToken activeToken = channel.getActiveSecurityToken();
		if (token!=activeToken) {
			log.debug("activeToken="+activeToken+", token="+token);
			if (activeToken.getCreationTime() < token.getCreationTime()) {
				channel.setActiveSecurityToken(token);			
			}
		}
		log.debug("secureMessageBuilder: "+secureMessageBuilder);
		if (secureMessageBuilder!=null && !secureMessageBuilder.moreChunksRequired()) secureMessageBuilder = null;
		if (secureMessageBuilder==null) {
			secureMessageBuilder = new SecureInputMessageBuilder(token/*channel*/, messageListener, ctx, encoderCtx, channel.recvSequenceNumber);
			log.debug("new secureMessageBuilder: "+secureMessageBuilder);
//			onSecureMessageBegin(secureMessageBuilder, chunk);
		}

		secureMessageBuilder.addChunk(chunk);
	}
	
	protected abstract void onAsymmSecureChunk(ByteBuffer chunk) throws ServiceResultException;

	// Handle incoming messages //
	MessageListener messageListener = new MessageListener() {
		public void onMessageComplete(InputMessage sender) {			
			IEncodeable msg = sender.getMessage();

			for (ChannelListener cl : channelListeners) 
				if (cl.handleMessage(sender)) return;
			
			// Handler error
			if (msg==null) {
				Exception error = sender.getError();
				if (error == null) return; // aborted;
				setError( StackUtils.toServiceResultException(error) );
			}
			
			// Handle message
			try {
				if (sender.getMessageType() == TcpMessageType.MESSAGE) {
					onSecureMessage(sender);
				} else if (sender.getMessageType() == TcpMessageType.CLOSE) {
					onCloseChannel(sender);
				} else if (sender.getMessageType() == TcpMessageType.OPEN) {
					onOpenChannel(sender);
				}
			} catch (ServiceResultException e) {
				// Handle message failed. Disconnect.
//				log.log(Level.INFO, e.getMessage());
				try {
					sendError(new ErrorMessage(e.getStatusCode(), e.getMessage()));
				} catch (ServiceResultException e1) {
				}
				setError(e);
			}
		}};	
	protected abstract void onError(ErrorMessage e);
	protected abstract void onHello(Hello h) throws ServiceResultException;
	protected abstract void onAcknowledge(Acknowledge a) throws ServiceResultException;
	protected abstract void onSecureMessage(InputMessage mb) throws ServiceResultException;
	protected abstract void onCloseChannel(InputMessage mb) throws ServiceResultException;
	protected abstract void onOpenChannel(InputMessage mb) throws ServiceResultException;
	/** Remote Certificate Validator, invoked upon connect */
	protected abstract CertificateValidator getRemoteCertificateValidator();	
	
	
	/**
	 * Send chunks.
	 * 
	 * @param chunks
	 * @return stream position after these chunks
	 */
	protected synchronized void sendChunks(ByteBuffer...chunks)
	{
		startChunkSend(chunks);		
		for (ByteBuffer chunk : chunks)
			endChunkSend(chunk);
	}
	
	/**
	 * Puts chunks into send queue. Chunks will be given a sequence number 
	 * but will be flushed in endChunkSend().  
	 * 
	 * @param chunks 
	 * @return sequence number for the first chunk
	 */
	protected void startChunkSend(ByteBuffer...chunks)
	{		
		synchronized(chunkIncubator) {
			for (ByteBuffer chunk : chunks)
				chunkIncubator.incubate(chunk);
		}
	}
	
	/**
	 * Flushes queued chunks (see startChunkSend())
	 *  
	 * @param chunk chunk to send
	 * @return the stream position after this chunk is flushed
	 */
	protected void endChunkSend(ByteBuffer chunk)
	{
		chunkIncubator.hatch(chunk);
		synchronized(this) {
			while (chunkIncubator.nextIsHatched()) {
				ByteBuffer c = chunkIncubator.removeNextHatchedIfAvailable();
				c.rewind();
				s.getOutputStream().offer(c);			
			}
		}
	}
	
	protected BufferMonitorState flush(long position)
	throws InterruptedException, IOException
	{		
		return s.getOutputStream().createMonitor(position, null).waitForState(BufferMonitorState.FINAL_STATES);
	}
	
	protected void sendHello(Hello h)
	{		
		ctx.endpointUrl = h.getEndpointUrl();
		ChunkFactory rawChunkFactory = new ChunkFactory(ctx.maxSendChunkSize, 8, 0, 0, 0, 1, MessageSecurityMode.None); 		
		//ChunkFactory rawChunkFactory = new HelloChunkFactory(); 		
		MessageToChunks mc = new MessageToChunks(h, ctx, encoderCtx, rawChunkFactory, MessageType.Encodeable);
		final ByteBuffer[] payloads = mc.call();
		final ByteBuffer[] chunks = rawChunkFactory.expandToCompleteChunk(payloads);
		assert(chunks.length==1);
		
		// Set header and write
		chunks[0].putInt(TcpMessageType.HELLO | TcpMessageType.FINAL);
		chunks[0].rewind();
		sendChunks(chunks);
	}
	
	protected void sendAcknowledge(Acknowledge a) 
	throws ServiceResultException 
	{
		ChunkFactory rawChunkFactory = new AcknowledgeChunkFactory(); 		
		MessageToChunks mc = new MessageToChunks(a, ctx, encoderCtx, rawChunkFactory, MessageType.Encodeable);
		final ByteBuffer[] payloads = mc.call();
		final ByteBuffer[] chunks = rawChunkFactory.expandToCompleteChunk(payloads);
		assert(chunks.length==1);
		
		// Set header and write
		chunks[0].putInt(TcpMessageType.ACKNOWLEDGE | TcpMessageType.FINAL);
		chunks[0].rewind();
		sendChunks(chunks);
	}

	protected void sendError(ErrorMessage e) 
	throws ServiceResultException 
	{
		ChunkFactory rawChunkFactory = new ErrorMessageChunkFactory(); 		
		MessageToChunks mc = new MessageToChunks(e, ctx, encoderCtx, rawChunkFactory, MessageType.Encodeable);
		final ByteBuffer[] payloads = mc.call();
		final ByteBuffer[] chunks = rawChunkFactory.expandToCompleteChunk(payloads);
		assert(chunks.length==1);
		
		// Set header and write
		chunks[0].putInt(TcpMessageType.ERROR | TcpMessageType.FINAL);
		chunks[0].rewind();
		sendChunks(chunks);
	}

	/**
	 * Send asymmetric secure message.  
	 * 
	 * @param msg
	 * @param securityConfiguration
	 * @param secureChannelId
	 * @param requestNumber
	 * @param sequenceNumber sequence number
	 * @return number of chunks 
	 * @throws ServiceResultException
	 */
	protected int sendAsymmSecureMessage(
			final AsyncWrite msg, 
			final SecurityConfiguration securityConfiguration,
			int secureChannelId,
			int requestNumber,
			AtomicInteger sendSequenceNumber)
	throws ServiceResultException
	{
		synchronized(msg) {
			if (msg.isCanceled()) return -1;
			msg.setQueued();
		}
		ChunkFactory cf = null;
		// No security chunk factory
		if (securityConfiguration.getMessageSecurityMode() == MessageSecurityMode.None) {
			cf = new ChunkFactory.AsymmMsgChunkFactory(ctx.maxSendChunkSize, securityConfiguration);
		} else {
			// Security chunk factory
 			cf = new ChunkFactory.AsymmMsgChunkFactory(ctx.maxSendChunkSize, securityConfiguration);
		}
		
		MessageToChunks mc = new MessageToChunks(msg.getMessage(), ctx, encoderCtx, cf, MessageType.Message);
		final ByteBuffer[] payloads = mc.call();
		final ByteBuffer[] chunks = cf.expandToCompleteChunk(payloads);
		synchronized(msg) {
			if (msg.isCanceled()) return -1;
			msg.setWriting();
		}
		SecurityPolicy policy = securityConfiguration.getSecurityPolicy();
		
		startChunkSend(chunks);
		for (int i=0; i<chunks.length; i++)
		{
				ByteBuffer chunk = chunks[i];
				ByteBuffer payload = payloads[i];
				boolean finalChunk = chunk == chunks[chunks.length-1];
				chunk.rewind();
				chunk.putInt( TcpMessageType.OPEN | (finalChunk ? TcpMessageType.FINAL : TcpMessageType.CONTINUE) );
				chunk.position(8);
				chunk.putInt(secureChannelId);
			
				// -- Security Header --
				// Policy URI
				byte[] data = policy.getEncodedPolicyUri();
				chunk.putInt(data.length);
				chunk.put(data);
			
				// Sender Certificate
				data = securityConfiguration.getEncodedLocalCertificate();
				chunk.putInt( data==null ? -1 : data.length);
				if (data!=null)	chunk.put(data);
			
				// Recv Certificate Thumbprint
				data = securityConfiguration.getEncodedRemoteCertificateThumbprint();
				chunk.putInt( data == null ? -1 : data.length);
				if (data!=null)	chunk.put(data);
			
				// -- Sequence header --
				chunk.putInt(sendSequenceNumber.getAndIncrement());
				chunk.putInt(requestNumber); // Request number	
			
				new ChunkAsymmEncryptSigner(chunk, payload, securityConfiguration).run();
				chunk.rewind();
				endChunkSend(chunk);
		} 
		msg.setWritten();
		return chunks.length;
	}
	
	/**
	 * Send symmetric secure message
	 * 
	 * @param msg
	 * @param token
	 * @param requestId
	 * @param messageType message type, one of {@link TcpMessageType} MESSAGE, OPEN, or CLOSE
	 * @throws ServiceResultException
	 */
	protected void sendSecureMessage(
			final AsyncWrite msg, 
			final SecurityToken token, 
			final int requestId,
			final int messageType,
			final AtomicInteger sendSequenceNumber
			)
	{		
		assert(token!=null);
		ByteBuffer chunks[], payloads[];
		boolean concurrent;
		try {
			synchronized(msg) {
				if (msg.isCanceled()) return;
				msg.setQueued();
			}
		
			EncoderCalc calc = new EncoderCalc();
			calc.setEncoderContext(encoderCtx);
			calc.putMessage(msg.getMessage());
			int len = calc.getLength();
		
 			if (len>ctx.maxSendMessageSize && ctx.maxSendMessageSize!=0)
				throw new ServiceResultException(StatusCodes.Bad_TcpMessageTooLarge);

 			SecurityPolicy policy = token.getSecurityPolicy();
 			MessageSecurityMode mode = token.getMessageSecurityMode();
 			String symmEncryptAlgo = policy.getSymmetricEncryptionAlgorithmUri();
 			String symmSignAlgo = policy.getSymmetricSignatureAlgorithmUri();
 			int cipherBlockSize = CryptoUtil.getCipherBlockSize(symmEncryptAlgo, null);
 			int signatureSize = CryptoUtil.getSignatureSize(symmSignAlgo, null); 
 			int paddingSize = token.getMessageSecurityMode() == MessageSecurityMode.SignAndEncrypt ? 1 : 0;
 			
 			int maxPayloadSize = ctx.maxSendChunkSize - 24 - paddingSize - signatureSize;
 			maxPayloadSize -= (maxPayloadSize + paddingSize + signatureSize + 8) % cipherBlockSize;
 			final int CORES = StackUtils.cores();
 			
			int optimalPayloadSize = (len+CORES-1) / CORES;
			if (optimalPayloadSize > maxPayloadSize)
				optimalPayloadSize = maxPayloadSize;
			if (optimalPayloadSize < 4096)
				optimalPayloadSize = 4096;
			int optimalChunkSize = optimalPayloadSize + 24 + paddingSize + signatureSize;
		
			ChunkFactory cf = new ChunkFactory(
				optimalChunkSize, 
				8, 
				8, 
				8, 
				signatureSize,
				cipherBlockSize,
				mode);
		
			// Calculate chunk count
			final int count = (len + cf.maxPayloadSize-1) / cf.maxPayloadSize;		
			if (count>ctx.maxSendChunkCount && ctx.maxSendChunkCount!=0)
				throw new ServiceResultException(StatusCodes.Bad_TcpMessageTooLarge);		
			concurrent = (count > 1) && (CORES>0) && (mode != MessageSecurityMode.None);
		
			// Allocate chunks
			int bytesLeft = len;
			payloads = new ByteBuffer[count];
			chunks = new ByteBuffer[count];
			for (int i=0; i<count; i++) {
				payloads[i] = cf.allocate(bytesLeft);
				chunks[i] = cf.expandToCompleteChunk(payloads[i]);
				bytesLeft -= payloads[i].remaining();
			}
			assert(bytesLeft==0);
		
			// Start write 
			synchronized(msg) {
				if (msg.isCanceled()) return;
				msg.setWriting();
			}		
	  	} catch (ServiceResultException se) {
	  		msg.setError(se);
	  		return;
	  	}
	  	final ByteBuffer _chunks[] = chunks;
	  	final ByteBuffer _payloads[] = payloads;
	  	final int count = chunks.length;
		final boolean parallel = concurrent;
	  
		int sequenceNumber = 0;
		synchronized(this) {
			sequenceNumber = sendSequenceNumber.getAndAdd(chunks.length);
			startChunkSend(chunks);
		}
		
		// Add chunk headers
		for (ByteBuffer chunk : chunks) {
			boolean finalChunk = chunk == chunks[chunks.length-1];
			chunk.rewind();
			chunk.putInt( messageType | (finalChunk ? TcpMessageType.FINAL : TcpMessageType.CONTINUE) );
			chunk.position(8);
			chunk.putInt(token.getSecureChannelId());
			
			// -- Security Header --
			chunk.putInt(token.getTokenId());
			
			// -- Sequence Header --
			chunk.putInt(sequenceNumber++);
			chunk.putInt(requestId);
		}
		
		// a Chunk-has-been-encoded handler
		final AtomicInteger chunksComplete = new AtomicInteger();
		ChunkListener completitionListener = new ChunkListener() {
			@Override
			public void onChunkComplete(ByteBuffer[] bufs, final int index) {
				Runnable action = new Runnable() {
					public void run() {
						// Chunk contains message data, it needs to be encrypted and signed
//						try {
							// Encrypt & sign 
							new ChunkSymmEncryptSigner(_chunks[index], _payloads[index], token).run();
							_chunks[index].rewind();
						
							// Write chunk				
							endChunkSend(_chunks[index]);
						
							// All chunks are completed
							if (chunksComplete.incrementAndGet()==count)
								msg.setWritten();
							
//						} catch (ServiceResultException se) {
//							msg.setError(se);
//						}
					}};
				if (parallel && count>1) {
					StackUtils.getNonBlockingWorkExecutor().execute(action);
				} else { 
					action.run();
				}
			}
		};
		
		// Create encoder
		ByteBufferArrayWriteable2 out = new ByteBufferArrayWriteable2(payloads, completitionListener);
		out.order(ByteOrder.LITTLE_ENDIAN);

		final BinaryEncoder enc = new BinaryEncoder(out);
		enc.setEncoderContext(encoderCtx);
		enc.setEncoderMode(EncoderMode.NonStrict);
		
		Runnable encoder = new Runnable() {
			public void run() {
				try {
					enc.putMessage(msg.getMessage());
				} catch (ServiceResultException e) {
					msg.setError( StackUtils.toServiceResultException(e) );
				}
			}};
		StackUtils.getBlockingWorkExecutor().execute(encoder);
	}


	
	protected void setError(UnsignedInteger errorCode)
	{
		setError(new StatusCode(errorCode));
	}
	
	protected void setError(StatusCode sc) 
	{
		setError(new ServiceResultException(sc));
	}
	
	protected synchronized void setError(ServiceResultException e) 
	{
		if (hasError()) return;
		super.setError(e);
		close();
	}
		
	@Override
	protected void onStateTransition(CloseableObjectState oldState,
			CloseableObjectState newState) {
		super.onStateTransition(oldState, newState);
		
		if (newState == CloseableObjectState.Open)
		{
			for (IConnectionListener l : connectionListeners)
				l.onOpen();
		}
		
		if (newState == CloseableObjectState.Closed) 
		{
			ServiceResultException sre = new ServiceResultException(StatusCodes.Bad_CommunicationError);
			for (IConnectionListener l : connectionListeners)
				l.onClosed(sre);
		}
		
	}
	
	// Handle runtime exceptions that are thrown by state listeners  
	@Override
	protected void onListenerException(RuntimeException rte) {
		setError( StackUtils.toServiceResultException(rte) );
	}

	public void getSecureChannels(Collection<ServerSecureChannel> list) {
		list.addAll( secureChannels.values() );
	}

	@Override
	public void addSecureChannelListener(SecureChannelListener l) {
		secureChannelListeners.add(l);
	}
	
	@Override
	public void removeSecureChannelListener(SecureChannelListener l) {
		secureChannelListeners.remove(l);
	}
	
	/**
	 * Send a notification to listeners that a secure channel has been 
	 * attached to (opened in) the connection. 
	 *  
	 * @param c
	 */
	protected void fireSecureChannelAttached(ServerSecureChannel c) {
		for (SecureChannelListener l : secureChannelListeners)
			l.onSecureChannelAttached(this, c);
	}
	
	/**
	 * Send a notification the listeners that a secure channel has been
	 * detached from the connection.
	 * 
	 * @param c
	 */
	protected void fireSecureChannelDetached(ServerSecureChannel c) {
		for (SecureChannelListener l : secureChannelListeners)
			l.onSecureChannelDetached(this, c);
	}
	
	public String getConnectURL() {
		return ctx.endpointUrl;
	}
	
	public Certificate getRemoteCertificate() {
		return securityConfiguration.getReceiverCertificate();
	}
	
	public void addChannelListener(ChannelListener listener) {
		channelListeners.add(listener);
	}
	
	public void removeChannelListener(ChannelListener listener) {
		channelListeners.remove(listener);
	}
	
	@Override
	public void addConnectionListener(IConnectionListener listener) {
		connectionListeners.add(listener);
	}
	
	@Override
	public void removeConnectionListener(IConnectionListener listener) {
		connectionListeners.remove(listener);
	}
	
	@Override
	public String toString() {
		CloseableObjectState s = getState();
		return "Connection (state="+s+", addr="+getRemoteAddress()+")";
	}	
	
}
