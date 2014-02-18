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

package org.opcfoundation.ua.transport.tcp.io;

import static org.opcfoundation.ua.core.StatusCodes.Bad_CertificateInvalid;
import static org.opcfoundation.ua.core.StatusCodes.Bad_CommunicationError;
import static org.opcfoundation.ua.core.StatusCodes.Bad_ConnectionClosed;
import static org.opcfoundation.ua.core.StatusCodes.Bad_ConnectionRejected;
import static org.opcfoundation.ua.core.StatusCodes.Bad_ServerNotConnected;
import static org.opcfoundation.ua.core.StatusCodes.Bad_ProtocolVersionUnsupported;
import static org.opcfoundation.ua.core.StatusCodes.Bad_ServerUriInvalid;
import static org.opcfoundation.ua.core.StatusCodes.Bad_TcpInternalError;
import static org.opcfoundation.ua.core.StatusCodes.Bad_TcpMessageTooLarge;
import static org.opcfoundation.ua.core.StatusCodes.Bad_TcpMessageTypeInvalid;

import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.builtintypes.ServiceRequest;
import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.common.NamespaceTable;
import org.opcfoundation.ua.common.RuntimeServiceResultException;
import org.opcfoundation.ua.common.ServiceMessageContext;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.ChannelSecurityToken;
import org.opcfoundation.ua.core.EncodeableSerializer;
import org.opcfoundation.ua.core.EndpointConfiguration;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.OpenSecureChannelRequest;
import org.opcfoundation.ua.core.OpenSecureChannelResponse;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.encoding.DecodingException;
import org.opcfoundation.ua.encoding.EncodeType;
import org.opcfoundation.ua.encoding.EncoderContext;
import org.opcfoundation.ua.encoding.EncoderMode;
import org.opcfoundation.ua.encoding.EncodingException;
import org.opcfoundation.ua.encoding.IEncodeable;
import org.opcfoundation.ua.encoding.binary.BinaryDecoder;
import org.opcfoundation.ua.encoding.binary.BinaryEncoder;
import org.opcfoundation.ua.encoding.binary.EncoderCalc;
import org.opcfoundation.ua.encoding.binary.IEncodeableSerializer;
import org.opcfoundation.ua.transport.IConnectionListener;
import org.opcfoundation.ua.transport.SecureChannel;
import org.opcfoundation.ua.transport.UriUtil;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityConfiguration;
import org.opcfoundation.ua.transport.security.SecurityMode;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.transport.tcp.impl.Acknowledge;
import org.opcfoundation.ua.transport.tcp.impl.ChunkAsymmDecryptVerifier;
import org.opcfoundation.ua.transport.tcp.impl.ChunkAsymmEncryptSigner;
import org.opcfoundation.ua.transport.tcp.impl.ChunkFactory;
import org.opcfoundation.ua.transport.tcp.impl.ChunkSymmDecryptVerifier;
import org.opcfoundation.ua.transport.tcp.impl.ChunkSymmEncryptSigner;
import org.opcfoundation.ua.transport.tcp.impl.ChunkUtils;
import org.opcfoundation.ua.transport.tcp.impl.ErrorMessage;
import org.opcfoundation.ua.transport.tcp.impl.Hello;
import org.opcfoundation.ua.transport.tcp.impl.SecurityToken;
import org.opcfoundation.ua.transport.tcp.impl.TcpMessageType;
import org.opcfoundation.ua.utils.CertificateUtils;
import org.opcfoundation.ua.utils.CryptoUtil;
import org.opcfoundation.ua.utils.StackUtils;
import org.opcfoundation.ua.utils.bytebuffer.ByteBufferArrayReadable;
import org.opcfoundation.ua.utils.bytebuffer.ByteBufferArrayWriteable2;
import org.opcfoundation.ua.utils.bytebuffer.IBinaryReadable;
import org.opcfoundation.ua.utils.bytebuffer.InputStreamReadable;
import org.opcfoundation.ua.utils.bytebuffer.OutputStreamWriteable;

/**
 * This class implements OPC UA Secure Conversation (UASC) for client to server communication. <p>
 * 
 * OPC UA TCP is a simple TCP based protocol that establishes a full duplex channel between a
 * client and server. This protocol has two key features that differentiate it from HTTP. First, this
 * protocol allows responses to be returned in any order. Second, this protocol allows responses to be
 * returned on a different socket if communication failures causes temporary socket interruption.
 * 
 * The OPC UA TCP protocol is designed to work with the SecureChannel implemented by a layer
 * higher in the stack. For this reason, the OPC UA TCP protocol defines its interactions with the
 * SecureChannel in addition to the wire protocol.<p>
 * 
 * Features included in this class:
 *   o Establishing connection, Handshake
 *   o Sync & Async encryption
 * Features excluded in this class:
 *   o Reconnect (See SecureChannel)
 *   o Token Renewal (See SecureChannel)
 *   
 * TcpConnection is instantiated and managed by {@link SecureChannel} which also handles Reconnection
 * and token renewal. 
 * <p>
 * 
 * {@link OpenSecureChannelRequest} and {@link OpenSecureChannelResponse} is ciphered with asymmetric 
 * encryption using the certificates set in initialize. Asymmetric encryption is omited if server 
 * certificate is null. (This is not allowed in Part 4, but is in Part 6). 
 * DiscoveryClient uses unencrypted connection.
 * 
 * TcpConnection captures security tokens from OpenSecureChannel conversation and uses them for 
 * symmetric messaging. The oldest non-expired token is used. <P>
 * 
 * TODO Prune expired tokens
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class TcpConnection implements IConnection {

	private class MessageBuffers {

		private ByteBuffer[] chunks;
		private ByteBuffer[] payloads;

		/**
		 * @param chunks
		 * @param payloads
		 */
		public MessageBuffers(ByteBuffer[] chunks, ByteBuffer[] payloads) {
			super();
			this.chunks = chunks;
			this.payloads = payloads;
		}

		public ByteBuffer[] getChunks() {
			return chunks;
		}

		public ByteBuffer[] getPayloads() {
			return payloads;
		}

	}

	/**
	 * Log4J Error logger. 
	 * Security settings are logged with DEBUG level.
	 * Unexpected errors are logged with ERROR level. 
	 */
	static Logger LOGGER = Logger.getLogger(TcpConnection.class);
	
	// Configuration variables
    EncodeType encodeType;    
    PrivKey clientPrivateKey;
    Cert clientCertificate;
    Cert serverCertificate;
    EndpointConfiguration endpointConfiguration;
    EndpointDescription endpointDescription;
    IEncodeableSerializer serializer = EncodeableSerializer.getInstance();
    CertificateValidator certificateValidator;
	InetSocketAddress addr;
	TcpConnectionLimits limits;
	TcpQuotas quotas = TcpQuotas.DEFAULT_CLIENT_QUOTA;
	EnumSet<TransportChannelSettings.Flag> flags = EnumSet.noneOf(TransportChannelSettings.Flag.class); 
	int handshakeTimeout = 60000;
	SecurityConfiguration securityConfiguration;
	
	/**
	 * All the tokens used in this connection.
	 */
	List<SecurityToken> tokens = new CopyOnWriteArrayList<SecurityToken>();
	
	/**
	 * This map captures that last used TokenId of the input channel for a secure channel
	 * Map<SecureChannelId, TokenId> 
	 */
	Map<Integer, SecurityToken> activeTokenIdMap = new ConcurrentHashMap<Integer, SecurityToken>();	
	
	/**
	 * Map<RequestId, ClientNonce> Capture of client nonces.
	 * Nonce is captured in sendRequest( OpenSecureMessageRequest ) and released in
	 * Readthread OpenSecureMessageResponse.
	 * The captured nonce is used in the instantiation of a SecurityToken.
	 */
	Map<Integer, byte[]> clientNonces = new ConcurrentHashMap<Integer, byte[]>();
	
	/**
	 * Map<SecureChannelId, SequenceNumber> Sequence numbering of secure channels.
	 */
	Map<Integer, SequenceNumber> sequenceNumbers = new ConcurrentHashMap<Integer, SequenceNumber>();
	
	/**
	 * The socket
	 */
	// he AtomicReference would be even more reliable, but with the 'lock' it seems
	// to be much slower - getting rid of 'lock' would be a good idea :)
//	private final AtomicReference<Socket> socket = new AtomicReference<Socket>(null);
	private Socket socket = null;
	
	/**
	 * @param socket the socket to set
	 */
	protected void setSocket(Socket socket) {
//		this.socket.set(socket);
		this.socket = socket;
	}

	/**
	 * This variable contains the agreed protocol version, the version sent by 
	 * the server in hand-shake
	 */
	int protocolVersion;
	
	/**
	 * Output stream
	 */
	OutputStreamWriteable out;
	
	/**
	 * Output stream lock. Only one thread at a time may write to the output channel.
	 * Message encrypting is done under the lock. This is because sequence number 
	 * is encrypted and messages may not be sent in wrong order.  
	 */
	ReentrantLock lock = new ReentrantLock();
	
	/**
	 * Read thread is instantiated and active while socket connection is established.
	 * The read thread shuts down itself automatically when there is socket exception
	 * while reading the input stream.
	 * 
	 * On connection close, read thread invokes close() to ensure cleanup.
	 * 
	 * Read thread sends message notifications to IMessageListeners.
	 */
	ReadThread thread;
	
	/**
	 * Encoder context and parameters
	 */
	EncoderContext ctx;	
	
	/**
	 * Incoming message listeners. All incoming messages are notified to all listeners.
	 * It is up to the listener to find the interesting messages.
	 * 
	 * Events are notified in ReadThread, thus input stream reading is locked during
	 * the message handling. 
	 */
	List<IMessageListener> listeners = new CopyOnWriteArrayList<IMessageListener>();
	
	/**
	 * IConnectionListener listeners. 
	 * All close events (from the user and the stack) are notified to the listeners 
	 */
	List<IConnectionListener> connectionListeners = new CopyOnWriteArrayList<IConnectionListener>();
	
	public void initialize(TransportChannelSettings settings)
	throws ServiceResultException
	{
		initialize(settings.getDescription().getEndpointUrl(), settings);
	}
	
	public void initialize(String url, TransportChannelSettings settings)
	throws ServiceResultException
	{
		try {
			URI uri = new URI(url);
			InetSocketAddress addr = UriUtil.getSocketAddress(uri);
			initialize(addr, settings);
		} catch (URISyntaxException e) {			
			//Bad_TcpEndpointUrlInvalid?
			throw new ServiceResultException(Bad_ServerUriInvalid, e);
		} catch (IllegalArgumentException e) {
			throw new ServiceResultException(Bad_ServerUriInvalid);
		}
	}	
	
	public void initialize(InetSocketAddress addr, TransportChannelSettings settings) 
	throws ServiceResultException 
	{
		lock.lock();
		try {
			this.addr = addr;
			this.endpointConfiguration = (EndpointConfiguration) settings
					.getConfiguration().clone();
			this.endpointDescription = settings.getDescription().clone();
			this.certificateValidator = settings.getCertificateValidator();
			clientCertificate = settings.getClientCertificate();
			serverCertificate = settings.getServerCertificate();
			clientPrivateKey = settings.getPrivKey();
			// If security is not used, the certificate and key are not set
			// if (clientCertificate==null)
			// throw new
			// IllegalArgumentException("arguments missing: clientCertificate");
			// if (clientPrivateKey==null)
			// throw new
			// IllegalArgumentException("arguments missing: private key");

			encodeType = EncodeType.Binary;
			if (endpointConfiguration.getUseBinaryEncoding() != null
					&& !endpointConfiguration.getUseBinaryEncoding())
				encodeType = EncodeType.Xml;

			this.flags = settings.getFlags();

			KeyPair pair = clientCertificate == null ? null : new KeyPair(
					clientCertificate, clientPrivateKey);
			SecurityPolicy securityPolicy = SecurityPolicy
					.getSecurityPolicy(endpointDescription
							.getSecurityPolicyUri());
			SecurityMode securityMode = new SecurityMode(securityPolicy,
					endpointDescription.getSecurityMode());
			securityConfiguration = new SecurityConfiguration(securityMode,
					pair, serverCertificate);

		} finally {
			lock.unlock();
		}
	}
	
	public void open() throws ServiceResultException
	{		
		lock.lock();
		try {
			Socket s = getSocket();
			if (s != null && s.isConnected())
				return;
			// throw new ServiceResultException(Bad_CommunicationError,
			// "Already connected");

			// Connect
			try {
				LOGGER.info(addr + " Connecting");
				int connectTimeout = handshakeTimeout;
				s = new Socket();
				setSocket(s);
				if (connectTimeout == 0) {
					s.connect(addr);
				} else {
					s.setSoTimeout(handshakeTimeout);
					s.connect(addr, connectTimeout);
				}
			} catch (ConnectException e) {
				LOGGER.info(addr + " Connect failed", e);
				throw new ServiceResultException(Bad_ConnectionRejected, e);
			} catch (IOException e) {
				LOGGER.info(addr + " Connect failed", e);
				throw new ServiceResultException(Bad_ConnectionRejected, e);
			} catch (IllegalArgumentException e) {
				throw new ServiceResultException(Bad_ServerUriInvalid);
			}

			// Handshake
			try {
				OutputStreamWriteable out = new OutputStreamWriteable(s
						.getOutputStream());
				out.order(ByteOrder.LITTLE_ENDIAN);

				InputStreamReadable in = new InputStreamReadable(s
						.getInputStream(), Long.MAX_VALUE);
				in.order(ByteOrder.LITTLE_ENDIAN);

				int maxMessageSize = Math.min(endpointConfiguration
						.getMaxMessageSize() != null ? endpointConfiguration
						.getMaxMessageSize() : Integer.MAX_VALUE,
						quotas.maxMessageSize);

				BinaryDecoder dec = new BinaryDecoder(in);
				EncoderContext decoderCtx = new EncoderContext();
				decoderCtx.setEncodeableSerializer(StackUtils
						.getDefaultSerializer());
				decoderCtx.setMaxArrayLength(endpointConfiguration
						.getMaxArrayLength() != null ? endpointConfiguration
						.getMaxArrayLength() : 0);
				decoderCtx.setMaxStringLength(endpointConfiguration
						.getMaxStringLength() != null ? endpointConfiguration
						.getMaxStringLength() : 0);
				decoderCtx
						.setMaxByteStringLength(endpointConfiguration
								.getMaxByteStringLength() != null ? endpointConfiguration
								.getMaxByteStringLength()
								: 0);
				dec.setEncoderContext(decoderCtx);

				BinaryEncoder enc = new BinaryEncoder(out);
				EncoderContext encoderCtx = new EncoderContext();
				encoderCtx.setEncodeableSerializer(StackUtils
						.getDefaultSerializer());
				encoderCtx.setMaxMessageSize(maxMessageSize);
				encoderCtx.setMaxArrayLength(endpointConfiguration
						.getMaxArrayLength() != null ? endpointConfiguration
						.getMaxArrayLength() : 0);
				encoderCtx.setMaxStringLength(endpointConfiguration
						.getMaxStringLength() != null ? endpointConfiguration
						.getMaxStringLength() : 0);
				encoderCtx
						.setMaxByteStringLength(endpointConfiguration
								.getMaxByteStringLength() != null ? endpointConfiguration
								.getMaxByteStringLength()
								: 0);
				enc.setEncoderMode(EncoderMode.NonStrict);
				enc.setEncoderContext(encoderCtx);

				EncoderCalc calc = new EncoderCalc();
				calc.setEncoderContext(encoderCtx);

				// Hello
				Hello h = new Hello();
				h.setEndpointUrl(endpointDescription.getEndpointUrl());
				h
						.setMaxChunkCount(UnsignedInteger
								.valueOf(endpointConfiguration
										.getMaxBufferSize() == null ? TcpMessageLimits.DefaultMaxBufferSize
										: endpointConfiguration
												.getMaxBufferSize().intValue()));
				h.setMaxMessageSize(UnsignedInteger.valueOf(maxMessageSize));
				h.setReceiveBufferSize(UnsignedInteger
						.valueOf(quotas.maxBufferSize));
				h.setSendBufferSize(UnsignedInteger
						.valueOf(quotas.maxBufferSize));
				h.setProtocolVersion(UnsignedInteger.valueOf(0));

				// Use the values of previous connection (this is reconnect)
				if (limits != null) {
					h.setProtocolVersion(UnsignedInteger
							.valueOf(protocolVersion));
					h.setMaxChunkCount(UnsignedInteger
							.valueOf(limits.maxRecvChunkCount));
					h.setMaxMessageSize(UnsignedInteger
							.valueOf(limits.maxRecvMessageSize));
					h.setSendBufferSize(UnsignedInteger
							.valueOf(limits.maxSendBufferSize));
					h.setReceiveBufferSize(UnsignedInteger
							.valueOf(limits.maxRecvBufferSize));
				}

				// Write to stream
				out.putInt(TcpMessageType.HELF);
				encoderCtx.setMaxStringLength(4096);
				calc.putEncodeable(null, Hello.class, h);
				int len = calc.getAndReset() + 8;
				out.putInt(len);
				enc.putEncodeable(null, Hello.class, h);
				out.flush();
				encoderCtx.setMaxStringLength(endpointConfiguration
						.getMaxStringLength() != null ? endpointConfiguration
						.getMaxStringLength() : 0);

				// Read Acknowledge
				int msgType = in.getInt();
				len = in.getInt();
				// Too large for handshake
				if (len < 8 || len > 0x1000) {
					throw new ServiceResultException(Bad_TcpMessageTooLarge);
				}

				// ERRF
				if (msgType == TcpMessageType.ERRF) {
					dec.getEncoderContext().setMaxStringLength(4096);
					ErrorMessage error = dec.getEncodeable(null,
							ErrorMessage.class);
					throw new ServiceResultException(new StatusCode(error
							.getError()), error.getReason());
				}

				// !ACKF
				if (msgType != TcpMessageType.ACKF) {
					throw new ServiceResultException(
							Bad_TcpMessageTypeInvalid,
							"Message type was "
									+ msgType
									+ ", expected "
									+ (TcpMessageType.ACKNOWLEDGE | TcpMessageType.FINAL));
				}

				// ACKF
				int oldMaxLen = decoderCtx.getMaxStringLength();
				decoderCtx.setMaxStringLength(4096);
				Acknowledge ack = dec.getEncodeable(null, Acknowledge.class);
				if (ack.getProtocolVersion().intValue() != 0)
					throw new ServiceResultException(
							Bad_ProtocolVersionUnsupported,
							"Version 0 requested, got "
									+ ack.getProtocolVersion());
				decoderCtx.setMaxStringLength(oldMaxLen);

				protocolVersion = Math.min(h.getProtocolVersion().intValue(),
						ack.getProtocolVersion().intValue());

				// 
				if (ack.getMaxMessageSize().equals(UnsignedInteger.valueOf(0)))
					ack.setMaxMessageSize(UnsignedInteger
							.valueOf(Integer.MAX_VALUE));
				if (ack.getMaxChunkCount().equals(UnsignedInteger.valueOf(0)))
					ack.setMaxChunkCount(UnsignedInteger
							.valueOf(Integer.MAX_VALUE));

				// Assert Acknowledge.ReceiveBufferSize is not larger that
				// Hello.ReceiveBufferSize
				if (ack.getReceiveBufferSize().longValue() > h
						.getReceiveBufferSize().longValue())
					throw new ServiceResultException(Bad_TcpInternalError,
							"Acknowledge.ReceiveBufferSize > Hello.ReceiveBufferSize");
				// Assert Acknowledge.ReceiveBufferSize is not smaller than 8192
				// bytes
				if (ack.getReceiveBufferSize().longValue() < TcpMessageLimits.MinBufferSize)
					throw new ServiceResultException(Bad_TcpInternalError,
							"Server recv buffer size < "
									+ TcpMessageLimits.MinBufferSize);

				// Assert Acknowledge.SendBufferSize is not larger that
				// Hello.SendBufferSize
				if (ack.getSendBufferSize().longValue() > h.getSendBufferSize()
						.longValue())
					throw new ServiceResultException(Bad_TcpInternalError,
							"Acknowledge.SendBufferSize > Hello.SendBufferSize");
				// Assert Acknowledge.SendBufferSize is larger than 8192 bytes
				if (ack.getSendBufferSize().longValue() < TcpMessageLimits.MinBufferSize)
					throw new ServiceResultException(Bad_TcpInternalError,
							"Server send buffer size < "
									+ TcpMessageLimits.MinBufferSize);

				limits = new TcpConnectionLimits();
				limits.maxSendBufferSize = (int) Math.min(ack
						.getSendBufferSize().longValue(), Long
						.valueOf((long) Integer.MAX_VALUE));
				limits.maxRecvBufferSize = (int) Math.min(ack
						.getReceiveBufferSize().longValue(), Long
						.valueOf((long) Integer.MAX_VALUE));
				limits.maxSendChunkCount = (int) Math.min(ack
						.getMaxChunkCount().longValue(), Long
						.valueOf((long) Integer.MAX_VALUE));
				limits.maxRecvChunkCount = (int) Math.min(h.getMaxChunkCount()
						.longValue(), Long.valueOf((long) Integer.MAX_VALUE));
				limits.maxSendMessageSize = (int) Math.min(ack
						.getMaxMessageSize().longValue(), Long
						.valueOf((long) Integer.MAX_VALUE));
				limits.maxRecvMessageSize = (int) Math.min(h
						.getMaxMessageSize().longValue(), Long
						.valueOf((long) Integer.MAX_VALUE));

				// Hands are shook, We are friends now
				s.setSoTimeout(0);
				s.setKeepAlive(true);
				LOGGER.info(addr + " Connected");

				for (IConnectionListener l : connectionListeners)
					l.onOpen();

				thread = new ReadThread(s, dec.getEncoderContext());
				thread.start();
				this.ctx = enc.getEncoderContext();
				this.out = out;
			} catch (IOException e) {
				try {
					s.close();
				} catch (IOException e1) {
				}
				setSocket(null);
				LOGGER.info(addr + " Connect failed", e);
				throw new ServiceResultException(Bad_CommunicationError, e);
			} catch (ServiceResultException e) {
				// this is not and is not
				// supposed to be captured
				// by prev line
				
				// Clean up the connection
				try {
					s.close();
				} catch (IOException e1) {
				}
				setSocket(null);
				LOGGER.info(addr + " Connect failed", e);
				// Rethrow
				throw e;
			}
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 * Close the socket connection. This method does not request CloseSecureChannel.  
	 * Does nothing if it is already closed or was never opened.
	 * 
	 * This method is invoked by the user and internally by read thread.
	 */
	public void close()  
	{
		ReadThread t = thread;
		if (t!=null) t.closing = true;
		close( new ServiceResultException(Bad_CommunicationError, "Socket closed by the user") );
	}
	
	private void close(ServiceResultException closeError)  
	{
		lock.lock();
		try {
			final Socket s = getSocket();
			if (s==null || !s.isConnected() || s.isClosed()) 
				return;
			try {
				s.close();
			} catch (IOException e) {
				// 	Unexpected, not important, log it for remotely possible debug situation 
				LOGGER.error(addr+" Close error", e);
			}
			setSocket(null);
//			out = null;
			clientNonces.clear();
//			activeTokenIdMap.clear();
//			tokens.clear();			
			LOGGER.info(addr + " Closed");
		} finally {
			lock.unlock();
		}		
		for (IConnectionListener l : connectionListeners) 
			l.onClosed(closeError);
	}

	/**
	 * @return
	 */
	protected Socket getSocket() {
//		return socket.get();
		return socket;
	}

	public void reconnect() throws ServiceResultException 
	{
		lock.lock();
		try {
			if (getSocket()!=null  && getSocket().isConnected() && !getSocket().isClosed())
				close();
			open();
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 * ReadThread is a thread that does blocking read to the input stream.
	 * If errors occur in the input stream, the error is logged and the socket closed.
	 * It deciphers and deserializes incoming messages and fires events to TcpConnection.  
	 *  
	 */
	class ReadThread extends Thread {
		Socket s;
		EncoderContext ctx;
				
		/**
		 * Variable where close cause is stored
		 */
		ServiceResultException closeError = null;
		
		/**  
		 * Indicator set to true to signal the thread that the socket has been closed
		 * in a controlled manner.
		 */
		boolean closing = false;
		
		/**
		 * Create new read thread.
		 * 
		 * @param s socket 
		 * @param ctx 
		 */
		ReadThread(Socket s, EncoderContext ctx) {
			super("TcpConnection/Read");
			this.setDaemon(true);
			this.s = s;
			this.ctx = ctx;
		}
		@Override
		public void run() {
			try {
				// total chunk count
				int chunkCount = 0;
				//boolean multithread = flags.contains( TransportChannelSettings.Flag.MultiThread );
				IBinaryReadable in = new InputStreamReadable( s.getInputStream(), Long.MAX_VALUE );
				in.order(ByteOrder.LITTLE_ENDIAN);
				ArrayList<ByteBuffer> chunks = new ArrayList<ByteBuffer>(256);
				
				read:while (this.s == TcpConnection.this.getSocket()) {
					// Read new message
					chunks.clear();
					int messageType = 0;
					int chunkNumber = 0;
					int chunkContinuationType = 0;
					int requestId = 0;
					int secureChannelId = 0;
					
					// Read Chunks
					do {
						if (chunkNumber > limits.maxRecvChunkCount) {
							closeError = new ServiceResultException("Recv chunk count exceeded (max = "+chunkNumber+")");
							LOGGER.error(addr+" Recv chunk count exceeded (max = "+chunkNumber+")");
							break read;
						}
						
						// Read Type
						int chunkType = in.getInt();
						int chunkMessageType = chunkType & TcpMessageType.MESSAGE_TYPE_MASK;
						chunkContinuationType = chunkType & TcpMessageType.CHUNK_TYPE_MASK;
						
						if (chunkNumber==0) {
							messageType = chunkMessageType;   
						} else if ( chunkMessageType != messageType) {
							closeError = new ServiceResultException("Error, message type changed between chunks");
							LOGGER.error(addr+" Error, message type changed between chunks");
							break read;
						}							
						
						if (chunkMessageType != TcpMessageType.OPEN && chunkMessageType != TcpMessageType.MESSAGE && chunkType != TcpMessageType.ERRF)
						{
							closeError = new ServiceResultException("Error, unknown message type "+String.format("0x%08x", chunkType));
							LOGGER.error(addr+" Error, unknown message type "+String.format("0x%08x", chunkType));
							break read;
						}
					
						// Read size
						int size = in.getInt();
						
						if (size>limits.maxRecvBufferSize) {
							closeError = new ServiceResultException("Error, chunk too large (max = "+limits.maxRecvBufferSize+")");
							LOGGER.error(addr+" Error, chunk too large (max = "+limits.maxRecvBufferSize+")");
							break read;
						}

						// Read the rest of the chunk
						ByteBuffer chunk = ByteBuffer.allocate(size); 
						chunk.order(ByteOrder.LITTLE_ENDIAN);
						chunk.putInt(chunkType);
						chunk.putInt(size);
						in.get(chunk, size-8);
					
						// Handle ERRF
						if (chunkType == TcpMessageType.ERRF) {
							chunk.position(8);
							BinaryDecoder dec = new BinaryDecoder(chunk);						
							dec.setEncoderContext(ctx);					
						
							ErrorMessage error = dec.getEncodeable(null, ErrorMessage.class);
							
//							ServiceResultException e = new ServiceResultException(StatusCodes.Bad_CommunicationError, "Error from Server ("+error.getError()+"): \""+error.getReason()+"\"");
							ServiceResultException e = new ServiceResultException(error.getError(), error.getReason());
							closeError = e;
							LOGGER.error(s.getRemoteSocketAddress()+" Error", e);
							break read;
						}

						int chunkSecureChannelId = ChunkUtils.getSecureChannelId(chunk);
						if (chunkNumber==0) {
							secureChannelId = chunkSecureChannelId;
						} else {
							if (secureChannelId!=chunkSecureChannelId)
							{
								closeError = new ServiceResultException("Error, SecureChannelId mismatch");
								LOGGER.error(addr+" Error, SecureChannelId mismatch");
								break read;									
							}
						}
						
						// Verify & Decrypt
						if (messageType == TcpMessageType.OPEN) {
							try {
								String securityPolicyUri = ChunkUtils.getSecurityPolicyUri(chunk);
								SecurityPolicy securityPolicy = SecurityPolicy.getSecurityPolicy( securityPolicyUri );
								byte[] encodedRemoteCertificate = ChunkUtils.getByteString(chunk);
								byte[] encodedLocalCertificateThumbprint = ChunkUtils.getByteString(chunk);
								
								
								// Verify returned values match requested
								if ( securityPolicy != securityConfiguration.getSecurityPolicy() )
								{
									closeError = new ServiceResultException("Error, unexpected security policy in OpenSecureChannelResponse");
									LOGGER.error(addr+" Error, unexpected security policy in OpenSecureChannelResponse");
									break read;									
								}
								
								if ( securityConfiguration.getSecurityPolicy() != SecurityPolicy.NONE &&
									 !Arrays.equals(encodedLocalCertificateThumbprint, securityConfiguration.getEncodedLocalCertificateThumbprint()))
								{
									closeError = new ServiceResultException("Error, certificate thumbprint mismatch");
									LOGGER.error(addr+" Error, certificate thumbprint mismatch");
									break read;									
								}
								
								// Decode remote certificate
								Cert remoteCertificate = null;
								if (encodedRemoteCertificate!=null)
									try {
										remoteCertificate = new Cert( CertificateUtils.decodeX509Certificate(encodedRemoteCertificate) ); 
									} catch (CertificateException e) {
										closeError = new ServiceResultException(Bad_CertificateInvalid, "Error, Invalid Remote Certificate");										
										LOGGER.error(addr+" Error, Invalid Remote Certificate", e);
										break read;									
									}
								
								// Validate remote certificate
								if (certificateValidator!=null) {
									StatusCode code = certificateValidator.validateCertificate( remoteCertificate );
									if (code!=null && !code.isGood()) {
										closeError = new ServiceResultException(code, "Remote certificate not accepted");										
										LOGGER.info(addr+" Remote certificate not accepted: "+code.toString());
										break read;									
									}
								}
								
								securityConfiguration = new SecurityConfiguration(
										securityConfiguration.getSecurityMode(), 
										securityConfiguration.getLocalCertificate2(),
										remoteCertificate
										);
								
								ChunkAsymmDecryptVerifier processor = new ChunkAsymmDecryptVerifier(chunk, securityConfiguration);
								processor.run();
								
							} catch (ServiceResultException e) {
								closeError = e;
								LOGGER.error(addr+"", e);
								break read;
							}
						}
							
						// Verify & Decrypt
						if (messageType == TcpMessageType.MESSAGE) {
							int securityTokenId = ChunkUtils.getTokenId(chunk);

							// Find token
							SecurityToken token = null;
							// LOGGER.debug("tokens("+tokens.size()+")="+tokens);
							for (SecurityToken t : tokens) 
								if (t.getTokenId() == securityTokenId && t.getSecureChannelId() == chunkSecureChannelId) 
									token = t;				
							// LOGGER.debug("token="+token);
							if (token==null) {								
								closeError = new ServiceResultException("Unexpected securityTokenId = "+securityTokenId);										
								LOGGER.error(addr+" Unexpected securityTokenId = "+securityTokenId);
								break read;
							}
							if (!token.isValid()) {
								closeError = new ServiceResultException("SecurityToken "+securityTokenId+" has timeouted");										
								LOGGER.error(addr+" SecurityToken "+token+" has timeouted");
								break read;
							}	
							activeTokenIdMap.put(chunkSecureChannelId, token);

							ChunkSymmDecryptVerifier processor = new ChunkSymmDecryptVerifier(chunk, token);
							processor.run();
														
							// Go to sequence header
							chunk.position(24);
						}	
						
						// Read & Verify Sequence number
						chunk.position( chunk.position() - 8 );
						int chunkSequenceNumber = chunk.getInt();	
						
						SequenceNumber seq = sequenceNumbers.get( secureChannelId );									
						if ( (messageType == TcpMessageType.MESSAGE) || (seq!=null) ) {
							if (!seq.testAndSetRecvSequencenumber(chunkSequenceNumber)) {
								// 	Sequence number mismatch
								closeError = new ServiceResultException("Sequence number mismatch");										
								LOGGER.error(addr+" Sequence number mismatch");
								break read;
							}
						}
						
						// Read & Verify request Id
						int chunkRequestId = chunk.getInt();
						if (chunkNumber==0) {
							requestId = chunkRequestId;
						} else {
							if (chunkRequestId!=requestId) {
								closeError = new ServiceResultException("Request id mismatch");										
								LOGGER.error(addr+" Request id mismatch");
								break read;
							}
						}					

						// Add chunk
						chunks.add(chunk);
						
						// Prepare next chunk
						chunkNumber++;
						chunkCount++;
												
					} while (chunkContinuationType == TcpMessageType.CONTINUE);
					
					if (chunkContinuationType == TcpMessageType.ABORT) continue;
						
					// Decode message
					IBinaryReadable r = new ByteBufferArrayReadable(chunks.toArray(new ByteBuffer[chunks.size()]));
					r.order(ByteOrder.LITTLE_ENDIAN);
					BinaryDecoder dec = new BinaryDecoder( r );
					dec.setEncoderContext(ctx);
					IEncodeable message = dec.getMessage();
					
					// Capture security token
					if (message instanceof OpenSecureChannelResponse) {
						
						OpenSecureChannelResponse opn = (OpenSecureChannelResponse) message;
						ChannelSecurityToken tkn = opn.getSecurityToken();						

						byte[] clientNonce = clientNonces.get( requestId );
						byte[] serverNonce = opn.getServerNonce();			
						
						// HAX! In Reconnect to secure channel -situation, the C# Server implementation sends
						// two conflicting secure channel id'socket. 
						// The old channel (correct) in message header and a new channel id in the payload. 
						int __secureChannelId = secureChannelId;  
						int ___secureChannelId = tkn.getChannelId().intValue();
						
						if (___secureChannelId != __secureChannelId) 
							LOGGER.error(addr+" OpenSecureChannel, server sent two secureChannelIds "+__secureChannelId+" and "+___secureChannelId+" using "+__secureChannelId);
						
						try {
							SecurityToken token = new SecurityToken(
									TcpConnection.this.securityConfiguration,
									__secureChannelId,
									tkn.getTokenId().intValue(),
									System.currentTimeMillis(),
									tkn.getRevisedLifetime().longValue(),
									clientNonce,
									serverNonce
								);
							LOGGER.debug("new token="+token);
							tokens.add( token );
							
							// Add new sequence number counter
							if (!sequenceNumbers.containsKey( __secureChannelId ))
								sequenceNumbers.put( __secureChannelId , new SequenceNumber() );
								
						} catch (ServiceResultException e) {
							closeError = e;
							LOGGER.error(addr+" SecurityTokenError ", e);
							break read;
						}
					}
					clientNonces.remove( requestId );
					
					for (IMessageListener l : listeners)
						l.onMessage(requestId, secureChannelId, message);					
				}
			} catch (IOException e) {
				if (e instanceof SocketException) {
					if (!closing) {
						LOGGER.info(addr+" Closed (unexpected)");
						closeError = new ServiceResultException(Bad_ConnectionClosed, e, "Connection closed (unexpected)");					
					} else {
						LOGGER.info(addr+" Closed (expected)");
						closeError = new ServiceResultException(Bad_ConnectionClosed, e, "Connection closed (expected)");					
					}
				} else if (e instanceof EOFException) {
					closeError = new ServiceResultException(Bad_ConnectionClosed, e, "Connection closed (graceful)");					
					LOGGER.info(addr+" Closed (graceful)");
				} else {
					closeError = StackUtils.toServiceResultException(e);
					LOGGER.error(addr+" Error", e);
				}
			} catch (DecodingException e) {
				if (e.getCause()!=null && e.getCause() instanceof EOFException) {
					LOGGER.info(addr+" Closed");
				} else {
					LOGGER.error(addr+" Error", e);
				}
				closeError = e;
			} catch (RuntimeServiceResultException e) {
				ServiceResultException sre = (ServiceResultException) e.getCause();
				LOGGER.error(addr+" Error", sre);
				closeError = sre;
			}
						
			if (closeError.getStatusCode().getValue().equals(StatusCodes.Bad_SecureChannelIdInvalid))
				close(closeError);
			else
			close(closeError);
		}
	}
	
	public EndpointConfiguration getEndpointConfiguration() {
		return endpointConfiguration;
	}

	public EndpointDescription getEndpointDescription() {
		return endpointDescription;
	}

	public ServiceMessageContext getMessageContext() {
		ServiceMessageContext result = new ServiceMessageContext();
		result.setEncodeableSerializer(serializer);
		result.setMaxArrayLength(endpointConfiguration.getMaxArrayLength());
		result.setMaxByteStringLength(endpointConfiguration.getMaxByteStringLength());
		result.setMaxMessageSize(endpointConfiguration.getMaxMessageSize());
		result.setMaxStringLength(endpointConfiguration.getMaxStringLength());
		result.setNamespaceTable(NamespaceTable.getDefault());
		return result;
	}
	
	/**
	 * Optional dispose closes connection and clears all variables 
	 */
	public void dispose() {
		lock.lock();
		try {
			close();
			clientPrivateKey = null;
			clientCertificate = null;
			serverCertificate = null;
			endpointConfiguration = null;
			endpointDescription = null;
			serializer = null;
			certificateValidator = null;
			setSocket(null);
			ctx = null;
			out = null;
			tokens = null;
			quotas = null;
			limits = null;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Send service request using a given secure channel and operation time out.
	 * 
	 * The operation may be interrupted by interrupting the calling thread with
	 * {@link Thread#interrupt()}.
	 * 
	 * @param request
	 * @param secureChannelId secure channel id, or -1 to open new secure channel
	 * @return
	 * @throws ServiceResultException
	 */
	public void sendRequest(ServiceRequest request, int secureChannelId, int requestId)
	throws ServiceResultException 
	{
		final Socket s = getSocket();
		if (s==null || !s.isConnected() || s.isClosed())
			throw new ServiceResultException(Bad_ServerNotConnected);
		
		LOGGER.debug(secureChannelId+" Sending Request (rid="+requestId+")"+request.getClass().getSimpleName());
		
		boolean asymm = request instanceof OpenSecureChannelRequest;
		SecurityToken token = null;
		
		// Count message size
		EncoderCalc calc = new EncoderCalc();
		calc.setEncoderContext(ctx);
		calc.putMessage(request);
		int len = calc.getAndReset();

		if (secureChannelId!=0) {
			token = getSecurityTokenToUse(secureChannelId);
		}
		LOGGER.debug("token="+token);
		
		SecurityMode securityMode = getSecurityMode(asymm, request, token);
		
		ChunkFactory cf = getChunkFactory(asymm, securityMode);
			
		MessageBuffers buffers = encodeMessage(cf, len, request);
		ByteBuffer[] chunks = buffers.getChunks();
		ByteBuffer[] payloads = buffers.getPayloads();
		// Lock output stream
		lock.lock();
		try {
			if (asymm) {
				// Capture ClientNonce of the request message
				byte[] clientNonce = ((OpenSecureChannelRequest) request).getClientNonce();
				clientNonces.put( requestId , clientNonce );
				// 
				
				for (int i=0; i<chunks.length; i++)
				{
					boolean finalChunk = i == chunks.length-1;
					sendAsymmChunk(secureChannelId, requestId, securityMode,
							chunks[i], payloads[i], finalChunk);
					payloads[i] = null;
					chunks[i] = null;
				}
				
			} else {
				
				activeTokenIdMap.put(secureChannelId, token);
				SequenceNumber seq = sequenceNumbers.get(secureChannelId);
				
				// Add chunk headers
				for (int i=0; i<chunks.length; i++) {
					ByteBuffer chunk = chunks[i];
					final ByteBuffer payload = payloads[i];
					boolean finalChunk = chunk == chunks[chunks.length-1];
					sendSymmChunk(requestId, token, seq, chunk, payload,
							finalChunk);
					payloads[i] = null;
					chunks[i] = null;
				}				
			}
			
			out.flush();
			
		} catch (IOException e) {
			clientNonces.remove( requestId );
			LOGGER.info(addr+" Connect failed", e);
			close();
			throw new ServiceResultException(Bad_CommunicationError, e);
		} finally {
			lock.unlock();
		}
	}

	/**
	 * @param requestId
	 * @param token
	 * @param seq
	 * @param chunk
	 * @param payload
	 * @param finalChunk
	 * @throws ServiceResultException
	 * @throws IOException
	 */
	private void sendSymmChunk(int requestId, SecurityToken token,
			SequenceNumber seq, ByteBuffer chunk, final ByteBuffer payload,
			boolean finalChunk) throws ServiceResultException, IOException {
		chunk.rewind();
		chunk.putInt( (finalChunk ? TcpMessageType.MSGF : TcpMessageType.MSGC) );
		chunk.position(8);
		chunk.putInt(token.getSecureChannelId());
		
		// -- Security Header --
		chunk.putInt(token.getTokenId());
		
		// -- Sequence Header --
		int sequenceNumber = seq.getNextSendSequencenumber();
		chunk.putInt( sequenceNumber );
		chunk.putInt( requestId ); // Request number	
//					LOGGER.debug(request.getClass().getSimpleName()+" SecureChannelId="+secureChannelId+" SequenceNumber="+sequenceNumber+ ", RequestId="+requestId);					
		
		try {
			new ChunkSymmEncryptSigner(chunk, payload, token).run();
		} catch (RuntimeServiceResultException sre) {
			throw (ServiceResultException) sre.getCause();
		}
		chunk.rewind();
		out.put(chunk);
	}

	/**
	 * @param secureChannelId
	 * @param requestId
	 * @param securityMode
	 * @param chunk
	 * @param payload
	 * @param finalChunk
	 * @throws ServiceResultException
	 * @throws IOException
	 */
	private void sendAsymmChunk(int secureChannelId, int requestId,
			SecurityMode securityMode, ByteBuffer chunk,
			final ByteBuffer payload, boolean finalChunk)
			throws ServiceResultException, IOException {
		chunk.rewind();
		chunk.putInt( finalChunk ? TcpMessageType.OPNF : TcpMessageType.OPNC );
		chunk.position(8);
		chunk.putInt(secureChannelId);
		
		// -- Security Header --
		byte[] data = securityMode.getSecurityPolicy().getEncodedPolicyUri();
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
		SequenceNumber seq = sequenceNumbers.get( secureChannelId );
		int sequenceNumber = seq==null ? 1 : seq.getNextSendSequencenumber();
		chunk.putInt( sequenceNumber ); 					
		chunk.putInt( requestId ); // Request number

		LOGGER.debug("SecureChannelId="
				+ secureChannelId + " SequenceNumber=" + sequenceNumber
				+ ", RequestId=" + requestId);

		try {
			new ChunkAsymmEncryptSigner(chunk, payload, securityConfiguration).run();
		} catch (RuntimeServiceResultException sre) {
			throw (ServiceResultException) sre.getCause();
		}
			
		chunk.rewind();
		out.put(chunk);
	}

	private MessageBuffers encodeMessage(ChunkFactory cf, int len, IEncodeable request) throws ServiceResultException {
		// Calculate chunk count
		final int count = (len + cf.maxPayloadSize-1) / cf.maxPayloadSize;		
		if (limits.maxSendChunkCount!=0 && count>limits.maxSendChunkCount)
			throw new ServiceResultException(Bad_TcpMessageTooLarge);		

		// Allocate chunks
		int bytesLeft = len;
		ByteBuffer[] payloads = new ByteBuffer[count];
		ByteBuffer[] chunks = new ByteBuffer[count];
		for (int i=0; i<count; i++) {
			payloads[i] = cf.allocate(bytesLeft);
			chunks[i] = cf.expandToCompleteChunk(payloads[i]);
			bytesLeft -= payloads[i].remaining();
		}
		assert(bytesLeft==0);
			
		// Encode message
		ByteBufferArrayWriteable2.ChunkListener listener = new ByteBufferArrayWriteable2.ChunkListener() {
			public void onChunkComplete(ByteBuffer[] chunks, int index) {
			}};
		ByteBufferArrayWriteable2 outBuffer = new ByteBufferArrayWriteable2( payloads, listener );
		outBuffer.order(ByteOrder.LITTLE_ENDIAN);
		BinaryEncoder enc = new BinaryEncoder( outBuffer );
		enc.setEncoderMode(EncoderMode.NonStrict);		
		enc.setEncoderContext( ctx );
		enc.putMessage(request);
		return new MessageBuffers(chunks, payloads);
	}

	/**
	 * @param asymm 
	 * @param request 
	 * @param token 
	 * @return
	 */
	private SecurityMode getSecurityMode(boolean asymm, ServiceRequest request, SecurityToken token) {
		SecurityPolicy policy;
		MessageSecurityMode mode;
		if (asymm) {
			mode = ((OpenSecureChannelRequest)request).getSecurityMode();
			policy = securityConfiguration.getSecurityMode().getSecurityPolicy();
		} else {
	 		mode = token.getMessageSecurityMode();
	 		policy = token.getSecurityPolicy();
		}
		return new SecurityMode(policy, mode);
	}

	/**
	 * @param asymm
	 * @param policy
	 * @param mode
	 * @return
	 * @throws ServiceResultException
	 */
	private ChunkFactory getChunkFactory(boolean asymm, SecurityMode securityMode) throws ServiceResultException {
		final MessageSecurityMode messageSecurityMode = securityMode.getMessageSecurityMode();
		if (asymm) {
			// No security chunk factory
			if (messageSecurityMode == MessageSecurityMode.None) {
				return new ChunkFactory.AsymmMsgChunkFactory(limits.maxSendBufferSize, securityConfiguration);
			} else {
			//	Security chunk factory
				return new ChunkFactory.AsymmMsgChunkFactory(limits.maxSendBufferSize, securityConfiguration);
			}
			
		} else {
	 		SecurityPolicy policy = securityMode.getSecurityPolicy();
			String symmEncryptAlgo = policy .getSymmetricEncryptionAlgorithmUri();
	 		String symmSignAlgo = policy.getSymmetricSignatureAlgorithmUri();
	 		int cipherBlockSize = CryptoUtil.getCipherBlockSize(symmEncryptAlgo, null);
	 		int signatureSize = CryptoUtil.getSignatureSize(symmSignAlgo, null); 
	 		
			return new ChunkFactory(limits.maxSendBufferSize, 8, 8, 8, signatureSize, cipherBlockSize, messageSecurityMode);				
		}
	}
	
	/**
	 * Get security token to use.
	 * The last used security token is preferred if its still alive.
	 * If not the youngest token is returned.
	 * 
	 * @param secureChannelId
	 * @return security token 
	 * @throws ServiceResultException Bad_CommunicationError if no suitable token is available
	 */
	private SecurityToken getSecurityTokenToUse(int secureChannelId) 
	throws ServiceResultException
	{
		pruneInvalidTokens();
		SecurityToken token = null;
		// Find youngest token
		LOGGER.debug("tokens="+tokens.toString());
		for (SecurityToken t : tokens) {
			if ((t.getSecureChannelId() == secureChannelId)
					&& (token == null || 
							token.getCreationTime() < t.getCreationTime()))
				token = t;
		}
		LOGGER.debug("getSecurityTokenToUse#1="+token);
		// Get last input token, use it if it has not expired
		SecurityToken token2 = activeTokenIdMap.get(secureChannelId);
		if (token2!=null && !token2.isExpired()) token = token2;
		LOGGER.debug("getSecurityTokenToUse#2="+token);
		
		if (token==null) {
			throw new ServiceResultException(Bad_CommunicationError, "All security tokens have expired");
		}
		return token;
	}
	
	private void pruneInvalidTokens()
	{	
		LOGGER.debug("pruneInvalidTokens: tokens("+tokens.size()+")="+tokens);
		for (SecurityToken t : tokens)
			if (!t.isValid())
				tokens.remove(t); // works with COW list
	}

	public int getHandshakeTimeout() {
		return handshakeTimeout;
	}

	public void setHandshakeTimeout(int handshakeTimeout) {
		this.handshakeTimeout = handshakeTimeout;
	}

	/** 
	 * Add input stream message listener. All incoming messages are notified to the listener.
	 * 
	 * The listener may not block in message handling as the message is handled in 
	 * read thread.
	 * 
	 * @param listener message listener
	 */
	public void addMessageListener(IMessageListener listener) {
		listeners.add(listener);
	}
	
	public void removeMessageListener(IMessageListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void addConnectionListener(IConnectionListener listener) {
		connectionListeners.add(listener);
	}

	@Override
	public void removeConnectionListener(IConnectionListener listener) {
		connectionListeners.remove(listener);
	}
	
	/**
	 * Get the protocol version agreen in the hand-shake
	 * 
	 * @return connection protocol version
	 */
	public int getProtocolVersion() {
		return protocolVersion;
	}
	
	/**
	 * Get the initialized socket address 
	 * 
	 * @return socket address or null if the connection has not been initialized
	 */
	public SocketAddress getSocketAddress() {
		return addr;
	}
	
}
