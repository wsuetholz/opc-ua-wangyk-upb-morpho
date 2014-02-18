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

import static org.opcfoundation.ua.core.StatusCodes.*;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.application.EndpointDiscoveryService;
import org.opcfoundation.ua.application.Server;
import org.opcfoundation.ua.builtintypes.DateTime;
import org.opcfoundation.ua.builtintypes.ServiceRequest;
import org.opcfoundation.ua.builtintypes.ServiceResponse;
import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.ChannelSecurityToken;
import org.opcfoundation.ua.core.CloseSecureChannelRequest;
import org.opcfoundation.ua.core.CloseSecureChannelResponse;
import org.opcfoundation.ua.core.GetEndpointsRequest;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.OpenSecureChannelRequest;
import org.opcfoundation.ua.core.OpenSecureChannelResponse;
import org.opcfoundation.ua.core.ResponseHeader;
import org.opcfoundation.ua.core.SecurityTokenRequestType;
import org.opcfoundation.ua.encoding.IEncodeable;
import org.opcfoundation.ua.transport.AsyncResult;
import org.opcfoundation.ua.transport.AsyncWrite;
import org.opcfoundation.ua.transport.Binding;
import org.opcfoundation.ua.transport.CloseableObjectState;
import org.opcfoundation.ua.transport.Connection;
import org.opcfoundation.ua.transport.Endpoint;
import org.opcfoundation.ua.transport.EndpointServiceRequest;
import org.opcfoundation.ua.transport.IConnectionListener;
import org.opcfoundation.ua.transport.ServerSecureChannel;
import org.opcfoundation.ua.transport.impl.AsyncResultImpl;
import org.opcfoundation.ua.transport.impl.ConnectionCollection;
import org.opcfoundation.ua.transport.impl.EndpointCollection;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.SecurityConfiguration;
import org.opcfoundation.ua.transport.security.SecurityMode;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.transport.tcp.impl.Acknowledge;
import org.opcfoundation.ua.transport.tcp.impl.ChunkUtils;
import org.opcfoundation.ua.transport.tcp.impl.ErrorMessage;
import org.opcfoundation.ua.transport.tcp.impl.Hello;
import org.opcfoundation.ua.transport.tcp.impl.SecurityToken;
import org.opcfoundation.ua.transport.tcp.impl.TcpMessageType;
import org.opcfoundation.ua.utils.AbstractState;
import org.opcfoundation.ua.utils.CertificateUtils;
import org.opcfoundation.ua.utils.CryptoUtil;
import org.opcfoundation.ua.utils.ObjectUtils;
import org.opcfoundation.ua.utils.StackUtils;
import org.opcfoundation.ua.utils.TimerUtil;
import org.opcfoundation.ua.utils.asyncsocket.AsyncServerSocket;
import org.opcfoundation.ua.utils.asyncsocket.AsyncSocketImpl;

/**
 * UATcpServer binds to a tcp socket and hosts a port for endpoints.
 * UATcpServer provides endpoint discovery if endpoint url is unknown.
 *
 * @see Executors for creating executor instances
 */
public class UATcpServer extends AbstractState<CloseableObjectState, ServiceResultException> implements Binding {

	/** Server Socket */
	AsyncServerSocket socket;
	/** Secure channel counter */
	AtomicInteger secureChannelCounter = new AtomicInteger();
	/** Endpoints */
	EndpointCollection endpoints;
	/** Rollback endpoint (for bad endpoint urls), contains endpoint discovery */
	Endpoint rollbackEndpoint;
	/** Rollback Server for default endpoint */
	Server rollbackServer;
	/** Logger */
	static Logger logger = Logger.getLogger(UATcpServer.class);
	
	/** AsyncServerSocket Connect listener */
	org.opcfoundation.ua.utils.asyncsocket.AsyncServerSocket.ConnectListener connectListener = new org.opcfoundation.ua.utils.asyncsocket.AsyncServerSocket.ConnectListener() {		
		public void onConnected(AsyncServerSocket sender, AsyncSocketImpl newConnection) {
			logger.info(UATcpServer.this+": "+newConnection.socket().getRemoteSocketAddress()+" connected");
			UATcpServerConnection conn = new UATcpServerConnection(newConnection);
			connections.addConnection(conn);
		}};
	ConnectionCollection connections = new ConnectionCollection(this);	
	
	public UATcpServer() throws IOException
	{
		super(CloseableObjectState.Closed, CloseableObjectState.Closed);
		socket = new AsyncServerSocket(
				(ServerSocketChannel) ServerSocketChannel.open().configureBlocking(false),
				StackUtils.getNonBlockingWorkExecutor(),  
				StackUtils.SELECTOR
				);
		socket.addListener(connectListener);
		
		rollbackEndpoint = new Endpoint("", SecurityMode.ALL);
		rollbackServer = new Server();
		EndpointDiscoveryService eds = rollbackServer.getServiceHandlerByService( GetEndpointsRequest.class );
		endpoints = eds.getEndpointCollection();
	}
	
	/**
	 * Convenience constructor that creates a server and binds it to a port.
	 * 
	 * @param addr
	 * @throws IOException
	 */
	public UATcpServer(SocketAddress addr) throws IOException
	{
		this();
		bind(addr);
	}
	

	/**
	 * Binds server socket to a port.
	 * 
	 * @param addr
	 * @return this object. Used for chained invocation.
	 * @throws IOException
	 */
	public synchronized UATcpServer bind(SocketAddress addr) 
	throws IOException
	{		
		setState(CloseableObjectState.Opening);
		try {
			socket.bind(addr, 0);
			logger.info("TCP/IP Socket bound to "+addr);
		} catch (IOException e) {
			setState(CloseableObjectState.Closed);
			throw e;
		}
		setState(CloseableObjectState.Open);
		return this;
	}
	
	public SocketAddress getBoundAddress() {
		return socket.socket().getLocalSocketAddress();
	}
	
	/**
	 * Disconnect all existing connections. 
	 */
	public void disconnectAll()
	{
		List<Connection> list = new ArrayList<Connection>();
		getConnections(list);
		for (Connection connection : list) {
			UATcpServerConnection c = (UATcpServerConnection) connection;
			c.close();
		}
	}

	/**
	 * Closes server socket. Does not disconnect existing connections.
	 */
	@Override
	public synchronized UATcpServer close() {
		rollbackServer.close();
		logger.info(getBoundAddress()+" closed");
		if (getState().isClosed()) return this;
		setState(CloseableObjectState.Closing);
		try {
			socket.close();
		} finally {
			setState(CloseableObjectState.Closed);
		}
		return this;
	}

	
	public class UATcpServerConnection extends UATcpConnection {

		/** Agreed protocol version */
		int agreedProtocolVersion;		
		/**  Request id - Pending Request mapping */
		Map<Integer, PendingRequest> pendingRequests  = new ConcurrentHashMap<Integer, PendingRequest>();
		/** Endpoint */
		Endpoint endpoint;
		/** Server */
		Server server;
		
		Timer timer = TimerUtil.getTimer();
		
		/** Pending requests */
		class PendingRequest extends EndpointServiceRequest<ServiceRequest, ServiceResponse> {		
			public PendingRequest(UATcpServerSecureChannel channel, Endpoint endpoint, Server server, int requestId, ServiceRequest requestMessage) {
				super(requestMessage, server, endpoint);
				this.channel = channel;
				this.requestId = requestId;
				this.requestMessage = requestMessage;
			}
			IEncodeable requestMessage;
			UATcpServerSecureChannel channel;
			int requestId;
			AsyncWrite write;
			@Override
			public ServerSecureChannel getChannel() {
				return channel;
			}
			@Override
			public void sendResponse(AsyncWrite response) {
				pendingRequests.remove(requestId);
				sendSecureMessage(response, channel.activeToken, requestId, TcpMessageType.MESSAGE, channel.sendSequenceNumber);
			}
			@Override
			public AsyncWrite sendResponse(ServiceResponse response) {
				write = new AsyncWrite(response);
				sendResponse(write);
				return write;
			}
		}

		UATcpServerConnection(AsyncSocketImpl s) {
			super(s);
			setState(CloseableObjectState.Opening);
			
			// Give client 10 minutes to handshake
			long handshakeTimeout = 10 * 60 * 1000; // 10 minutes 
			timeoutTimer = TimerUtil.schedule(timer, timeout, StackUtils.getBlockingWorkExecutor(), System.currentTimeMillis() + handshakeTimeout); 
		}

		TimerTask timeoutTimer;
		Runnable timeout = new Runnable() {
			public void run() {
				setError(Bad_Timeout);
			}};		
		
		@Override
		protected void onHello(Hello h) throws ServiceResultException {
			// Cancel hand-shake time-out
			if (timeoutTimer!=null) {
				timeoutTimer.cancel();
				timeoutTimer = null;
			}
			
			EndpointCollection c = getEndpoints();// UATcpServer.this.endpoints;
			if (c==null) throw new ServiceResultException(Bad_UnexpectedError);
			String url = trimUrl(h.getEndpointUrl());
			
			logger.debug("onHello: url=" + url);
			
//			if (url==null) url = "";
			endpoint = c.get( url ); // Returns the first endpoint if url=null
			logger.debug(" endpoints=" + Arrays.toString(c.getEndpoints()));
			logger.debug(" endpoint=" + endpoint);
			if (endpoint==null) {
//				throw new ServiceResultException(Bad_TcpEndpointUrlInvalid);
				endpoint = rollbackEndpoint;
				server = rollbackServer;
			} else {
				server = c.getServer(endpoint);
			}
			
			if (getState()!=CloseableObjectState.Opening) throw new ServiceResultException(Bad_UnexpectedError);

			Acknowledge a = new Acknowledge();
			
			// Assert sane values from client
			if (h.getSendBufferSize().longValue()<8192)
				setError(new ServiceResultException(Bad_TcpInternalError, "Peer send buffer size <  8192"));
			if (h.getReceiveBufferSize().longValue()<8192)
				setError(new ServiceResultException(Bad_TcpInternalError, "Peer recv buffer size <  8192"));
			
			// Determine communication protocol version
			agreedProtocolVersion = Math.min(StackUtils.TCP_PROTOCOL_VERSION, h.getProtocolVersion().intValue());
			a.setProtocolVersion( UnsignedInteger.getFromBits(agreedProtocolVersion) );
			
			// Message size
			if (h.getMaxMessageSize()!=null && h.getMaxMessageSize().intValue()!=0) {
				if (ctx.maxSendMessageSize==0) 
					ctx.maxSendMessageSize = h.getMaxMessageSize().intValue();
				else
					ctx.maxSendMessageSize = Math.min(ctx.maxSendMessageSize, h.getMaxMessageSize().intValue());
			}

			// Chunk count
			if (h.getMaxChunkCount().intValue()!=0)
				ctx.maxSendChunkCount = Math.min(ctx.maxSendChunkCount, h.getMaxChunkCount().intValue());
			a.setMaxChunkCount( UnsignedInteger.getFromBits( ctx.maxRecvChunkCount ) );
			
			// Chunk sizes
			ctx.maxSendChunkSize = Math.min(h.getReceiveBufferSize().intValue(), ctx.maxSendChunkSize);
			ctx.maxRecvChunkSize = Math.min(h.getSendBufferSize().intValue(), ctx.maxRecvChunkSize);
			a.setSendBufferSize(UnsignedInteger.getFromBits(ctx.maxSendChunkSize));
			a.setReceiveBufferSize(UnsignedInteger.getFromBits(ctx.maxRecvChunkSize));
			
			// Send buffer (chunk) size
			ctx.maxRecvChunkSize = Math.min(ctx.maxRecvChunkSize, h.getReceiveBufferSize().intValue());
			ctx.maxSendChunkSize = Math.min(ctx.maxSendChunkSize, h.getSendBufferSize().intValue());
			setState(CloseableObjectState.Opening);
			
			ctx.endpointUrl = h.getEndpointUrl();
			
			sendAcknowledge(a);
			setState(CloseableObjectState.Open);
		}
		
		@Override
		protected void onAcknowledge(Acknowledge a) throws ServiceResultException {
			throw new ServiceResultException(Bad_UnexpectedError);			
		}

		@Override
		protected void onError(ErrorMessage e) {			
			setError(e.getError());
		}

		protected void onAsymmSecureChunk(ByteBuffer chunk) throws ServiceResultException {
			chunk.rewind();		
			if (secureMessageBuilder!=null && !secureMessageBuilder.moreChunksRequired()) secureMessageBuilder = null;
			
			// First chunk of the message
			if (secureMessageBuilder==null) {
				// Read remote certificate and thumbprint of the expected local certificate
//				chunk.position(8);
//				int secureChannelId = chunk.getInt();			
				int secureChannelId = ChunkUtils.getSecureChannelId(chunk);			
				UATcpSecureChannel secureChannel =(UATcpSecureChannel) secureChannels.get(secureChannelId);			
				
				String securityPolicyUri = ChunkUtils.getString(chunk);
				SecurityPolicy securityPolicy = SecurityPolicy.getSecurityPolicy(securityPolicyUri);
				if (securityPolicy==null)
				{
					log.warn("Security policy \""+securityPolicyUri+"\" is not supported by the stack");
					throw new ServiceResultException("Security policy \""+securityPolicyUri+"\" is not supported by the stack");
				}
				
				if (!endpoint.supportsSecurityPolicy(securityPolicy)) 
				{
					log.warn("Security policy \""+securityPolicyUri+"\" is not supported by the endpoint");
					throw new ServiceResultException("Security policy \""+securityPolicyUri+"\" is not supported by the endpoint");
				}				
				
				byte[] encodedRemoteCertificate = ChunkUtils.getByteString(chunk);
				byte[] encodedLocalCertificateThumbprint = ChunkUtils.getByteString(chunk);

				KeyPair localCertificate = server.getApplicationInstanceCertificate(encodedLocalCertificateThumbprint);
				
				if (localCertificate==null && securityPolicy != SecurityPolicy.NONE) {
					log.warn("Requested Application Instance Certificate is not found in the server");
					throw new ServiceResultException("Requested Application Instance Certificate is not found in the server");
					// FIXME exception is not sent to client as service fault, is it possible?
				}
				
				// Decode remote certificate
				org.opcfoundation.ua.transport.security.Cert remoteCertificate;
		        try {
		        	remoteCertificate = 
		        		encodedRemoteCertificate==null ? 
		        		null : 
		        		new org.opcfoundation.ua.transport.security.Cert( CertificateUtils.decodeX509Certificate(encodedRemoteCertificate) ); 
				} catch (CertificateException e) {
					throw new ServiceResultException(Bad_CertificateInvalid);
				}

				// Validate Client's Certificate
				StatusCode code = getRemoteCertificateValidator().validateCertificate( remoteCertificate );
				if (code!=null && !code.isGood()) {
					log.warn("Remote certificate not accepted: "+code.toString());
					throw new ServiceResultException(code);
				}

				// MessageMode is unknown at this time. It is fixed in UATcpServerSecureChannel.onOpenChannel
				MessageSecurityMode msm = securityPolicy == SecurityPolicy.NONE ? MessageSecurityMode.None : MessageSecurityMode.SignAndEncrypt;  
				SecurityMode mode = new SecurityMode(securityPolicy, msm);					
				securityConfiguration = new SecurityConfiguration(mode, localCertificate, remoteCertificate);

				AtomicInteger recvSequenceNumber = secureChannel==null ? null : secureChannel.recvSequenceNumber;
				
				secureMessageBuilder = new SecureInputMessageBuilder(securityConfiguration, messageListener, ctx, encoderCtx, recvSequenceNumber);
			}
			logger.debug("onAsymmSecureChunk: " + chunk);
			secureMessageBuilder.addChunk(chunk);
		}
		
		@Override
		protected CertificateValidator getRemoteCertificateValidator() {
			return server==null ? null: server.getClientApplicationInstanceCertificateValidator();
		}
		
		@Override
		protected void onCloseChannel(InputMessage mb) throws ServiceResultException {
			logger.error("onCloseChannel");
			IEncodeable msg = mb.getMessage();
			if (!(msg instanceof CloseSecureChannelRequest)) 
				throw new ServiceResultException(Bad_UnexpectedError);
			
			CloseSecureChannelRequest req = (CloseSecureChannelRequest) msg;
			int secureChannelId = mb.getSecureChannelId();
			UATcpServerSecureChannel chan = (UATcpServerSecureChannel) secureChannels.get(secureChannelId);
			if (chan==null) throw new ServiceResultException( Bad_SecureChannelIdInvalid );
			chan.onCloseChannel(mb, req);
		}

		@Override
		protected void onOpenChannel(InputMessage mb) throws ServiceResultException {
			IEncodeable msg = mb.getMessage();
			if (msg==null) {
				Exception e = mb.getError();
				e.printStackTrace();
				throw new ServiceResultException(Bad_UnexpectedError, e);
			}
			if (!(msg instanceof OpenSecureChannelRequest)) 
				throw new ServiceResultException(Bad_UnexpectedError);
			
			OpenSecureChannelRequest req		= (OpenSecureChannelRequest) msg;
			
			if (req.getRequestType() == SecurityTokenRequestType.Issue)
			{
				UATcpServerSecureChannel channel = new UATcpServerSecureChannel( secureChannelCounter.incrementAndGet() );
				channel.onOpenChannel(mb, req);
			} else if (req.getRequestType() == SecurityTokenRequestType.Renew) {
				UATcpServerSecureChannel channel = (UATcpServerSecureChannel) secureChannels.get(mb.getSecureChannelId());
				if (channel==null) 
					throw new ServiceResultException( Bad_SecureChannelIdInvalid );
				
				if (!ObjectUtils.objectEquals(req.getRequestType(), SecurityTokenRequestType.Renew)) throw new ServiceResultException(Bad_UnexpectedError);
				
				channel.onRenewChannel(mb, req);								
			}
		}
		
		@Override
		protected void onSecureMessage(InputMessage mb) throws ServiceResultException {
			IEncodeable msg = mb.getMessage();
			logger.debug("onSecureMessage: " + msg.getClass().getSimpleName());
			int secureChannelId = mb.getSecureChannelId();
			//logger.debug(" secureChannelId="+secureChannelId);
			UATcpServerSecureChannel chan = (UATcpServerSecureChannel) secureChannels.get(secureChannelId);
			//logger.debug(" chan="+chan);
			if (chan==null) 
				throw new ServiceResultException( Bad_SecureChannelIdInvalid );
			
			if (msg instanceof OpenSecureChannelRequest) {
				OpenSecureChannelRequest req = (OpenSecureChannelRequest) msg;
				
				if (!ObjectUtils.objectEquals(req.getRequestType(), SecurityTokenRequestType.Renew)) throw new ServiceResultException(Bad_UnexpectedError);
				
				chan.onRenewChannel(mb, req);				
			} else {
				chan.onSecureMessage(mb, msg);
			}
		}
		
		// Propagate connection closed/error to channels
		@Override
		protected synchronized void onStateTransition(CloseableObjectState oldState,
				CloseableObjectState newState) {
			super.onStateTransition(oldState, newState);
			logger.debug("onStateTransition: " + oldState + "->" + newState);
			
			if (newState == CloseableObjectState.Closing)
			{
				ServiceResultException err = getError();
				List<ServerSecureChannel> list = new ArrayList<ServerSecureChannel>();
				UATcpServerConnection.this.getSecureChannels(list);				
				for (ServerSecureChannel c : list)
				{
					UATcpServerSecureChannel cc = (UATcpServerSecureChannel) c;
					if (err!=null) cc.setError(err);
					c.close();
				}
			}		
		}

		public class UATcpServerSecureChannel extends UATcpSecureChannel implements ServerSecureChannel {

			/** Security profile for this security channel */
			SecurityConfiguration securityConfiguration;			
			/** Secure channel counter */
			AtomicInteger tokenIdCounter = new AtomicInteger();			
			
			public UATcpServerSecureChannel(int secureChannelId)
			{
				super();
				super.secureChannelId = secureChannelId;
			}
			
			@Override
			public String getConnectURL() {
				return ctx.endpointUrl;
			}

			@Override
			public Connection getConnection() {
				return UATcpServerConnection.this;
			}
			
			@Override
			public void close() {				
				if (getState()!=CloseableObjectState.Open) return;				
				setState(CloseableObjectState.Closing);
				setState(CloseableObjectState.Closed);
				return;
			}

			@Override
			public AsyncResult closeAsync() {
				AsyncResultImpl result = new AsyncResultImpl(); 
				if (getState()!=CloseableObjectState.Open) {
					result.setResult(this);
					return result;				
				}
				setState(CloseableObjectState.Closing);
				setState(CloseableObjectState.Closed);
				result.setResult(this);
				return result;
			}

			@Override
			public Endpoint getEndpoint() {
				return endpoint;
			}
			
			public Server getServer() {
				return server;
			}

			@Override
			public void getPendingServiceRequests(Collection<EndpointServiceRequest<?, ?>> result) {
				result.addAll( pendingRequests.values() );
			}
			
			protected void onSecureMessage(InputMessage mb, IEncodeable msg) throws ServiceResultException {
				logger.debug("onSecureMessage: server="+server);
				logger.debug("onSecureMessage: endpoint="+endpoint);
				int requestId = mb.getRequestId();
				PendingRequest req = new PendingRequest(this, endpoint, server, mb.getRequestId(), (ServiceRequest) msg); 
				pendingRequests.put(requestId, req);
				server.getServiceHandlerComposition().serve(req);
			}

			private SecurityToken createToken(OpenSecureChannelRequest req, InputMessage mb) throws ServiceResultException
			{
				byte[] clientNonce					= req.getClientNonce();
				int tokenId							= tokenIdCounter.incrementAndGet();				

				String algo = securityConfiguration.getSecurityPolicy().getAsymmetricEncryptionAlgorithmUri();
				int nonceLength = CryptoUtil.getNonceLength( algo );
				byte[] serverNonce = CryptoUtil.createNonce( nonceLength );
				
				final UnsignedInteger tokenLifetime = 
					req.getRequestedLifetime() != null && req.getRequestedLifetime().intValue() > 0 
						? req.getRequestedLifetime() 
						: StackUtils.SERVER_GIVEN_TOKEN_LIFETIME;
				log.debug("tokenLifetime: "+tokenLifetime);
				SecurityToken token = new SecurityToken(
						securityConfiguration, 
						secureChannelId,
						tokenId,
						System.currentTimeMillis(),
						tokenLifetime.longValue(),
						serverNonce,
						clientNonce
						);
				tokens.put(tokenId, token);

				return token;
			}

			private void sendOpenChannelResponse(InputMessage mb,
					SecurityToken token, SecurityConfiguration securityConfiguration) throws ServiceResultException {
				ChannelSecurityToken chanToken		= new ChannelSecurityToken();
				chanToken.setChannelId( UnsignedInteger.valueOf(secureChannelId) );
				chanToken.setCreatedAt( new DateTime() );
				chanToken.setRevisedLifetime(UnsignedInteger.valueOf(token.getLifeTime()));
				chanToken.setTokenId(UnsignedInteger.valueOf(token.getTokenId()));
				
				setState(CloseableObjectState.Open);	
				secureChannels.put(secureChannelId, this);				

				OpenSecureChannelResponse res		= new OpenSecureChannelResponse();
				res.setResponseHeader(new ResponseHeader());
				res.setSecurityToken(chanToken);
				res.setServerNonce(token.getLocalNonce());
				res.setServerProtocolVersion( UnsignedInteger.valueOf(agreedProtocolVersion) );
				
				AsyncWrite msgToWrite = new AsyncWrite(res);
				boolean isAsync = (mb.getMessageType() == TcpMessageType.OPEN) || (mb.getMessageType() == TcpMessageType.CLOSE); 
				if (isAsync) {
					sendAsymmSecureMessage(msgToWrite, securityConfiguration, token.getSecureChannelId(), mb.getRequestId(), sendSequenceNumber);
				} else {
					sendSecureMessage(msgToWrite, activeToken, mb.getRequestId(), TcpMessageType.MESSAGE, sendSequenceNumber);
				}
				
			}

			protected void onOpenChannel(InputMessage mb, OpenSecureChannelRequest req) throws ServiceResultException {

				SecurityConfiguration sc				= (SecurityConfiguration) mb.getToken();
				SecurityPolicy securityPolicy		= sc.getSecurityPolicy();
				MessageSecurityMode messageMode		= req.getSecurityMode();
				SecurityMode securityMode			= new SecurityMode(securityPolicy, messageMode);
				if (!endpoint.supportsSecurityMode(securityMode)) {
					log.warn("The requested MessageSecurityMode("+messageMode+") is not supported by the endpoint");
					throw new ServiceResultException("The requested MessageSecurityMode("+messageMode+") is not supported by the endpoint");
				}
				securityConfiguration				= 
					new SecurityConfiguration(
						securityMode,
						sc.getLocalCertificate2(),
						sc.getRemoteCertificate2());
				
				SecurityToken token = createToken(req, mb);

				// Set the receive sequence number to the size of the list
				recvSequenceNumber.set( mb.getSequenceNumbers().get(mb.getSequenceNumbers().size()-1)+1 );
				
				setState(CloseableObjectState.Opening);
				setActiveSecurityToken(token);				
				
				sendOpenChannelResponse(mb, token, securityConfiguration);

				log.info("SecureChannel opened; "+getActiveSecurityToken());
			}

			protected void onRenewChannel(InputMessage mb, OpenSecureChannelRequest req) throws ServiceResultException {
				SecurityToken token = createToken(req, mb);
				sendOpenChannelResponse(mb, token, (SecurityConfiguration) mb.getToken());
				log.info("SecureChannel renewed; "+token);
			}

			
			protected void onCloseChannel(InputMessage mb, CloseSecureChannelRequest req) {
				close();	
				CloseSecureChannelResponse res = new CloseSecureChannelResponse();
				AsyncWrite msg = new AsyncWrite(res);
				sendSecureMessage(msg, getActiveSecurityToken(), mb.getRequestId(), TcpMessageType.CLOSE, sendSequenceNumber);				
			}
			
			// Propagate channel closed/error to pending requests
			@Override
			protected synchronized void onStateTransition(CloseableObjectState oldState, CloseableObjectState newState) 
			{			
				super.onStateTransition(oldState, newState);
				
				if (newState==CloseableObjectState.Closed) {	
					log.info("Secure Channel closed, token="+activeToken);
					secureChannels.remove( getSecureChannelId() );
					fireSecureChannelDetached( this );
					// Cancel pending requests			
					ServiceResultException se = new ServiceResultException(Bad_SecureChannelClosed);
					for (PendingRequest pr : getPendingRequests2())
					{
						AsyncWrite w = pr.write;
						if (w!=null) w.attemptSetError(se);
					}
				}
			}
			
			protected Collection<PendingRequest> getPendingRequests2() {
				ArrayList<PendingRequest> result = new ArrayList<PendingRequest>();
				for (PendingRequest pr : pendingRequests.values()) {
					if (pr.channel == this)
						result.add(pr);
				}
				return result;
			}

			@Override
			public void dispose() {
			}

			@Override
			public boolean isOpen() {
				return getState().isOpen();
			}
			
		}

		@Override
		public void addConnectionListener(IConnectionListener listener) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void removeConnectionListener(IConnectionListener listener) {
			// TODO Auto-generated method stub
			
		}

		/**
		 * @param uri
		 * @return
		 */
		private String trimUrl(String uri) {
			// Also remove an optional '/' from the end, since it is not significant
			if (uri.endsWith("/"))
				uri = uri.substring(0, uri.length()-1);
			return uri;
		}
		

	}
	
	@Override
	public EndpointCollection getEndpoints() {
		return endpoints;
	}

	@Override
	public void addConnectionListener(org.opcfoundation.ua.transport.ConnectionMonitor.ConnectListener l) {
		connections.addConnectionListener(l);
	}

	@Override
	public void getConnections(Collection<Connection> result) {
		connections.getConnections(result);
	}

	@Override
	public void removeConnectionListener(org.opcfoundation.ua.transport.ConnectionMonitor.ConnectListener l) {
		connections.removeConnectionListener(l);
	}	
	
	
	@Override
	public String toString() {
		if (!socket.socket().isBound()) return getClass().getSimpleName()+"(Unbound)";
		return getClass().getSimpleName()+"("+socket.socket().getLocalSocketAddress().toString()+")";
	}	
	
	public Object getBindIdentity() {
		return socket.socket().getLocalSocketAddress();
	}
	
}
