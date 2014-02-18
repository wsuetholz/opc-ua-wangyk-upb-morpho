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

package org.opcfoundation.ua.application;

import static org.opcfoundation.ua.utils.EndpointUtil.select;

import static org.opcfoundation.ua.core.StatusCodes.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.common.NamespaceTable;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.ApplicationType;
import org.opcfoundation.ua.core.CreateSessionRequest;
import org.opcfoundation.ua.core.CreateSessionResponse;
import org.opcfoundation.ua.core.EndpointConfiguration;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.FindServersRequest;
import org.opcfoundation.ua.core.FindServersResponse;
import org.opcfoundation.ua.core.GetEndpointsRequest;
import org.opcfoundation.ua.core.GetEndpointsResponse;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.SignatureData;
import org.opcfoundation.ua.transport.ChannelService;
import org.opcfoundation.ua.transport.SecureChannel;
import org.opcfoundation.ua.transport.ServiceChannel;
import org.opcfoundation.ua.transport.UriUtil;
import org.opcfoundation.ua.transport.UriUtil.TransportProtocol;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.SecurityMode;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.transport.tcp.io.SecureChannelTcp;
import org.opcfoundation.ua.transport.tcp.io.TransportChannelSettings;
import org.opcfoundation.ua.utils.CertificateUtils;
import org.opcfoundation.ua.utils.CryptoUtil;
import org.opcfoundation.ua.utils.bytebuffer.ByteBufferUtils;

/**
 * OPC UA Client application
 */
public class Client extends Application {
	Logger logger = Logger.getLogger(Client.class);

	/**
	 * Construct a new client application
	 * 
	 * @param cert
	 */
	public Client(KeyPair cert) {
		addApplicationInstanceCertificate(cert);
		this.applicationDescription.setApplicationType(ApplicationType.Client);
	}

	/**
	 * Construct a new client application.
	 * <p>
	 * Note: Client needs an application instance certificate to create secure
	 * channels. See {@link #addApplicationInstanceCertificate(KeyPair)}
	 */
	public Client() {
		this.applicationDescription.setApplicationType(ApplicationType.Client);
	}

	/**
	 * Create a new session on a server
	 * 
	 * @param channel
	 *            open channel
	 * @throws ServiceResultException
	 */
	public Session createSession(SecureChannel channel) throws ServiceResultException {
		return createSession(channel, null, null, null);
	}

	/**
	 * Create a new session on a server
	 * 
	 * @param channel
	 *            open channel to use
	 * @param maxResponseMessageSize
	 *            max size of response messages - if null, use 4194304
	 * @param requestedSessionTimeout
	 *            requested session time out (in ms) - if null, use 3600000 (one hour)
	 * @param sessionName
	 *            session name - if null a random GUID is used to generate the
	 *            name
	 * @return the session
	 * @throws IllegalArgumentException
	 * @throws ServiceResultException
	 */
	public Session createSession(SecureChannel channel,
			UnsignedInteger maxResponseMessageSize,
			Double requestedSessionTimeout, String sessionName)
			throws IllegalArgumentException, ServiceResultException {
		if (maxResponseMessageSize == null)
		maxResponseMessageSize = UnsignedInteger.valueOf(4 * 1024 * 1024);
		if (requestedSessionTimeout == null)
		requestedSessionTimeout = 60 * 60 * 1000.0;

		EndpointDescription endpoint = channel.getEndpointDescription();
		Client client = this;
		if (endpoint == null || channel == null)
			throw new IllegalArgumentException("null arg");

		Session session = new Session();
		if (sessionName == null)
			sessionName = UUID.randomUUID() + "-"
					+ String.format("%08X", System.identityHashCode(session));

		session.endpoint = endpoint;
		session.name = sessionName;
		session.clientCertificate = client.getApplicationInstanceCertificate()
				.getCertificate();
		session.clientPrivateKey = client.getApplicationInstanceCertificate()
				.getPrivateKey();
		session.clientNonce = CryptoUtil.createNonce(32);

		// 1. Create Session
		CreateSessionRequest req = new CreateSessionRequest();
		req.setClientNonce(session.clientNonce);
		req.setClientDescription(client.getApplicationDescription());
		req.setClientCertificate(session.getClientCertificate().getEncoded());
		req.setEndpointUrl(endpoint.getEndpointUrl());
		req.setMaxResponseMessageSize(maxResponseMessageSize);
		if (endpoint.getServer() != null)
			req.setServerUri(endpoint.getServer().getApplicationUri());
		req.setSessionName(session.name);
		req.setRequestedSessionTimeout(requestedSessionTimeout/* 1 hour */);
		CreateSessionResponse res = (CreateSessionResponse) channel.serviceRequest(req);

		session.serverCertificate = res.getServerCertificate() == null ? null
				: new Cert(res.getServerCertificate());
		session.serverNonce = res.getServerNonce();
		session.sessionId = res.getSessionId();
		session.authenticationToken = res.getAuthenticationToken();
		session.sessionTimeout = res.getRevisedSessionTimeout();
		session.maxRequestMessageSize = res.getMaxRequestMessageSize();
		session.serverSoftwareCertificates = res
				.getServerSoftwareCertificates();

		logger.debug("MessageSecurityMode: " + channel.getMessageSecurityMode());
		if (!MessageSecurityMode.None.equals(channel.getMessageSecurityMode())) {
			// Verify Server Signature
			SignatureData serverSignature = res.getServerSignature();
			// Client Cert + Client nonce
			byte[] dataServerSigned = ByteBufferUtils.concatenate(req
					.getClientCertificate(), session.clientNonce);
			try {
				if (serverSignature != null)
					logger.debug("Algorithm: " + serverSignature.getAlgorithm());
				boolean ok = CertificateUtils.verify(session.serverCertificate
						.getCertificate(), serverSignature.getAlgorithm(),
						dataServerSigned, serverSignature.getSignature());
				if (!ok)
					throw new ServiceResultException(
							Bad_ApplicationSignatureInvalid,
							"The signature generated with the server certificate is missing or invalid.");
				// This proofs that the server has the private key of its
				// certificate
			} catch (InvalidKeyException e) {
				// The certificate is not Key Usable
				throw new ServiceResultException(Bad_CertificateInvalid, e);
			} catch (SignatureException e) {
				throw new ServiceResultException(Bad_CertificateInvalid, e);
			} catch (NoSuchAlgorithmException e) {
				throw new ServiceResultException(Bad_SecurityPolicyRejected,
						"Unsupported asymmetric signature algorithm: "
								+ e.getMessage());
			}
		}
		// Verify that server has the endpoint given in the arguments
		EndpointDescription[] endpoints = res.getServerEndpoints();
		EndpointDescription[] filteredEndpoints = select(endpoints, endpoint
				.getEndpointUrl(), null, endpoint.getSecurityMode(),
				SecurityPolicy.getSecurityPolicy(endpoint
						.getSecurityPolicyUri()), endpoint
						.getServerCertificate());
		if (filteredEndpoints.length == 0)
			throw new ServiceResultException(
					"Requested endpoint is not found on the server");
		if (filteredEndpoints.length == 1)
			session.endpoint = filteredEndpoints[0];

		return session;
	}

	/**
	 * Creates a secure channel and an unactivated session channel.
	 * <p>
	 * The channel needs to be activated separately.
	 * <p>
	 * To close the object, both secure channel and the session must be close
	 * separately. SessionChannel.closeSession()
	 * SessionChannel.closeSecureChannel()
	 * 
	 * @param uri
	 *            public server uri
	 * @return session
	 * @throws ServiceResultException
	 *             on errors
	 */
	public SessionChannel createSessionChannel(URI uri) throws ServiceResultException {
		// Discover server's endpoints, and choose one
		EndpointDescription[] endpoints = discoverEndpoints(uri);		
		// Suitable endpoint
		EndpointDescription endpoint = select(endpoints);
		// Crete service channel
		SecureChannel channel = createSecureChannel(endpoint);
		try {
			// Create session
			Session session = createSession(channel);
			// Create session channel
			SessionChannel sessionChannel = session.createSessionChannel(channel, this);
			return sessionChannel;
		} catch (ServiceResultException se) {
			channel.closeAsync();
			throw se;
		}
	}

	/**
	 * Creates a secure channel and an unactivated session channel.
	 * <p>
	 * The channel needs to be activated separately.
	 * <p>
	 * To close the object, both secure channel and the session must be close
	 * separately. SessionChannel.closeSession()
	 * SessionChannel.closeSecureChannel()
	 * 
	 * @param endpoint
	 *            endpoint description
	 * @return session channel
	 * @throws ServiceResultException
	 *             on errors
	 */
	public SessionChannel createSessionChannel(EndpointDescription endpoint)
			throws ServiceResultException {
		// Create service channel
		SecureChannel channel = createSecureChannel(endpoint);
		try {
			// Create session
			Session session = createSession(channel);
			// Create session channel
			SessionChannel sessionChannel = session.createSessionChannel(channel, this);
			return sessionChannel;
		} catch (ServiceResultException se) {
			channel.closeAsync();
			throw se;
		}
	}

	/**
	 * Creates a secure channel and an unactivated session channel.
	 * <p>
	 * The channel needs to be activated separately.
	 * <p>
	 * To close the object, both secure channel and the session must be close
	 * separately. SessionChannel.closeSession()
	 * SessionChannel.closeSecureChannel()
	 * 
	 * @param applicationDescription
	 *            application description
	 * @return session channel
	 * @throws ServiceResultException
	 *             on errors
	 */
	public SessionChannel createSessionChannel(
			ApplicationDescription applicationDescription)
			throws ServiceResultException {
		// Create service channel
		SecureChannel channel = createSecureChannel(applicationDescription);
		try {
			// Create session
			Session session = createSession(channel);
			// Create session channel
			SessionChannel sessionChannel = session.createSessionChannel(
					channel, this);
			return sessionChannel;
		} catch (ServiceResultException se) {
			channel.closeAsync();
			throw se;
		}
	}

	/**
	 * Create a secure channel to a UA Server. 
	 * This method first queries endpoints, chooses the most suitable and connects to it.
	 * <p>
	 * Note this implementation is unsecure as the dialog with discover endpoint
	 * is not encrypted.
	 * <p>
	 * Default Local Discovery Server (LDS) Uris: http://localhost/UADiscovery
	 * opc.tcp://localhost:4840/UADiscovery http://localhost:52601/UADiscovery
	 * 
	 * @param uri endpoint uri
	 * @return service channel
	 * @throws ServiceResultException
	 */
	public SecureChannel createSecureChannel(URI uri) throws ServiceResultException {
		return createSecureChannel( uri.toString() );
	}	

	/**
	 * Create a service channel to a UA Server This method first queries
	 * endpoints, chooses the most suitable and connects to it.
	 * <p>
	 * Note this implementation is unsecure as the dialog with discover endpoint
	 * is not encrypted.
	 * <p>
	 * Default Local Discovery Server (LDS) Uris: http://localhost/UADiscovery
	 * opc.tcp://localhost:4840/UADiscovery http://localhost:52601/UADiscovery
	 * 
	 * @param uri endpoint uri
	 * @return service channel
	 * @throws ServiceResultException
	 */
	public SecureChannel createSecureChannel(String uri) throws ServiceResultException {
		// Discover server's endpoints, and choose one
		EndpointDescription[] endpoints = discoverEndpoints(uri);
		// Filter out all but opc.tcp protocol endpoints
		EndpointDescription endpoint = select(endpoints);
		// Connect to the endpoint
		return createSecureChannel(endpoint);
	}

	/**
	 * Create a service channel to a UA application
	 * <p>
	 * This implementation accepts only connections with opc.tcp protocol and
	 * with encryption.
	 * <p>
	 * Note this implementation is unsafe as the dialog with discover endpoint
	 * is not encrypted.
	 * 
	 * @param applicationDescription
	 * @return service channel
	 * @throws ServiceResultException
	 */
	public SecureChannel createSecureChannel(
			ApplicationDescription applicationDescription)
			throws ServiceResultException {
		String urls[] = applicationDescription.getDiscoveryUrls();
		if (urls == null || urls.length == 0)
			throw new ServiceResultException(
					"application description does not contain any discovery url");
		for (String url : urls) {
			if (!url.toLowerCase().startsWith("opc.tcp"))
				continue;
			try {
				SecureChannel result = createSecureChannel(new URI(url));
				return result;
			} catch (URISyntaxException e) {
				throw new ServiceResultException(e);
			}
		}
		throw new ServiceResultException("No suitable discover url was found");
	}

	/**
	 * Create a service channel to an endpoint
	 * 
	 * @param endpoint
	 *            endpoint description
	 * @return an open service channel
	 */
	public SecureChannel createSecureChannel(EndpointDescription endpoint)
			throws ServiceResultException {
		
		org.opcfoundation.ua.transport.tcp.io.SecureChannelTcp sc = new org.opcfoundation.ua.transport.tcp.io.SecureChannelTcp();
		
		EndpointConfiguration ec = EndpointConfiguration.defaults();					
		KeyPair localApplicationInstanceCertificate = getApplicationInstanceCertificate();
		
		TransportChannelSettings settings = new TransportChannelSettings();
		settings.setConfiguration(ec);
		settings.setDescription( endpoint );
		settings.setCertificateValidator(CertificateValidator.ALLOW_ALL);
		settings.setNamespaceUris( NamespaceTable.DEFAULT );
								
		if (localApplicationInstanceCertificate!=null) {
			settings.setPrivKey( localApplicationInstanceCertificate.getPrivateKey() );
			settings.setClientCertificate( localApplicationInstanceCertificate.getCertificate() );
		}			
		
		try {
			sc.initialize(settings);
			sc.open();
			return sc;
		} catch (ServiceResultException e) {
			sc.dispose();
			throw e;
		}

	}

	/**
	 * Create and open a secure channel.
	 * 
	 * @param endpointUri
	 * @param mode
	 * @param remoteCertificate
	 * @return an open secure channel
	 * @throws ServiceResultException 
	 */
	public SecureChannel createSecureChannel(String endpointUri,
			SecurityMode mode,
			org.opcfoundation.ua.transport.security.Cert remoteCertificate) throws ServiceResultException {

			org.opcfoundation.ua.transport.tcp.io.SecureChannelTcp sc = new org.opcfoundation.ua.transport.tcp.io.SecureChannelTcp();
			
			EndpointConfiguration ec = EndpointConfiguration.defaults();			
			
			EndpointDescription ed = new EndpointDescription();
			ed.setEndpointUrl(endpointUri);
			ed.setSecurityMode( mode.getMessageSecurityMode() );
			ed.setSecurityPolicyUri( mode.getSecurityPolicy().getPolicyUri() );			
			
			KeyPair localApplicationInstanceCertificate = getApplicationInstanceCertificate();
			Cert _remoteCertificate = mode.messageSecurityMode == MessageSecurityMode.None ? null : remoteCertificate;
			
			if (_remoteCertificate != null)
				ed.setServerCertificate( _remoteCertificate.getEncoded() );

			TransportChannelSettings settings = new TransportChannelSettings();
			settings.setConfiguration(ec);
			settings.setDescription(ed);
			settings.setCertificateValidator(CertificateValidator.ALLOW_ALL);
			settings.setNamespaceUris( NamespaceTable.DEFAULT );
									
			if (localApplicationInstanceCertificate!=null) {
				settings.setPrivKey( localApplicationInstanceCertificate.getPrivateKey() );
				settings.setClientCertificate( localApplicationInstanceCertificate.getCertificate() );
			}			
			
			try {
				sc.initialize(settings);
				sc.open();
				return sc;
			} catch (ServiceResultException e) {
				sc.dispose();
				throw e;
			}

	}
	
	/**
	 * Create and open a secure channel.
	 * 
	 * @param settings
	 * @param mode
	 * @param remoteCertificate
	 * @return an open secure channel
	 * @throws ServiceResultException 
	 */
	public SecureChannel createSecureChannel(TransportChannelSettings settings) 
			throws ServiceResultException {

		TransportProtocol proto = UriUtil.getTransportProtocol( settings.getDescription().getEndpointUrl() );		
		if ( proto == TransportProtocol.Socket ) {			

			SecureChannel sc = new SecureChannelTcp();
			
			settings = settings.clone();
			
			KeyPair localApplicationInstanceCertificate = getApplicationInstanceCertificate();
			if (localApplicationInstanceCertificate!=null) {
				settings.setPrivKey( localApplicationInstanceCertificate.getPrivateKey() );
				settings.setClientCertificate( localApplicationInstanceCertificate.getCertificate() );
			}			
			
			try {
				sc.initialize(settings);
				sc.open();
				return sc;
			} catch (ServiceResultException e) {
				sc.dispose();
				throw e;
			}

		}
		throw new ServiceResultException("Unsupported protocol " + proto);
	}	

	
	
	
	/**
	 * Create a service channel to a UA Server This method first queries
	 * endpoints, chooses the most suitable and connects to it.
	 * <p>
	 * Note this implementation is unsecure as the dialog with discover endpoint
	 * is not encrypted.
	 * <p>
	 * Default Local Discovery Server (LDS) Uris: http://localhost/UADiscovery
	 * opc.tcp://localhost:4840/UADiscovery http://localhost:52601/UADiscovery
	 * 
	 * @param uri endpoint uri
	 * @return service channel
	 * @throws ServiceResultException
	 */
	public ServiceChannel createServiceChannel(URI uri) throws ServiceResultException {
		return new ServiceChannel( createSecureChannel( uri ) );
	}

	
	/**
	 * Create a service channel to a UA Server This method first queries
	 * endpoints, chooses the most suitable and connects to it.
	 * <p>
	 * Note this implementation is unsecure as the dialog with discover endpoint
	 * is not encrypted.
	 * <p>
	 * Default Local Discovery Server (LDS) Uris: http://localhost/UADiscovery
	 * opc.tcp://localhost:4840/UADiscovery http://localhost:52601/UADiscovery
	 * 
	 * @param uri endpoint uri
	 * @return service channel
	 * @throws ServiceResultException
	 */
	public ServiceChannel createServiceChannel(String uri) throws ServiceResultException {
		return new ServiceChannel( createSecureChannel( uri ) );
	}	
	
	/**
	 * Create a service channel
	 * <p>
	 * Note this implementation is unsecure as the dialog with discover endpoint
	 * is not encrypted.
	 * 
	 * @param applicationDescription
	 * @return service channel
	 * @throws ServiceResultException
	 */
	public ServiceChannel createServiceChannel(
			ApplicationDescription applicationDescription)
			throws ServiceResultException {
		return new ServiceChannel( createSecureChannel( applicationDescription ) );
	}

	/**
	 * Create a service channel to an endpoint
	 * 
	 * @param endpoint
	 *            endpoint description
	 * @return an open service channel
	 */
	public ServiceChannel createServiceChannel(EndpointDescription endpoint)
			throws ServiceResultException {
		return new ServiceChannel( createSecureChannel( endpoint ) );
	}

	/**
	 * Create and open a service channel.
	 * 
	 * @param endpointUri
	 * @param mode
	 * @param remoteCertificate
	 * @return an open secure channel
	 * @throws ServiceResultException 
	 */
	public ServiceChannel createServiceChannel(String endpointUri,
			SecurityMode mode,
			org.opcfoundation.ua.transport.security.Cert remoteCertificate) throws ServiceResultException {
		return new ServiceChannel( createSecureChannel( endpointUri, mode, remoteCertificate ) );
	}
	
	/**
	 * Create and open a secure channel and adapt to service channel.
	 * 
	 * @param settings
	 * @param mode
	 * @param remoteCertificate
	 * @return an open service channel
	 * @throws ServiceResultException 
	 */
	public ServiceChannel createServiceChannel(TransportChannelSettings settings) 
	throws ServiceResultException {
		return new ServiceChannel( createSecureChannel(settings) );
	}	


	/**
	 * Discover endpoints
	 * 
	 * @param discoveryUri
	 *            socket address
	 * @return Endpoint Descriptions
	 * @throws ServiceFaultException Error that occured while processing the operation.
	 * @throws IOException
	 * @throws URISyntaxException
	 */
	public EndpointDescription[] discoverEndpoints(URI discoveryUri)
	throws ServiceResultException, ServiceFaultException 
	{
		return discoverEndpoints( discoveryUri.toString() );
	}
	
	
	/**
	 * Discover endpoints
	 * 
	 * @param discoveryUri
	 *            socket address
	 * @return Endpoint Descriptions
	 * @throws ServiceFaultException Error that occured while processing the operation.
	 * @throws IOException
	 * @throws URISyntaxException
	 */
	public EndpointDescription[] discoverEndpoints(String discoveryUri)
			throws ServiceResultException, ServiceFaultException {
		// Must not use encryption!
		SecureChannel channel = createSecureChannel(discoveryUri,
				SecurityMode.NONE, null);
		ChannelService chan = new ChannelService(channel);
		try {
			GetEndpointsRequest req = new GetEndpointsRequest(null, discoveryUri, 
					new String[0], new String[0]);
			GetEndpointsResponse res = chan.GetEndpoints(req);
			
			EndpointDescription[] result = res.getEndpoints();
			return result;
		} finally {
			channel.close();
			channel.dispose();
		}
	}

	/**
	 * Discover applications
	 * 
	 * @param discoverServerEndpointUri
	 *            Discovery Server URI
	 * @return Endpoint Application Descriptions
	 * @throws ServiceResultException 
	 * @throws ServiceFaultException 
	 * @throws ServiceResultException
	 */
	public ApplicationDescription[] discoverApplications( URI discoverServerEndpointUri ) 
	throws ServiceFaultException, ServiceResultException {
		return discoverApplications( discoverServerEndpointUri.toString() );		
	}
	
	/**
	 * Discover applications
	 * 
	 * @param discoverServerEndpointUri
	 *            Discovery Server URI
	 * @return Endpoint Application Descriptions
	 * @throws ServiceFaultException 
	 * @throws ServiceResultException
	 */
	public ApplicationDescription[] discoverApplications(
			String discoverServerEndpointUri) throws ServiceFaultException, ServiceResultException {
		// Must not use encryption!
		SecureChannel channel = createSecureChannel(
				discoverServerEndpointUri, SecurityMode.NONE, null);
		ChannelService chan = new ChannelService(channel);
		try {
			FindServersRequest req = new FindServersRequest(null,
					discoverServerEndpointUri, new String[0],
					new String[0]);
			FindServersResponse res = chan.FindServers(req);
			return res.getServers();
		} finally {
			channel.close();
			channel.dispose();
		}
	}

}
