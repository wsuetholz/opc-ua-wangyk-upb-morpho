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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.builtintypes.ServiceRequest;
import org.opcfoundation.ua.builtintypes.UnsignedByte;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.ApplicationType;
import org.opcfoundation.ua.core.AttributeServiceSetHandler;
import org.opcfoundation.ua.core.DiscoveryServiceSetHandler;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.MethodServiceSetHandler;
import org.opcfoundation.ua.core.MonitoredItemServiceSetHandler;
import org.opcfoundation.ua.core.NodeManagementServiceSetHandler;
import org.opcfoundation.ua.core.ServiceFault;
import org.opcfoundation.ua.core.SessionServiceSetHandler;
import org.opcfoundation.ua.core.SubscriptionServiceSetHandler;
import org.opcfoundation.ua.core.TestServiceSetHandler;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.encoding.IEncodeable;
import org.opcfoundation.ua.transport.Binding;
import org.opcfoundation.ua.transport.BindingFactory;
import org.opcfoundation.ua.transport.Endpoint;
import org.opcfoundation.ua.transport.impl.EndpointCollection;
import org.opcfoundation.ua.transport.security.AllowAllCertificatesValidator;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.SecurityMode;

/**
 * A server is an application that serves to {@link ServiceRequest}s queries.
 * <p> 
 * Server may has one or multiple application instance certificates.
 * <p>
 * The initial server contains {@link EndpointDiscoveryService} by defualt.
 *
 * @see Application  
 * @see ServiceHandler service handler
 * @see BindingFactory#bind(Endpoint, Server) to bind an endpoint to a server 
 */
public class Server extends Application {

	/** Logger */
	static Logger logger = Logger.getLogger(Server.class);
	
	/** Service Handler */
	ServiceHandlerComposition serviceHandlers = new ServiceHandlerComposition();
	/** Client Application Instance Certificate validator */
	CertificateValidator clientApplicationInstanceCertificateValidator = new AllowAllCertificatesValidator();
	/** User Token Policies */
	List<UserTokenPolicy> userTokenPolicies = new CopyOnWriteArrayList<UserTokenPolicy>();
	/** Endpoints */
	EndpointCollection endpoints = new EndpointCollection();
	/** Endpoint discovery service */
	EndpointDiscoveryService endpointDiscoveryService = new EndpointDiscoveryService( endpoints );
	
	public Server() {
		applicationDescription.setApplicationType(ApplicationType.Server);
		addServiceHandler( endpointDiscoveryService );
	}
	
	/**
	 * Add Service Handler. Service handler handles one or more service methods.  
	 * Note, the server may not have more than one service handler for each method.
	 * <p>
	 * The <tt>serviceHandler</tt> is either: 
	 *  (a) an implementation of {@link ServiceHandler}
	 *  (b) an object that contains methods that implement service requests. 
	 *      These methods are discovered using Java Reflection. 
	 * <p>
	 * The following list contains service methods grouped by service sets:
	 * @see AttributeServiceSetHandler
	 * @see DiscoveryServiceSetHandler
	 * @see MethodServiceSetHandler
	 * @see MonitoredItemServiceSetHandler
	 * @see NodeManagementServiceSetHandler
	 * @see SessionServiceSetHandler
	 * @see SubscriptionServiceSetHandler
	 * @see TestServiceSetHandler
	 * <P>
	 * The <tt>serviceHandler</tt> may implement one or more methods.
	 * In typical case service handler implements one service set, e.g. 
	 * {@link SessionServiceSetHandler}.
	 * <p>
	 * A {@link ServiceFault} is returned to the client in case the server doesn't
	 * the requested service method.
	 * <p>
	 * Example: 
	 *   addServiceHandler( new TestServiceSetHandler() {
	 *      void onTestStack(EndpointServiceRequest<TestStackRequest, TestStackResponse> req) {
	 *         req.sendResponse( new ServiceFault() ); 
	 *      }
	 *      void onTestStackEx(EndpointServiceRequest<TestStackExRequest, TestStackExResponse> req) {
	 *         req.sendFault(new ServiceFault());
	 *      }
	 *   } );
	 * 
	 * @param serviceHandler instanceof {@link ServiceHandler} or Object implementing service requests
	 */
	public void addServiceHandler(Object serviceHandler) 
	{
		if (serviceHandler==null) throw new IllegalArgumentException("null arg");
		logger.debug("addServiceHandler: " + serviceHandler + " from " + 
				Thread.currentThread().getStackTrace()[2].toString());
		serviceHandlers.add(serviceHandler);
	}
	
	public ServiceHandler[] getServiceHandlers() {
		return serviceHandlers.getServiceHandlers();
	}
	
	/**
	 * Get Service Handler object by service.
	 * <p>
	 * For example, to acquire session manager:
	 *    SessionManager sessionManager = x.getServiceHandlerByService( CreateSessionRequest.class );
	 *      
	 * @param <T> 
	 * @param requestClass Service request class
	 * @return Service handler that serves the given request class in this server
	 */
	@SuppressWarnings("unchecked")
	public <T> T getServiceHandlerByService(Class<? extends ServiceRequest> requestClass)
	{
		return (T) serviceHandlers.getServiceHandlerByService(requestClass);
	}	
	
	/**
	 * Query whether the server can handle a service.
	 * 
	 * @param requestClass request class of the service, e.g. ReadRequest 
	 * @return true if server can handle the service
	 */
	public boolean handlesService(Class<? extends IEncodeable> requestClass)
	{		
		return serviceHandlers.supportsService(requestClass);
	}
	
	public ServiceHandlerComposition getServiceHandlerComposition() {
		return serviceHandlers;
	}

	public CertificateValidator getClientApplicationInstanceCertificateValidator() {
		return clientApplicationInstanceCertificateValidator;
	}

	public void setClientApplicationInstanceCertificateValidator(CertificateValidator clientApplicationInstanceCertificateValidator) {
		this.clientApplicationInstanceCertificateValidator = clientApplicationInstanceCertificateValidator;
	}
	
	public void addUserTokenPolicy(UserTokenPolicy policy) {
		this.userTokenPolicies.add(policy);
	}
	
	public void removeUserTokenPolicy(UserTokenPolicy policy) {
		this.userTokenPolicies.remove( policy );
	}
	
	public UserTokenPolicy[] getUserTokenPolicies() {
		return userTokenPolicies.toArray( new UserTokenPolicy[0] );
	}

	/**
	 * Bind an endpoint to a server. An endpoint requires concrete transport 
	 * means to bind endpoint to. For instance, binary (opc.tcp) endpoint 
	 * requires a socket and SOAP (http) endpoint requires a web server. This 
	 * method will use existing service or create a new one if necessary. 
	 * 
	 * @param endpoint endpoint 
	 * @throws ServiceResultException
	 */
	public void bind(Endpoint endpoint)
	throws ServiceResultException
	{
		BindingFactory.getInstance().bind(endpoint, this);
		endpoints.add(endpoint, this);
		logger.info("Endpoint bound "+endpoint.getEndpointUrl());		
	}
	
	/**
	 * Unbind an endpoint from the server.
	 * If all endpoints are removed from the {@link Binding} then it will be closed.
	 * 
	 * @param endpoint endpoint to unbind
	 */
	public void unbind(Endpoint endpoint)
	throws ServiceResultException
	{
		BindingFactory.getInstance().unbind(endpoint);
		endpoints.remove(endpoint);
		logger.info("Endpoint unbound "+endpoint.getEndpointUrl());		
	}
	
	/**
	 * Close the server. 
	 */
	public void close()
	{
		BindingFactory.getInstance().unbind(this);
		logger.info("Server "+this+" closed");				
	}
	
	public Endpoint[] getEndpoints() {
		return endpoints.getEndpoints();
	}
	
	public boolean hasEndpoint(String uri) {
		return endpoints.get(uri) != null;
	}
	
	public Endpoint getEndpointByUri(String uri) {
		return endpoints.get(uri);
	}
	
	public EndpointDescription[] getEndpointDescriptions() {		
		List<EndpointDescription> result = new ArrayList<EndpointDescription>( endpoints.size() );
		UserTokenPolicy[] userTokenPolicies = getUserTokenPolicies();
		
		for (Endpoint ep : getEndpoints())
		{
			for (KeyPair serverApplicationInstanceCertificate : getApplicationInstanceCertificates())
			{
				ApplicationDescription ap = getApplicationDescription(); 
			
				for (SecurityMode conf : ep.getSecurityModes())
				{
					MessageSecurityMode msm = conf.getMessageSecurityMode();
					int securityLevel = msm == MessageSecurityMode.None ? 0 : msm == MessageSecurityMode.Sign ? 1 : msm == MessageSecurityMode.SignAndEncrypt ? 2 : -1;
				
					EndpointDescription desc = new EndpointDescription();
					desc.setEndpointUrl( ep.getEndpointUrl() );
					desc.setSecurityMode( conf.getMessageSecurityMode() );
					desc.setSecurityLevel( UnsignedByte.valueOf(securityLevel) );
					desc.setSecurityPolicyUri( conf.getSecurityPolicy().getPolicyUri() );
					desc.setServer( ap );
					desc.setServerCertificate( serverApplicationInstanceCertificate.getCertificate().getEncoded() );
					desc.setTransportProfileUri( ep.getEndpointUrl() );
					desc.setUserIdentityTokens( userTokenPolicies );
				
					result.add(desc);
				}
			}
		}			
		
		return result.toArray( new EndpointDescription[0] );
	}
	
	public Binding[] getBindings() {
		return BindingFactory.getInstance().getBindings(this);
	}
	
	@Override
	public String toString() {
		return "Server "+getApplicationUri();
	}
	
}
