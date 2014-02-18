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

package org.opcfoundation.ua.transport;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.application.Server;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.transport.tcp.nio.UATcpServer;
import org.opcfoundation.ua.utils.IStatefulObject;
import org.opcfoundation.ua.utils.StateListener;

/**
 * BindingFactory is an utility that binds Endpoints to Servers.
 * 
 */
public class BindingFactory {

	/** Logger */
	private static Logger logger = Logger.getLogger(BindingFactory.class);
	private static BindingFactory instance;
	
	public synchronized static BindingFactory getInstance() {
		if (instance==null) instance = new BindingFactory();
		return instance;
	}
	
	Map<Object, Binding> bindings = new HashMap<Object, Binding>();
	
	BindingFactory() {}
	
	/**
	 * Bind an endpoint to a server. An endpoint requires concrete transport 
	 * means to bind endpoint to. For instance, binary (opc.tcp) endpoint 
	 * requires a socket and SOAP (http) endpoint requires a web server. This 
	 * method will use existing service or create a new one if necessary.
	 *  
	 * Note, use {@link Server#bind(Endpoint)} instead of calling this directly.
	 * 
	 * @param endpoint endpoint 
	 * @param server server 
	 * @throws ServiceResultException
	 */
	public synchronized void bind(Endpoint endpoint, Server server) 
	throws ServiceResultException
	{
		try {
			String endpointUrl = endpoint.getEndpointUrl();
			final Set<Object> bindNames = toBindNames( endpointUrl );
			
			// Bind to the host in endpoint uri, and to no other interface
			for (Object bindName : bindNames) {
				if (bindName instanceof SocketAddress /*opc.tcp*/) {
					Binding binding = getBinding( bindName );
					if (binding==null) {			
						final SocketAddress addr = (SocketAddress) bindName;				
						binding = new UATcpServer(addr);
					
						// Remove from the internal map when socket is closed
						binding.addStateListener(new StateListener<CloseableObjectState>() {
							@Override
							public void onStateTransition(
								IStatefulObject<CloseableObjectState, ?> sender,
								CloseableObjectState oldState, CloseableObjectState newState) {
								if (newState != CloseableObjectState.Closing && newState != CloseableObjectState.Closed) return;
								synchronized(BindingFactory.this) {
									bindings.remove(addr);
								}
							}});
					
						// Remember the binding
						bindings.put(bindName, binding);
					}
					
					binding.getEndpoints().add(endpoint, server);
				} else {
					throw new ServiceResultException("Unsupported endpoint type "+endpointUrl);
				}
			}
				
		} catch (IOException e) {
			throw new ServiceResultException(e);
		}
	}
	
	/**
	 * Note, use {@link Server#bind(Endpoint)} instead of calling this directly.
	 * 
	 * Unbind an endpoint from a server.
	 * If all endpoints are removed from the {@link Binding} then it will be closed.
	 * 
	 * @param endpoint endpoint to unbind
	 */
	public synchronized void unbind(Endpoint endpoint)
	{
		
		for (Binding binding : getBindings(endpoint))
		{				
			binding.getEndpoints().remove(endpoint);
			
			// Close binding if its empty
			if (binding.getEndpoints().size()==0)
			{
				// There is only endpoint discovery endpoint left, which is created by this class
				// We can close this binding
				binding.close();
			}
		}
	}
	
	/**
	 * Unbind all endpoints of a server
	 * Note, use {@link Server#close()} instead of calling this directly.
	 * 
	 * @param server
	 */
	public void unbind(Server server)
	{
		for (Endpoint ep : getEndpoints(server))
			unbind(ep);
	}
	
	/**
	 * Get existing bindings
	 * 
	 * @param endpoint
	 * @return bindings
	 * @throws UnknownHostException 
	 */
	public synchronized Binding[] getBindings(Endpoint endpoint) 
	{
		Set<Binding> result = new HashSet<Binding>(1);
		for (Object bindName : toBindNames(endpoint.getEndpointUrl())) 
		{
			Binding binding = bindings.get( bindName );
			if (binding==null) continue;
			if (!binding.getEndpoints().contains(endpoint)) continue;
			result.add(bindings.get(bindName));
		}
		return result.toArray(new Binding[0]);
	}
	
	/**
	 * Get existing binding 
	 * 
	 * @param server
	 * @return bindings
	 * @throws UnknownHostException 
	 */
	public synchronized Binding[] getBindings(Server server) 
	{
		Set<Binding> result = new HashSet<Binding>(1);
		for (Binding b : bindings.values())
		{
			b.getEndpoints().contains(server);
			result.add(b);
		}
		return result.toArray(new Binding[0]);
	}	
	
	public synchronized Binding getBinding( Object bindName )
	{
		return bindings.get( bindName );
	}
	
	/**
	 * Get all the endpoints bound to a server
	 * 
	 * @param server
	 * @return endpoints
	 */
	public synchronized Endpoint[] getEndpoints(Server server)
	{
		List<Endpoint> result = new ArrayList<Endpoint>();
		for (Binding b : bindings.values())
			for (Endpoint ep : b.getEndpoints().getEndpoints(server))
				result.add(ep);
		return result.toArray( new Endpoint[result.size()] );
	}

	/**
	 * Convert endpoint url to transport layer object name
	 * @param endpoint
	 * @return
	 * @throws IllegalArgumentException endpointUrl is problematic some way
	 */
	private Set<Object> toBindNames(String endpointUrl) 
	throws IllegalArgumentException
	{
		Set<Object> result = new HashSet<Object>();

		if (endpointUrl == null) 
			throw new IllegalArgumentException("URL not valid.");
		try {
			URI uri = new URI(endpointUrl);
			String proto = uri.getScheme().toLowerCase();
			String host = uri.getHost();
			int port = uri.getPort();
			if (host == null) {
				// Do a custom parse, if the URI is not valid, possibly because
				// it
				// does not conform to RFC 2396. This occurs, for example, if
				// the
				// host name
				// contains '_' characters, which are used by some Windows
				// computers
				String[] parts = endpointUrl.split("/+");
//				proto = parts[0].split(":")[0]; // // Use the proto parsed from URI, which should be fine, already
				String[] host_port = parts[1].split(":");
				host = host_port[0];
				try {
					port = Integer.parseInt(host_port[1]);
				} catch (NumberFormatException e1) {
					port = 0;
				} catch (ArrayIndexOutOfBoundsException e2) {
					port = 0;
				}
			}

			proto = proto.toLowerCase();

			if (port == 0)
				port = UriUtil.defaultPort(proto);

			if (proto.equals("opc.tcp")) {
				// Bind to the host in endpoint uri, and to no other interface

				try {
					// !!WORKAROUND!! Java6 cannot bind to IPv6
					// Hostnames (e.g. localhost) resoves to 127.0.0.1 and 0::1
					// This workaround omits IPv6 addresses if IPv4 addresses
					// exist, but lets error to be thrown if there are only
					// IPv6 addresses. This is to show IPv6 cannot be bound

					InetAddress addrs[] = InetAddress.getAllByName(host);
					boolean hasIPv4 = false;
					boolean hasIPv6 = false;
					for (InetAddress addr : addrs) {
						hasIPv4 |= addr instanceof Inet4Address;
						hasIPv6 |= addr instanceof Inet6Address;
					}

					for (InetAddress addr : InetAddress.getAllByName(host)) {
						boolean IPv6 = addr instanceof Inet6Address;

						if (IPv6 && hasIPv6 && hasIPv4) {
							logger.warn("Binding of " + endpointUrl + " to "
									+ addr.getHostAddress()
									+ " was omited. (Workaround)");
							continue;
						}

						SocketAddress sa = new InetSocketAddress(addr, port);
						result.add(sa);
					}
				} catch (UnknownHostException e) {
					throw new IllegalArgumentException(e);
				}

			} else {
				throw new IllegalArgumentException("Unsupported protocol "
						+ proto);
			}
		} catch (URISyntaxException ex) {
			throw new IllegalArgumentException("Invalid URL" + ex);
		}
		return result;
	}

	
}
