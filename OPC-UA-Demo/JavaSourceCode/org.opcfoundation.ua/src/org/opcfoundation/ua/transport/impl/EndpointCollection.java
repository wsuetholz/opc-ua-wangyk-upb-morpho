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

package org.opcfoundation.ua.transport.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.opcfoundation.ua.application.Server;
import org.opcfoundation.ua.transport.Endpoint;
import org.opcfoundation.ua.transport.security.SecurityMode;

/**
 * A collection of endpoint to server bindings 
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class EndpointCollection  {

	/** Endpoints  (Uri -> Endpoint) */
	protected Map<Endpoint, Server> endpoints = new HashMap<Endpoint, Server>();
	
	public EndpointCollection() {
	}
	
	public synchronized void add(Endpoint endpoint, Server server) {
		if (endpoint==null || server==null) throw new IllegalArgumentException("null arg");
		for (Endpoint ep : endpoints.keySet())
			if (ep.getEndpointUrl().equals(endpoint.getEndpointUrl()))
				throw new RuntimeException("Collection already contains endpoint");
		endpoints.put(endpoint, server);
	}
	
	public synchronized Server remove(Endpoint endpoint) {
		return endpoints.remove(endpoint);
	}
	
	public synchronized boolean contains(Endpoint endpoint) {
		return endpoints.containsKey(endpoint);
	}
	
	public synchronized boolean contains(Server server) {
		return endpoints.containsValue(server);
	}
	
	public synchronized Server getServer(Endpoint endpoint) {
		return endpoints.get(endpoint);
	}
	
	/**
	 * Get all endpoints
	 * 
	 * @return endpoints
	 */
	public synchronized Endpoint[] getEndpoints() {
		return endpoints.keySet().toArray(new Endpoint[endpoints.size()]);
	}
	
	/**
	 * Get endpoints by server
	 *  
	 * @return endpoints
	 */
	public synchronized Endpoint[] getEndpoints(Server server) {
		List<Endpoint> result = new ArrayList<Endpoint>();
		for (Entry<Endpoint, Server> e : endpoints.entrySet())
			if (e.getValue()==server)
				result.add(e.getKey());
		return result.toArray(new Endpoint[result.size()]);
	}
	
	public synchronized Server[] getServers() {
		Set<Server> l = new HashSet<Server>();
		for (Server s: endpoints.values())
			l.add(s);
		return l.toArray(new Server[0]);
	}
	
	public synchronized Endpoint get(String url, SecurityMode mode)
	{
		for (Endpoint ep : endpoints.keySet())
			if (ep.supportsSecurityMode(mode) && url.equalsIgnoreCase(ep.getEndpointUrl()))
				return ep;
		return null;
	}

	public synchronized Endpoint get(String url)
	{
		// It seems that the casing of the host name part of the URL can vary,
		// so we must use a case-ignoring check here
		for (Endpoint ep : endpoints.keySet())
			if (url == null || url.equalsIgnoreCase(ep.getEndpointUrl()))
				return ep;
		return null;
	}

	public synchronized int size() 
	{
		return endpoints.size();
	}
	
}
