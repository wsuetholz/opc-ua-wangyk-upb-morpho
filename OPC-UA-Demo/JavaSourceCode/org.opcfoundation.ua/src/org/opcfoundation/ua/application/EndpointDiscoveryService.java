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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.GetEndpointsRequest;
import org.opcfoundation.ua.core.GetEndpointsResponse;
import org.opcfoundation.ua.transport.Endpoint;
import org.opcfoundation.ua.transport.EndpointServiceRequest;
import org.opcfoundation.ua.transport.impl.EndpointCollection;

/**
 * Service handler that serves onGetEndpoints request.
 * 
 */
public class EndpointDiscoveryService {

	final EndpointCollection endpoints;
	
	public EndpointDiscoveryService(EndpointCollection endpoints) {
		this.endpoints = endpoints;
	}
	
	public void onGetEndpoints(EndpointServiceRequest<GetEndpointsRequest, GetEndpointsResponse> req) throws ServiceFaultException {
		GetEndpointsResponse res = new GetEndpointsResponse();
		String requestUrl = trimUrl(req.getRequest().getEndpointUrl()).toLowerCase();
		String[] reqUriArray = req.getRequest().getProfileUris();
		Collection<String> reqUris = reqUriArray==null?new ArrayList<String>(0):Arrays.asList(reqUriArray);
		List<EndpointDescription> list = new ArrayList<EndpointDescription>();
		
		final Server[] servers = endpoints.getServers();
		for (Server s : servers)
		{
			final EndpointDescription[] endpointDescriptions = s.getEndpointDescriptions();
			for (EndpointDescription ed : endpointDescriptions)
			{
				// Add, if Uri was requested
				final String url = ed.getEndpointUrl().toLowerCase();
				if ((reqUris.isEmpty() || reqUris.contains(url))
						&& (requestUrl == null || requestUrl.isEmpty() || url
								.contains(requestUrl)))
					list.add(ed);
			}
		}
				
		res.setEndpoints(list.toArray(new EndpointDescription[0]));
		req.sendResponse(res);
	}

	public EndpointCollection getEndpointCollection()
	{
		return endpoints;
	}

	/**
	 * @param uri
	 * @return
	 */
	private String trimUrl(String uri) {
		// Also remove an optional '/' from the end, since it is not significant
		if ((uri != null) && uri.endsWith("/"))
			uri = uri.substring(0, uri.length()-1);
		return uri;
	}
		
}
