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

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.StatusCodes;

public class UriUtil {

	public static final String OPCTCP = "opc.tcp";
	public static final String HTTP = "http";
		
	public static final int OPC_TCP_PORT = 6000;
	public static final int HTTP_PORT = 80;
	public static final int HTTPS_PORT = 8080;
	public static final int OPC_TCP_DISCOVERY_PORT = 4840;
	
	private final static Pattern PATTERN_OPCTCP = Pattern.compile("opc.tcp.*", Pattern.CASE_INSENSITIVE);
	private final static Pattern PATTERN_HTTP = Pattern.compile("http.*", Pattern.CASE_INSENSITIVE);
	private final static Pattern PATTERN_HTTPS = Pattern.compile("https.*", Pattern.CASE_INSENSITIVE);

	public static enum TransportProtocol {
		Socket,  // UA Secure Conversion, UASC, Opc.tcp
		Soap;    // SOAP, http, https		
	}
	
	/**
	 * Get transport protocol of an endpoint
	 * 
	 * @param endpointUri
	 * @return transport protocol
	 * @throws ServiceResultException Bad_ServerUriInvalid if the protocol is unknown
	 */
	public static TransportProtocol getTransportProtocol(String endpointUri)
	throws ServiceResultException
	{
		if (PATTERN_OPCTCP.matcher(endpointUri).matches()) return TransportProtocol.Socket;		
		if (PATTERN_HTTPS.matcher(endpointUri).matches()) return TransportProtocol.Soap;
		if (PATTERN_HTTP.matcher(endpointUri).matches()) return TransportProtocol.Soap;
		throw new ServiceResultException(StatusCodes.Bad_ServerUriInvalid);
	}
	
	
	/**
	 * Convert uri to socket address 
	 * 
	 * @param endpointUri
	 * @return
	 * @throws ServiceResultException
	 */
	public static InetSocketAddress getSocketAddress(String endpointUri)
	throws ServiceResultException
	{
		try {
			URI uri = new URI(endpointUri);
			return getSocketAddress(uri);			
		} catch (URISyntaxException e) {
			throw new ServiceResultException(StatusCodes.Bad_ServerUriInvalid, e);
		} catch (IllegalArgumentException e) {
			try {
				// Do a custom parse, if the URI is not valid, possibly because it
				// does not conform to RFC 2396. This occurs, for example, if the host name
				// contains '_' characters, which are used by some Windows computers
				String[] parts = endpointUri.split("/+");
				String proto = parts[0].split(":")[0];
				String[] host_port = parts[1].split(":");
				String host = host_port[0];
				int port;
				try {
					port = Integer.parseInt(host_port[1]);
				} catch (NumberFormatException e1) {
					port = defaultPort(proto);
				} catch (ArrayIndexOutOfBoundsException e2) {
					port = defaultPort(proto);
				}
				return new InetSocketAddress(host, port);
			} catch (RuntimeException ex) {
				// Use the original exception as cause
				throw new ServiceResultException(
						StatusCodes.Bad_ServerUriInvalid, e);
			}
		}

	}
	
	public static InetSocketAddress getSocketAddress(URI endpointUri)
	{
		String proto = endpointUri.getScheme().toLowerCase(); 
		String host = endpointUri.getHost();
		int port = endpointUri.getPort();
		if (port==-1) port =defaultPort(proto);
		return new InetSocketAddress(host, port);
	}


	public static int defaultPort(String proto) {
		if (PATTERN_OPCTCP.matcher(proto).matches())
			return OPC_TCP_PORT;
		if (PATTERN_HTTP.matcher(proto).matches())
			return HTTP_PORT;
		if (PATTERN_HTTPS.matcher(proto).matches())
			return HTTPS_PORT;
		throw new IllegalArgumentException("Unsupported protocol " + proto);
	}	

}
