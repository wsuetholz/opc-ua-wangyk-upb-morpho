/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

package org.opcfoundation.ua.examples;

import java.net.InetAddress;
import java.net.URI;

import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.application.Client;
import org.opcfoundation.ua.application.Server;
import org.opcfoundation.ua.application.TestStackService;
import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.TestStackRequest;
import org.opcfoundation.ua.core.TestStackResponse;
import org.opcfoundation.ua.transport.BindingFactory;
import org.opcfoundation.ua.transport.Endpoint;
import org.opcfoundation.ua.transport.ServiceChannel;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityMode;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.EndpointUtil;

/**
 * This example creates both a server and a client. 
 * The server is bound to port 6001 and serves to TestStack requests (See {@link TestStackService}) with echo.
 * The client connects to the server and makes a simple "Hello World" request and receives 
 * corresponding "Hello World" resopnse.
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class Example1 {

	public static void main(String[] args) throws Exception {
		// Load Log4j configurations from external file
		PropertyConfigurator.configure( Example1.class.getResource("log.properties") );
		
		//////////////  SERVER  //////////////
		// Create UA Server
		Server myServer = new Server();
		// Add a service to the server - TestStack echo
		myServer.addServiceHandler( new TestStackService() );
		
		// Load Servers's Application Instance Certificate from file
		Cert myServerCertificate = Cert.load( Example1.class.getResource( "ServerCert.der" ) );
		PrivKey myServerPrivateKey = PrivKey.loadFromKeyStore( Example1.class.getResource( "UAServerCert.pfx"), "Opc.Sample.Ua.Server" );
		KeyPair myServerApplicationInstanceCertificate = new KeyPair(myServerCertificate, myServerPrivateKey); 
		// Add application instance certificate		
		myServer.addApplicationInstanceCertificate( myServerApplicationInstanceCertificate );		
		
		// Create endpoint
		String hostname = InetAddress.getLocalHost().getHostName();	
		// Well known URI of the server
		URI myUri = new URI( "opc.tcp://"+hostname+":6001/UAExample" );
		Endpoint myEndpoint = new Endpoint( myUri.toASCIIString(), SecurityMode.ALL );
		// Bind my server to my endpoint. This opens the port 6001 as well.   
		myServer.bind(myEndpoint);
		//////////////////////////////////////
		

		//////////////  CLIENT  //////////////
		// Load Client's Application Instance Certificate from file
		Cert myClientCertificate = Cert.load( Example1.class.getResource( "ClientCert.der" ) );
		PrivKey myClientPrivateKey = PrivKey.loadFromKeyStore( Example1.class.getResource( "ClientCert.pfx"), "Opc.Sample.Ua.Client");
		KeyPair myClientApplicationInstanceCertificate = new KeyPair(myClientCertificate, myClientPrivateKey);
		// Create Client
		Client myClient = new Client( myClientApplicationInstanceCertificate );
		//////////////////////////////////////		
		
		
		/////////// DISCOVER ENDPOINT ////////
		// Discover server's endpoints, and choose one
		EndpointDescription[] endpoints = myClient.discoverEndpoints( new URI( "opc.tcp://"+hostname+":6001/" ) ); //51210=Sample Server
		// Filter out all but opc.tcp protocol endpoints
		endpoints = EndpointUtil.selectByProtocol(endpoints, "opc.tcp");
		// Filter out all but Signed & Encrypted endpoints
		endpoints = EndpointUtil.selectByMessageSecurityMode(endpoints, MessageSecurityMode.SignAndEncrypt);
		// Filter out all but Basic128 cryption endpoints
		endpoints = EndpointUtil.selectBySecurityPolicy(endpoints, SecurityPolicy.BASIC128RSA15);
		// Sort endpoints by security level. The lowest level at the beginning, the highest at the end of the array
		endpoints = EndpointUtil.sortBySecurityLevel(endpoints); 
		// Choose one endpoint
		EndpointDescription endpoint = endpoints[endpoints.length-1]; 
		//////////////////////////////////////		
		
				
		////////////  TEST-STACK  ////////////
		// Create Channel
		ServiceChannel myChannel = myClient.createServiceChannel( endpoint );
		// Create Test Request		
		TestStackRequest req = new TestStackRequest(null, null, null, new Variant( "Hello World" ));
		System.out.println("REQUEST: "+req);		
		// Invoke service
		TestStackResponse res = myChannel.TestStack(req);		
		// Print result
		System.out.println("RESPONSE: "+res);		
		//////////////////////////////////////		
		
		
		/////////////  SHUTDOWN  /////////////
		// Close channel
		myChannel.closeAsync();
		// Unbind endpoint. This also closes the socket 6001 as it has no more endpoints.
		BindingFactory.getInstance().unbind(myServer);
		//////////////////////////////////////		
		
	}
	
}
