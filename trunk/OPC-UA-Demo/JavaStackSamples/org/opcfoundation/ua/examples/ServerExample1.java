// (c) Copyright 2009 The OPC Foundation
// ALL RIGHTS RESERVED.
//
// DISCLAIMER:
//  This code is provided by the OPC Foundation solely to assist in 
//  understanding and use of the appropriate OPC Specification(s) and may be 
//  used as set forth in the License Grant section of the OPC Specification.
//  This code is provided as-is and without warranty or support of any sort
//  and is subject to the Warranty and Liability Disclaimers which appear
//  in the printed OPC Specification.
//
// Authors:
//  VTT Technical Research Centre of Finland (www.vtt.fi)
//  Tampere University of Technology (www.tut.fi)
//  Prosys (www.prosys.fi) 
//  Wapice (www.wapice.fi) 
//  Metso Automation (www.metsoautomation.com) 
//  Kone (www.kone.com)

package org.opcfoundation.ua.examples;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.application.Server;
import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.common.DebugLogger;
import org.opcfoundation.ua.common.StackException;
import org.opcfoundation.ua.core.TestStackRequest;
import org.opcfoundation.ua.core.TestStackResponse;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.transport.Binding;
import org.opcfoundation.ua.transport.Endpoint;
import org.opcfoundation.ua.transport.EndpointServiceRequest;
import org.opcfoundation.ua.transport.ServiceException;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityMode;
import org.opcfoundation.ua.utils.EndpointUtil;

/**
 * Simple Server example. This server responds to stack test and endpoint discover service requests.
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class ServerExample1 {

	public static void main(String[] args) throws Exception {
		// Load Log4j configurations from external file
		PropertyConfigurator.configure( ServerExample1.class.getResource("log.properties") );
		// Create Logger
		Logger myLogger = Logger.getLogger(ServerExample1.class); 
		
		//////////////  SERVER  //////////////
		// Create UA Server
		Server myServer = new Server();

		// Add a service to the server - TestStack echo
		myServer.addServiceHandler( 
			
			// An example service handler. This handler sends echo responses
			new Object() {
				@SuppressWarnings("unused")
				public void onTestStack(EndpointServiceRequest<TestStackRequest, TestStackResponse> req)
				throws ServiceException {
					// TestStack echo			
					req.sendResponse( new TestStackResponse(null, req.getRequest().getInput() ) );
				}
			}
			
		);
		
		// Add Client Application Instance Certificate validator
		myServer.setClientApplicationInstanceCertificateValidator(new CertificateValidator() {
			@Override
			public StatusCode validateCertificate(Cert c) {
				return StatusCode.GOOD;
			}});
		
		// Load Servers's Application Instance Certificate from file
		Cert myServerCertificate = Cert.load( ServerExample1.class.getResource( "ServerCert.der" ) );
		PrivKey myServerPrivateKey = PrivKey.loadFromKeyStore( ServerExample1.class.getResource( "UAServerCert.pfx"), "Opc.Sample.Ua.Server" );
		KeyPair myServerApplicationInstanceCertificate = new KeyPair(myServerCertificate, myServerPrivateKey); 
		myServer.addApplicationInstanceCertificate( myServerApplicationInstanceCertificate );		
		
		// Add User Token Policies
		myServer.addUserTokenPolicy( UserTokenPolicy.ANONYMOUS );
		myServer.addUserTokenPolicy( UserTokenPolicy.SECURE_USERNAME_PASSWORD );

		// Create an endpoint for each network interface
		for (String addr : EndpointUtil.getInetAddressNames()) {
			URI endpointUri = new URI( "opc.tcp://"+addr+":6001/UAExample" );
			try {
				Endpoint myEndpoint = new Endpoint( endpointUri, SecurityMode.ALL );			
				myServer.bind( myEndpoint );
			} catch(StackException e) {
				myLogger.error("Error binding "+endpointUri +" - "+ (e.getCause()!=null?e.getCause().getMessage():e.getMessage()) );
			}
		}
		
		// Attach listener (debug logger) to each binding
		DebugLogger debugLogger = new DebugLogger( myLogger );
		for (Binding b : myServer.getBindings())
			b.addConnectionListener( debugLogger );		
		//////////////////////////////////////
		
		
		//////////////////////////////////////		
		// Press enter to shutdown
		System.out.println("Press enter to shutdown");
		System.in.read();
		//////////////////////////////////////		
		
		
		/////////////  SHUTDOWN  /////////////
		// Close the server by unbinding all endpoints 
		myServer.close();
		//////////////////////////////////////		
		
	}
		
	
}
