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

import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.application.Server;
import org.opcfoundation.ua.builtintypes.StatusCode;
import org.opcfoundation.ua.common.DebugLogger;
import org.opcfoundation.ua.common.ServiceFaultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.TestStackRequest;
import org.opcfoundation.ua.core.TestStackResponse;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.transport.Binding;
import org.opcfoundation.ua.transport.Endpoint;
import org.opcfoundation.ua.transport.EndpointServiceRequest;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityMode;
import org.opcfoundation.ua.utils.CertificateUtils;
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
				throws ServiceFaultException {
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
		
		// Try to Load Servers's Application Instance Certificate from file
		
		KeyPair myServerApplicationInstanceCertificate = loadOrCreateCertificate();
		
		 
		 
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
			} catch(ServiceResultException e) {
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
	
	/**
	 * In the first run this method creates public&private key pair and saves them to files.
	 * In other runs the key pairs are loaded from files.
	 * 
	 * @return KeyPair
	 * @throws Exception
	 */
    public static KeyPair loadOrCreateCertificate() 
    throws Exception
    {
    	File certFile = new File("PKI/ServerCert.der");
    	File privFile = new File("PKI/ServerCert.key");
    	
    	//try to load certificate information (public certificate & private key)
    	try {
    		//Cert cert = Cert.load(ServerExample1.class.getResource( "ServerCert1.der" ));
    		
    		//Load certificate from file
    		Cert cert = Cert.load(certFile);
    		//This may be used to load private key from keystore.
    		//PrivKey privKey = PrivKey.loadFromKeyStore(ServerExample1.class.getResource( "UAServerCert.pfx"), "Opc.Sample.Ua.Server");
			PrivKey privKey = PrivKey.load(privFile);
    		return new KeyPair(cert, privKey);
		} catch (Exception e) {
		}
		//could not find the certificate info...create new self-signeg certificate
		System.out.println("generating new certificate for Client");
    	List<String> hostnameList = new ArrayList<String>();
    	hostnameList.add("My Hostname");
    	
    	
		KeyPair result = CertificateUtils.createApplicationInstanceCertificate("Java Sample Client", "Early Adopter Test Organisation", java.net.InetAddress.getLocalHost().getHostName(), 365);
		
		//save the certificate data & private key to (static) file
		result.save(certFile,privFile );
		return result;
    }
		
	
}
