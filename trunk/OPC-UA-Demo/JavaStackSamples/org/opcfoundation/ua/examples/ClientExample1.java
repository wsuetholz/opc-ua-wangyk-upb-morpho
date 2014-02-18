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

import java.net.InetAddress;
import java.net.URI;

import org.apache.log4j.PropertyConfigurator;
import org.opcfoundation.ua.application.Client;
import org.opcfoundation.ua.builtintypes.Variant;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.TestStackRequest;
import org.opcfoundation.ua.core.TestStackResponse;
import org.opcfoundation.ua.transport.ServiceChannel;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import static org.opcfoundation.ua.utils.EndpointUtil.*;

/**
 * In this example, a client connects to a server, discovers endpoints, 
 * chooses one endpoint and connects to it, and makes a stack-test using a 
 * {@link ServiceChannel}. 
 * 
 * Run this example with {@link ServerExample1}.
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class ClientExample1 {

	public static void main(String[] args) throws Exception {
		// Load Log4j configurations from external file
		PropertyConfigurator.configure( ClientExample1.class.getResource("log.properties") );
		
		//////////////  CLIENT  //////////////
		// Load Client's Application Instance Certificate from file
		Cert myClientCertificate = Cert.load( ClientExample1.class.getResource( "ClientCert.der" ) );
		PrivKey myClientPrivateKey = PrivKey.loadFromKeyStore( ClientExample1.class.getResource( "ClientCert.pfx"), "Opc.Sample.Ua.Client");
		KeyPair myClientApplicationInstanceCertificate = new KeyPair(myClientCertificate, myClientPrivateKey);
		// Create Client
		Client myClient = new Client( myClientApplicationInstanceCertificate );
		//////////////////////////////////////		
		
		
		////////// DISCOVER ENDPOINT /////////
		// Discover server's endpoints, and choose one
		String publicHostname = InetAddress.getLocalHost().getHostName();	
		EndpointDescription[] endpoints = myClient.discoverEndpoints( new URI( "opc.tcp://"+publicHostname+":6001/" ) ); //51210=Sample Server
		// Filter out all but opc.tcp protocol endpoints
		endpoints = selectByProtocol(endpoints, "opc.tcp");
		// Filter out all but Signed & Encrypted endpoints
		endpoints = selectByMessageSecurityMode(endpoints, MessageSecurityMode.SignAndEncrypt);
		// Filter out all but Basic128 cryption endpoints
		endpoints = selectBySecurityPolicy(endpoints, SecurityPolicy.BASIC128RSA15);
		// Sort endpoints by security level. The lowest level at the beginning, the highest at the end of the array
		endpoints = sortBySecurityLevel(endpoints); 
		// Choose one endpoint
		EndpointDescription endpoint = endpoints[endpoints.length-1]; 
		//////////////////////////////////////		
		
				
		////////////  TEST-STACK  ////////////
		// Create Channel
		ServiceChannel myChannel = myClient.createServiceChannel( endpoint );
		// Create Test Request		
		TestStackRequest req = new TestStackRequest(null, null, null, new Variant(new Short[320][256]));
		System.out.println("REQUEST: "+req);		
		// Invoke service
		TestStackResponse res = myChannel.TestStack(req);		
		// Print result
		System.out.println("RESPONSE: "+res);		
		//////////////////////////////////////		
		
		
		/////////////  SHUTDOWN  /////////////
		// Close channel
		myChannel.closeSecureChannel();
		//////////////////////////////////////		
		
	}
	
}
