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
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.TestStackRequest;
import org.opcfoundation.ua.core.TestStackResponse;
import org.opcfoundation.ua.transport.ServiceChannel;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.KeyPair;
import org.opcfoundation.ua.transport.security.PrivKey;

/**
 * In this example the client discovers server applications from a 
 * discover server and then connects to one.
 * 
 * Run this example with c# UA Sample Server.
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class ClientExample3 {

	public static void main(String[] args) throws Exception {
		// Load Log4j configurations from external file
		PropertyConfigurator.configure( ClientExample3.class.getResource("log.properties") );
		
		//////////////  CLIENT  //////////////
		// Load Client's Application Instance Certificate from file
		Cert myClientCertificate = Cert.load( Example1.class.getResource( "ClientCert.der" ) );
		PrivKey myClientPrivateKey = PrivKey.loadFromKeyStore( Example1.class.getResource( "ClientCert.pfx"), "Opc.Sample.Ua.Client");
		KeyPair myClientApplicationInstanceCertificate = new KeyPair(myClientCertificate, myClientPrivateKey);
		// Create Client
		Client myClient = new Client( myClientApplicationInstanceCertificate );
		//////////////////////////////////////
		
		
		/////////  DISCOVER SERVERS  /////////
		// Discover server applications
		String publicHostname = InetAddress.getLocalHost().getHostName();	
		ApplicationDescription[] servers = myClient.discoverApplications( new URI("opc.tcp://"+publicHostname+":4840/") );
		// Choose one application
		ApplicationDescription server = servers[0];
		// Connect the application
		ServiceChannel myChannel = myClient.createServiceChannel( server );
		//////////////////////////////////////
		
				
		////////////  TEST-STACK  ////////////
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
